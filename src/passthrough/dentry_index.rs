// Copyright 2026 The Virtiofs Project Developers.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Reverse dentry index for push-based cache invalidation.
//!
//! The passthrough filesystem normally only needs to map FUSE inode IDs to host
//! file descriptors (forward direction). To turn a host filesystem event
//! (`/shared/foo/bar.txt was modified`) into a FUSE notification, we need the
//! inverse: given a path on the host, find the FUSE inode ID (if any) the
//! guest currently has cached.
//!
//! The index is keyed by `(parent_fuse_inode, name)` rather than by absolute
//! path. This sidesteps two problems:
//!   * The shared dir might be relocated under the daemon's feet (chroot,
//!     bind mount, pivot_root in the sandbox).
//!   * Resolving a host path to its FUSE inode requires walking from the root
//!     anyway because the daemon never sees absolute host paths after the
//!     sandbox sets up the chroot.
//!
//! A path lookup walks the components: split the path into segments, look up
//! each `(current_parent, segment) -> child` until either the leaf is found
//! or a segment is missing (meaning the guest never cached that subtree, so
//! there is nothing to invalidate).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::sync::RwLock;

use crate::passthrough::inode_store::Inode;

pub type Name = Vec<u8>;

/// A bidirectional map between FUSE inodes and `(parent, name)` dentries.
///
/// Forward: `(parent, name) -> child_inode` — for resolving a host event path
/// to a FUSE inode that may be cached on the guest.
///
/// Reverse: `child_inode -> set of (parent, name)` — for invalidating *all*
/// names that reference an inode (hardlinks) and for cleaning the forward map
/// when an inode is forgotten without a preceding unlink.
#[derive(Default)]
pub struct DentryIndex {
    inner: RwLock<DentryIndexInner>,
}

#[derive(Default)]
struct DentryIndexInner {
    forward: BTreeMap<(Inode, Name), Inode>,
    reverse: BTreeMap<Inode, BTreeSet<(Inode, Name)>>,
}

impl DentryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `parent/name` resolves to `child`.
    ///
    /// If a previous mapping for `(parent, name)` existed, it is overwritten
    /// and the old reverse entry is cleaned up. This handles the common case
    /// of a `lookup` returning a different inode than was previously cached
    /// (e.g., the host file at that path was replaced out-of-band).
    pub fn insert(&self, parent: Inode, name: &[u8], child: Inode) {
        let key = (parent, name.to_vec());
        let mut inner = self.inner.write().unwrap();
        if let Some(prev) = inner.forward.insert(key.clone(), child) {
            if prev != child {
                if let Some(set) = inner.reverse.get_mut(&prev) {
                    set.remove(&key);
                    if set.is_empty() {
                        inner.reverse.remove(&prev);
                    }
                }
            }
        }
        inner.reverse.entry(child).or_default().insert(key);
    }

    /// Remove the mapping for `parent/name` (called from unlink/rmdir/rename).
    pub fn remove(&self, parent: Inode, name: &[u8]) {
        let key = (parent, name.to_vec());
        let mut inner = self.inner.write().unwrap();
        if let Some(child) = inner.forward.remove(&key) {
            if let Some(set) = inner.reverse.get_mut(&child) {
                set.remove(&key);
                if set.is_empty() {
                    inner.reverse.remove(&child);
                }
            }
        }
    }

    /// Atomically rename `(old_parent, old_name) -> (new_parent, new_name)`.
    /// If `(new_parent, new_name)` already pointed at an inode (overwrite case),
    /// that mapping is dropped first.
    pub fn rename(
        &self,
        old_parent: Inode,
        old_name: &[u8],
        new_parent: Inode,
        new_name: &[u8],
    ) {
        let old_key = (old_parent, old_name.to_vec());
        let new_key = (new_parent, new_name.to_vec());
        let mut inner = self.inner.write().unwrap();

        // Drop whatever was at the destination first.
        if let Some(prev) = inner.forward.remove(&new_key) {
            if let Some(set) = inner.reverse.get_mut(&prev) {
                set.remove(&new_key);
                if set.is_empty() {
                    inner.reverse.remove(&prev);
                }
            }
        }

        // Move the source mapping.
        if let Some(child) = inner.forward.remove(&old_key) {
            inner.forward.insert(new_key.clone(), child);
            if let Some(set) = inner.reverse.get_mut(&child) {
                set.remove(&old_key);
                set.insert(new_key);
            }
        }
    }

    /// Drop every mapping that points at `inode`. Called when the inode is
    /// fully forgotten by the guest so we don't keep stale dentries.
    pub fn forget_inode(&self, inode: Inode) {
        let mut inner = self.inner.write().unwrap();
        if let Some(set) = inner.reverse.remove(&inode) {
            for key in set {
                inner.forward.remove(&key);
            }
        }
    }

    /// Look up the FUSE inode for `(parent, name)` if one is currently
    /// recorded.
    pub fn get(&self, parent: Inode, name: &[u8]) -> Option<Inode> {
        self.inner.read().unwrap().forward.get(&(parent, name.to_vec())).copied()
    }

    /// Walk the path components from the given root, returning the deepest
    /// ancestor inode that is currently in the index along with the remaining
    /// (unresolved) path components.
    ///
    /// Returns `(inode, remaining)` where:
    ///   * `inode` is the deepest known ancestor (always at least `root`);
    ///   * `remaining` is the slice of names that were not found in the index.
    ///
    /// Use cases:
    ///   * If `remaining` is empty, the leaf inode is `inode` — issue
    ///     `FUSE_NOTIFY_INVAL_INODE { inode }`.
    ///   * If `remaining` has length 1, `inode` is the parent and the name is
    ///     `remaining[0]` — issue `FUSE_NOTIFY_INVAL_ENTRY { parent: inode,
    ///     name: remaining[0] }`.
    ///   * If `remaining` has length > 1, the guest has never looked up this
    ///     subtree, so there is nothing to invalidate.
    pub fn resolve_path(
        &self,
        root: Inode,
        path: &Path,
    ) -> (Inode, Vec<Name>) {
        let segments: Vec<Name> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.as_encoded_bytes().to_vec()),
                _ => None,
            })
            .collect();

        let inner = self.inner.read().unwrap();
        let mut current = root;
        let mut consumed = 0usize;
        for seg in &segments {
            if let Some(child) = inner.forward.get(&(current, seg.clone())).copied() {
                current = child;
                consumed += 1;
            } else {
                break;
            }
        }
        (current, segments[consumed..].to_vec())
    }

    /// Iterate all known dentries for `inode`. Useful when the inode itself
    /// changes and we need to send INVAL_ENTRY for every cached name.
    pub fn names_for(&self, inode: Inode) -> Vec<(Inode, Name)> {
        self.inner
            .read()
            .unwrap()
            .reverse
            .get(&inode)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Snapshot of every inode currently tracked. Used on overflow to drive a
    /// bulk-invalidate.
    pub fn all_inodes(&self) -> Vec<Inode> {
        self.inner.read().unwrap().reverse.keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().forward.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ROOT: Inode = 1;

    #[test]
    fn insert_lookup() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"foo", 2);
        idx.insert(2, b"bar", 3);
        assert_eq!(idx.get(ROOT, b"foo"), Some(2));
        assert_eq!(idx.get(2, b"bar"), Some(3));
        assert_eq!(idx.get(ROOT, b"missing"), None);
    }

    #[test]
    fn remove_clears_both_directions() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"foo", 2);
        idx.insert(2, b"bar", 3);
        idx.remove(2, b"bar");
        assert_eq!(idx.get(2, b"bar"), None);
        assert!(idx.names_for(3).is_empty());
        // sibling still there
        assert_eq!(idx.get(ROOT, b"foo"), Some(2));
    }

    #[test]
    fn rename_moves_entry() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"a", 2);
        idx.insert(ROOT, b"b", 3);
        idx.rename(ROOT, b"a", ROOT, b"c");
        assert_eq!(idx.get(ROOT, b"a"), None);
        assert_eq!(idx.get(ROOT, b"c"), Some(2));
        assert_eq!(idx.names_for(2), vec![(ROOT, b"c".to_vec())]);
    }

    #[test]
    fn rename_overwrites_destination() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"src", 2);
        idx.insert(ROOT, b"dst", 3);
        idx.rename(ROOT, b"src", ROOT, b"dst");
        assert_eq!(idx.get(ROOT, b"src"), None);
        assert_eq!(idx.get(ROOT, b"dst"), Some(2));
        // Inode 3 was overwritten — its dentry record is gone.
        assert!(idx.names_for(3).is_empty());
        assert_eq!(idx.names_for(2), vec![(ROOT, b"dst".to_vec())]);
    }

    #[test]
    fn hardlink_records_multiple_names() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"a", 2);
        idx.insert(ROOT, b"b", 2);
        let mut names = idx.names_for(2);
        names.sort();
        assert_eq!(
            names,
            vec![(ROOT, b"a".to_vec()), (ROOT, b"b".to_vec())]
        );
    }

    #[test]
    fn forget_inode_drops_everything() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"a", 2);
        idx.insert(ROOT, b"b", 2);
        idx.insert(2, b"c", 3);
        idx.forget_inode(2);
        assert_eq!(idx.get(ROOT, b"a"), None);
        assert_eq!(idx.get(ROOT, b"b"), None);
        // The child of `2` is still indexed (forget cascades only one level —
        // the guest will FORGET its descendants separately).
        assert_eq!(idx.get(2, b"c"), Some(3));
    }

    #[test]
    fn resolve_path_walks_index() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"a", 2);
        idx.insert(2, b"b", 3);
        idx.insert(3, b"c", 4);

        let (ino, rem) = idx.resolve_path(ROOT, &PathBuf::from("a/b/c"));
        assert_eq!(ino, 4);
        assert!(rem.is_empty());

        let (ino, rem) = idx.resolve_path(ROOT, &PathBuf::from("a/b/missing"));
        assert_eq!(ino, 3);
        assert_eq!(rem, vec![b"missing".to_vec()]);

        let (ino, rem) = idx.resolve_path(ROOT, &PathBuf::from("a/x/y"));
        assert_eq!(ino, 2);
        assert_eq!(rem, vec![b"x".to_vec(), b"y".to_vec()]);
    }

    #[test]
    fn insert_overwrite_cleans_old_reverse() {
        let idx = DentryIndex::new();
        idx.insert(ROOT, b"foo", 2);
        // Same path now points at a different inode — typical when a file is
        // replaced out-of-band on the host and the guest re-looks-up.
        idx.insert(ROOT, b"foo", 5);
        assert!(idx.names_for(2).is_empty());
        assert_eq!(idx.names_for(5), vec![(ROOT, b"foo".to_vec())]);
    }
}
