// Copyright 2026 The Virtiofs Project Developers.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Translate normalized host events into FUSE notifications.
//!
//! Resolution policy:
//!
//! * `Modify(host_path)`
//!     - Walk the dentry index from the shared-dir root.
//!     - If the leaf inode is known: emit `INVAL_INODE { leaf }`.
//!     - If only the parent is known: emit nothing — the guest has not
//!       cached this dentry, so neither attrs nor data can be stale.
//!     - If even the parent is unknown: emit nothing for the same reason.
//!
//! * `Create(parent/name)` and `Remove(parent/name)`
//!     - Resolve the parent. If known, emit `INVAL_ENTRY { parent, name }`
//!       so the guest's `readdir` cache for the parent is consistent. For
//!       `Remove`, additionally emit `INVAL_INODE` for the leaf if the leaf
//!       inode was cached, so any open-but-unlinked semantics are flushed.
//!
//! * `Rename { from, to }`
//!     - For each side that is `Some`, emit `INVAL_ENTRY` against the
//!       respective parent and name. If the renamed inode itself is cached,
//!       additionally emit `INVAL_INODE` for it.
//!
//! * `Overflow`
//!     - Bulk invalidate: emit `INVAL_INODE` for every inode the index has
//!       seen. The cost is O(n) in cached inodes; the alternative is the
//!       guest serving stale data until the next TTL.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use log::{debug, info, warn};

use crate::passthrough::dentry_index::DentryIndex;
use crate::passthrough::inode_store::Inode;

use super::notifier::{Notification, Notifier, NotifierError};
use super::watcher::{HostEvent, HostEventKind};

#[derive(Debug)]
pub enum TranslateError {
    Notifier(NotifierError),
    Io(io::Error),
}

impl fmt::Display for TranslateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranslateError::Notifier(e) => write!(f, "{e}"),
            TranslateError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TranslateError {}

impl From<NotifierError> for TranslateError {
    fn from(e: NotifierError) -> Self {
        TranslateError::Notifier(e)
    }
}

pub struct Translator {
    root_inode: Inode,
    shared_dir: PathBuf,
    index: Arc<DentryIndex>,
    notifier: Arc<dyn Notifier>,
}

impl Translator {
    pub fn new(
        root_inode: Inode,
        shared_dir: PathBuf,
        index: Arc<DentryIndex>,
        notifier: Arc<dyn Notifier>,
    ) -> Self {
        Self {
            root_inode,
            shared_dir,
            index,
            notifier,
        }
    }

    /// Process one normalized host event.
    pub fn handle(&mut self, event: HostEvent) -> Result<(), TranslateError> {
        match event.kind {
            HostEventKind::Modify { path } => self.handle_modify(&path),
            HostEventKind::Create { path } => self.handle_parent_change(&path),
            HostEventKind::Remove { path } => self.handle_remove(&path),
            HostEventKind::Rename { from, to } => self.handle_rename(from.as_deref(), to.as_deref()),
            HostEventKind::Overflow => self.bulk_invalidate(),
        }
    }

    fn handle_modify(&self, host_path: &Path) -> Result<(), TranslateError> {
        let rel = match self.relativize(host_path) {
            Some(r) => r,
            None => return Ok(()),
        };
        let (inode, remaining) = self.index.resolve_path(self.root_inode, &rel);
        if remaining.is_empty() {
            // Known leaf — invalidate it.
            self.notifier.send(Notification::InvalInode { inode })?;
        } else {
            // Unknown leaf, possibly a fresh dentry under a known parent. We
            // could speculatively INVAL_ENTRY the parent here, but that
            // would also be triggered by `Create`, which the kernel emits
            // separately. Skip to avoid double work.
            debug!(
                "modify({}): leaf not cached (resolved to inode {}, {} segments unknown)",
                rel.display(),
                inode,
                remaining.len()
            );
        }
        Ok(())
    }

    /// Used for both `Create` and the entry-side of `Remove`. The parent's
    /// readdir cache must be invalidated so the next ls sees the change.
    fn handle_parent_change(&self, host_path: &Path) -> Result<(), TranslateError> {
        let rel = match self.relativize(host_path) {
            Some(r) => r,
            None => return Ok(()),
        };
        let parent_rel = rel.parent().map(Path::to_path_buf).unwrap_or_default();
        let leaf_name = match rel.file_name() {
            Some(n) => n.as_encoded_bytes().to_vec(),
            None => return Ok(()),
        };

        let (parent_inode, remaining) = self.index.resolve_path(self.root_inode, &parent_rel);
        if !remaining.is_empty() {
            debug!(
                "create/remove({}): parent not cached, skipping",
                rel.display()
            );
            return Ok(());
        }

        self.notifier.send(Notification::InvalEntry {
            parent: parent_inode,
            name: leaf_name,
        })?;
        Ok(())
    }

    fn handle_remove(&self, host_path: &Path) -> Result<(), TranslateError> {
        // Two effects: parent's readdir cache becomes stale, and any cached
        // open of the leaf becomes a "deleted-but-still-mapped" file. The
        // FUSE protocol handles both via INVAL_ENTRY (kernel will infer the
        // leaf is gone).
        self.handle_parent_change(host_path)?;

        // If the leaf inode is also cached, flush its data too. This matters
        // when something later creates a new file with the same name — the
        // guest could otherwise hand back stale data from the old inode.
        if let Some(rel) = self.relativize(host_path) {
            let (inode, remaining) = self.index.resolve_path(self.root_inode, &rel);
            if remaining.is_empty() && inode != self.root_inode {
                self.notifier.send(Notification::InvalInode { inode })?;
            }
        }
        Ok(())
    }

    fn handle_rename(
        &self,
        from: Option<&Path>,
        to: Option<&Path>,
    ) -> Result<(), TranslateError> {
        // Capture the renamed inode (if cached) before dispatching INVAL_ENTRY
        // so we can also flush its content.
        let renamed_inode = from.and_then(|p| {
            let rel = self.relativize(p)?;
            let (inode, remaining) = self.index.resolve_path(self.root_inode, &rel);
            if remaining.is_empty() && inode != self.root_inode {
                Some(inode)
            } else {
                None
            }
        });

        if let Some(p) = from {
            self.handle_parent_change(p)?;
        }
        if let Some(p) = to {
            self.handle_parent_change(p)?;
        }
        if let Some(inode) = renamed_inode {
            self.notifier.send(Notification::InvalInode { inode })?;
        }
        Ok(())
    }

    /// Invalidate every inode the index currently knows about.
    pub fn bulk_invalidate(&mut self) -> Result<(), TranslateError> {
        let inodes = self.index.all_inodes();
        info!(
            "notify-invalidate: bulk invalidating {} cached inodes",
            inodes.len()
        );
        for inode in inodes {
            // Skip root: invalidating it would force a re-mount-like flush
            // and is not what `INVAL_INODE` is for.
            if inode == self.root_inode {
                continue;
            }
            if let Err(err) = self.notifier.send(Notification::InvalInode { inode }) {
                warn!("bulk invalidate: send failed for inode {inode}: {err}");
            }
        }
        Ok(())
    }

    /// Strip the shared-dir prefix from an absolute host path. Returns `None`
    /// when the path is outside the shared dir (which can happen with
    /// FSEvents on macOS reporting symlink targets).
    fn relativize(&self, host_path: &Path) -> Option<PathBuf> {
        host_path.strip_prefix(&self.shared_dir).ok().map(Path::to_path_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::super::notifier::CapturingNotifier;
    use super::*;
    use std::path::PathBuf;

    const ROOT: Inode = 1;

    fn fixture() -> (Translator, Arc<DentryIndex>, Arc<CapturingNotifier>) {
        let idx = Arc::new(DentryIndex::new());
        let notifier = Arc::new(CapturingNotifier::new());
        let t = Translator::new(
            ROOT,
            PathBuf::from("/shared"),
            Arc::clone(&idx),
            Arc::clone(&notifier) as Arc<dyn Notifier>,
        );
        (t, idx, notifier)
    }

    #[test]
    fn modify_known_leaf_emits_inval_inode() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"a", 2);
        idx.insert(2, b"b.txt", 3);
        t.handle(HostEvent {
            kind: HostEventKind::Modify {
                path: PathBuf::from("/shared/a/b.txt"),
            },
        })
        .unwrap();
        let captured = notifier.drain();
        assert_eq!(captured.len(), 1);
        assert!(matches!(captured[0], Notification::InvalInode { inode: 3 }));
    }

    #[test]
    fn modify_unknown_path_emits_nothing() {
        let (mut t, _idx, notifier) = fixture();
        t.handle(HostEvent {
            kind: HostEventKind::Modify {
                path: PathBuf::from("/shared/nope/missing.txt"),
            },
        })
        .unwrap();
        assert!(notifier.drain().is_empty());
    }

    #[test]
    fn create_emits_inval_entry_against_parent() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"dir", 5);
        t.handle(HostEvent {
            kind: HostEventKind::Create {
                path: PathBuf::from("/shared/dir/new.txt"),
            },
        })
        .unwrap();
        let captured = notifier.drain();
        assert_eq!(captured.len(), 1);
        match &captured[0] {
            Notification::InvalEntry { parent, name } => {
                assert_eq!(*parent, 5);
                assert_eq!(name, b"new.txt");
            }
            _ => panic!("expected InvalEntry"),
        }
    }

    #[test]
    fn remove_emits_entry_and_inode_invalidations() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"dir", 5);
        idx.insert(5, b"old.txt", 7);
        t.handle(HostEvent {
            kind: HostEventKind::Remove {
                path: PathBuf::from("/shared/dir/old.txt"),
            },
        })
        .unwrap();
        let captured = notifier.drain();
        assert_eq!(captured.len(), 2);
        // parent INVAL_ENTRY first
        match &captured[0] {
            Notification::InvalEntry { parent, name } => {
                assert_eq!(*parent, 5);
                assert_eq!(name, b"old.txt");
            }
            _ => panic!("expected InvalEntry first"),
        }
        // then leaf INVAL_INODE
        match &captured[1] {
            Notification::InvalInode { inode } => assert_eq!(*inode, 7),
            _ => panic!("expected InvalInode second"),
        }
    }

    #[test]
    fn rename_paired_emits_both_sides_and_inode() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"dir", 5);
        idx.insert(5, b"old.txt", 7);
        t.handle(HostEvent {
            kind: HostEventKind::Rename {
                from: Some(PathBuf::from("/shared/dir/old.txt")),
                to: Some(PathBuf::from("/shared/dir/new.txt")),
            },
        })
        .unwrap();
        let captured = notifier.drain();
        // Two INVAL_ENTRY (old, new) + one INVAL_INODE for the renamed leaf.
        assert_eq!(captured.len(), 3);
    }

    #[test]
    fn rename_only_from_still_invalidates_parent() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"dir", 5);
        idx.insert(5, b"x", 9);
        t.handle(HostEvent {
            kind: HostEventKind::Rename {
                from: Some(PathBuf::from("/shared/dir/x")),
                to: None,
            },
        })
        .unwrap();
        let captured = notifier.drain();
        // INVAL_ENTRY for old + INVAL_INODE for the leaf.
        assert_eq!(captured.len(), 2);
    }

    #[test]
    fn overflow_invalidates_every_known_inode_except_root() {
        let (mut t, idx, notifier) = fixture();
        idx.insert(ROOT, b"a", 2);
        idx.insert(ROOT, b"b", 3);
        idx.insert(2, b"c", 4);
        t.handle(HostEvent {
            kind: HostEventKind::Overflow,
        })
        .unwrap();
        let captured = notifier.drain();
        // Three non-root inodes: 2, 3, 4.
        assert_eq!(captured.len(), 3);
        for n in &captured {
            assert!(matches!(n, Notification::InvalInode { .. }));
        }
    }

    #[test]
    fn paths_outside_shared_dir_are_ignored() {
        let (mut t, _idx, notifier) = fixture();
        t.handle(HostEvent {
            kind: HostEventKind::Modify {
                path: PathBuf::from("/etc/passwd"),
            },
        })
        .unwrap();
        assert!(notifier.drain().is_empty());
    }
}
