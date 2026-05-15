// Copyright 2026 The Virtiofs Project Developers.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Push-based cache invalidation for virtiofsd.
//!
//! Without this module, virtiofsd is purely reactive: the guest decides when
//! to revalidate cached attributes/dentries based on `--cache=auto` TTLs.
//! When a file changes on the host, the guest only sees the change after its
//! TTL expires (~1 s) or when an out-of-band invalidation happens (e.g.
//! `--cache=never`, which carries its own throughput cost).
//!
//! With this module enabled (via the `--notify-invalidate` flag), virtiofsd
//! watches the shared directory tree on the host and emits FUSE invalidation
//! messages to the guest as soon as it sees a change. The guest kernel drops
//! its cached data/dentries and the next access sees fresh state.
//!
//! # Architecture
//!
//! ```text
//!   ┌────────────┐ host events  ┌──────────────┐ inode IDs ┌──────────────┐
//!   │ HostWatcher │─────────────▶│  Translator  │──────────▶│  Notifier    │
//!   │ (notify rs) │              │ (DentryIndex │           │ (vhost notif │
//!   └────────────┘              │   resolver)  │           │  queue)      │
//!                                └──────────────┘           └──────────────┘
//! ```
//!
//! * [`watcher::HostWatcher`] wraps the `notify` crate and emits a normalized
//!   stream of [`watcher::HostEvent`] values plus an explicit overflow signal.
//! * [`translate::Translator`] consumes those events, resolves them through
//!   the [`crate::passthrough::dentry_index::DentryIndex`] (which is kept in
//!   sync with the FUSE op hot path), and emits
//!   [`notifier::Notification`] values.
//! * [`notifier::Notifier`] frames each notification as
//!   `OutHeader { unique: 0, error: NotifyOpcode } + body` and writes it to
//!   the virtio-fs notification queue (when the guest has negotiated
//!   `VIRTIO_FS_F_NOTIFICATION`).
//!
//! The split is deliberate: the watcher knows nothing about FUSE wire format,
//! the notifier knows nothing about host filesystems, and the translator owns
//! the index but no I/O. Each piece is unit-testable on its own.
//!
//! # What this module does *not* guarantee
//!
//! * Notifications are best-effort. Both `inotify` and FSEvents drop events
//!   under heavy churn; the watcher detects this and triggers a bulk
//!   invalidation, but the guest may briefly serve stale data between the
//!   overflow and the bulk-invalidate landing.
//! * Events occurring between daemon start and watcher subscription are lost.
//!   The pipeline does an initial bulk invalidate when it comes up to cover
//!   that window.
//! * The TTL-based revalidation in `--cache=auto` is *not* removed. Push
//!   invalidation is a fast path on top of the TTL backstop, not a
//!   replacement for it.

pub mod notifier;
pub mod translate;
pub mod watcher;

pub use notifier::{Notification, Notifier, NotifierError};
pub use translate::Translator;
pub use watcher::{HostEvent, HostEventKind, HostWatcher, WatcherError};

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use log::{error, info, warn};

use crate::passthrough::dentry_index::DentryIndex;
use crate::passthrough::inode_store::Inode;

/// Spawn the full watcher → translator → notifier pipeline on a background
/// thread. Returns a join handle for shutdown.
pub fn spawn_pipeline(
    shared_dir: PathBuf,
    root_inode: Inode,
    dentry_index: Arc<DentryIndex>,
    notifier: Arc<dyn Notifier>,
) -> Result<thread::JoinHandle<()>, WatcherError> {
    let watcher = HostWatcher::new(shared_dir.clone())?;
    let rx = watcher.events();
    let mut translator = Translator::new(root_inode, shared_dir, dentry_index, notifier);

    // Initial bulk invalidate covers the start-up gap between daemon launch
    // and watcher subscription. The watcher's `Modify` semantics differ
    // between platforms, so it is cheap insurance.
    if let Err(err) = translator.bulk_invalidate() {
        warn!("Initial bulk invalidate failed: {err}");
    }

    let handle = thread::Builder::new()
        .name("virtiofsd-notify-invalidate".to_string())
        .spawn(move || {
            // Keep the watcher alive for the duration of the thread.
            let _watcher = watcher;
            info!("notify-invalidate pipeline running");
            for event in rx.iter() {
                if let Err(err) = translator.handle(event) {
                    error!("notify-invalidate failed to dispatch event: {err}");
                }
            }
            info!("notify-invalidate pipeline terminated");
        })
        .map_err(WatcherError::Spawn)?;
    Ok(handle)
}
