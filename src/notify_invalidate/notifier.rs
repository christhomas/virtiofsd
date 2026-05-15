// Copyright 2026 The Virtiofs Project Developers.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! FUSE notification framing and dispatch.
//!
//! The wire format mirrors a normal FUSE reply, with two twists that come
//! straight from the kernel side (`fs/fuse/inode.c::fuse_reverse_inval_*`):
//!
//! 1. The `unique` field of [`fuse::OutHeader`] is set to **0**. The kernel
//!    distinguishes notifications from request replies by this sentinel.
//! 2. The `error` field encodes the [`fuse::NotifyOpcode`] (negative on the
//!    wire so the kernel sees it as `-NOTIFY_OPCODE`). Yes, this re-purposing
//!    of the error field is weird; it is what the protocol specifies.
//!
//! For virtio-fs specifically, the framed bytes are written into a buffer
//! the guest has placed on the dedicated *notification queue* (queue index 1
//! when `VIRTIO_FS_F_NOTIFICATION` is negotiated). This module owns the
//! framing; the queue plumbing lives in `vhost_user.rs`.

use std::fmt;
use std::io;
use std::mem::size_of;
use std::sync::Mutex;

use log::{debug, warn};
use vm_memory::ByteValued;

use crate::fuse::{self, NotifyInvalEntryOut, NotifyInvalInodeOut, NotifyOpcode, OutHeader};
use crate::passthrough::inode_store::Inode;

/// A single FUSE notification ready to frame and send.
#[derive(Debug, Clone)]
pub enum Notification {
    /// `FUSE_NOTIFY_INVAL_INODE` — drop cached attrs/data for this inode.
    /// Setting `len` to `-1` invalidates the entire data cache for the inode
    /// (matches what `fuse_reverse_inval_inode` does on the kernel side when
    /// passed a negative length).
    InvalInode { inode: Inode },
    /// `FUSE_NOTIFY_INVAL_ENTRY` — drop the (parent, name) dentry. Used when
    /// a child is created, removed, or renamed under a parent the guest has
    /// already enumerated.
    InvalEntry { parent: Inode, name: Vec<u8> },
}

impl Notification {
    /// Serialize into the on-the-wire byte sequence:
    ///   `OutHeader { len, error: -opcode, unique: 0 } || body || maybe-name || maybe-NUL`
    ///
    /// The trailing NUL is required for `INVAL_ENTRY`; the kernel's
    /// `fuse_notify_inval_entry` reads `namelen + 1` bytes of name and
    /// expects the last byte to be a NUL terminator (see
    /// `fs/fuse/inode.c`).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Notification::InvalInode { inode } => {
                let body = NotifyInvalInodeOut {
                    ino: *inode,
                    off: 0,
                    len: -1,
                };
                let total_len = size_of::<OutHeader>() + size_of::<NotifyInvalInodeOut>();
                let header = OutHeader {
                    len: total_len as u32,
                    error: -(NotifyOpcode::InvalInode as i32),
                    unique: 0,
                };
                let mut out = Vec::with_capacity(total_len);
                out.extend_from_slice(header.as_slice());
                out.extend_from_slice(body.as_slice());
                out
            }
            Notification::InvalEntry { parent, name } => {
                let body = NotifyInvalEntryOut {
                    parent: *parent,
                    namelen: name.len() as u32,
                    flags: 0,
                };
                // namelen excludes the trailing NUL; +1 for the NUL itself.
                let total_len = size_of::<OutHeader>()
                    + size_of::<NotifyInvalEntryOut>()
                    + name.len()
                    + 1;
                let header = OutHeader {
                    len: total_len as u32,
                    error: -(NotifyOpcode::InvalEntry as i32),
                    unique: 0,
                };
                let mut out = Vec::with_capacity(total_len);
                out.extend_from_slice(header.as_slice());
                out.extend_from_slice(body.as_slice());
                out.extend_from_slice(name);
                out.push(0);
                out
            }
        }
    }

    /// Human-readable opcode name for logging.
    pub fn opcode_name(&self) -> &'static str {
        match self {
            Notification::InvalInode { .. } => "FUSE_NOTIFY_INVAL_INODE",
            Notification::InvalEntry { .. } => "FUSE_NOTIFY_INVAL_ENTRY",
        }
    }
}

#[derive(Debug)]
pub enum NotifierError {
    /// The guest has not negotiated `VIRTIO_FS_F_NOTIFICATION`, so we have no
    /// queue to write to.
    QueueNotNegotiated,
    /// No buffer available on the notification queue. Caller should retry or
    /// drop the notification (and queue an overflow signal).
    QueueFull,
    /// A buffer was available but it is too small for this notification.
    BufferTooSmall { needed: usize, have: usize },
    /// Underlying I/O error encoding into the queue buffer.
    Io(io::Error),
}

impl fmt::Display for NotifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotifierError::QueueNotNegotiated => {
                write!(f, "guest has not negotiated VIRTIO_FS_F_NOTIFICATION")
            }
            NotifierError::QueueFull => write!(f, "notification queue full"),
            NotifierError::BufferTooSmall { needed, have } => {
                write!(f, "queue buffer too small (needed {needed}, have {have})")
            }
            NotifierError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NotifierError {}

impl From<io::Error> for NotifierError {
    fn from(e: io::Error) -> Self {
        NotifierError::Io(e)
    }
}

/// Sink for serialized FUSE notifications. The pipeline in
/// [`super::spawn_pipeline`] holds an `Arc<dyn Notifier>`; the production
/// implementation forwards into the virtio-fs notification queue.
pub trait Notifier: Send + Sync {
    fn send(&self, notification: Notification) -> Result<(), NotifierError>;
}

/// Logging-only notifier. Useful before the notification queue is wired up
/// or in unit tests where we just want to verify the translator's behavior.
/// Not used in production paths once the vhost notification queue lands.
pub struct LoggingNotifier;

impl Notifier for LoggingNotifier {
    fn send(&self, notification: Notification) -> Result<(), NotifierError> {
        let bytes = notification.encode();
        debug!(
            "would send {} ({} bytes): {:?}",
            notification.opcode_name(),
            bytes.len(),
            notification
        );
        Ok(())
    }
}

/// In-memory notifier that records every sent notification. Used for tests.
#[derive(Default)]
pub struct CapturingNotifier {
    captured: Mutex<Vec<Notification>>,
}

impl CapturingNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drain(&self) -> Vec<Notification> {
        std::mem::take(&mut *self.captured.lock().unwrap())
    }
}

impl Notifier for CapturingNotifier {
    fn send(&self, notification: Notification) -> Result<(), NotifierError> {
        self.captured.lock().unwrap().push(notification);
        Ok(())
    }
}

/// Combinator that drops notifications and increments a counter when the
/// underlying notifier returns `QueueFull`. The pipeline reads the counter to
/// decide when to escalate to a bulk invalidate.
pub struct DropOnFullNotifier<N: Notifier> {
    inner: N,
    dropped: std::sync::atomic::AtomicU64,
}

impl<N: Notifier> DropOnFullNotifier<N> {
    pub fn new(inner: N) -> Self {
        Self {
            inner,
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl<N: Notifier> Notifier for DropOnFullNotifier<N> {
    fn send(&self, notification: Notification) -> Result<(), NotifierError> {
        match self.inner.send(notification) {
            Err(NotifierError::QueueFull) => {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("notification dropped (queue full)");
                Ok(())
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inval_inode_frame_layout() {
        let bytes = Notification::InvalInode { inode: 42 }.encode();
        assert_eq!(
            bytes.len(),
            size_of::<OutHeader>() + size_of::<NotifyInvalInodeOut>()
        );

        // Header: { len, error: -2 (InvalInode), unique: 0 }
        let header_bytes = &bytes[..size_of::<OutHeader>()];
        let header: OutHeader = unsafe { std::ptr::read_unaligned(header_bytes.as_ptr() as *const OutHeader) };
        assert_eq!(header.unique, 0);
        assert_eq!(header.error, -(NotifyOpcode::InvalInode as i32));
        assert_eq!(header.len as usize, bytes.len());

        // Body: { ino: 42, off: 0, len: -1 }
        let body_bytes = &bytes[size_of::<OutHeader>()..];
        let body: NotifyInvalInodeOut = unsafe {
            std::ptr::read_unaligned(body_bytes.as_ptr() as *const NotifyInvalInodeOut)
        };
        assert_eq!(body.ino, 42);
        assert_eq!(body.off, 0);
        assert_eq!(body.len, -1);
    }

    #[test]
    fn inval_entry_frame_includes_trailing_nul() {
        let name = b"hello.txt".to_vec();
        let bytes = Notification::InvalEntry {
            parent: 7,
            name: name.clone(),
        }
        .encode();

        let expected_len =
            size_of::<OutHeader>() + size_of::<NotifyInvalEntryOut>() + name.len() + 1;
        assert_eq!(bytes.len(), expected_len);
        assert_eq!(*bytes.last().unwrap(), 0u8, "name must end with NUL");

        let body_offset = size_of::<OutHeader>();
        let body: NotifyInvalEntryOut = unsafe {
            std::ptr::read_unaligned(bytes[body_offset..].as_ptr() as *const NotifyInvalEntryOut)
        };
        assert_eq!(body.parent, 7);
        assert_eq!(body.namelen as usize, name.len());

        let name_offset = body_offset + size_of::<NotifyInvalEntryOut>();
        assert_eq!(&bytes[name_offset..name_offset + name.len()], &name[..]);
    }

    #[test]
    fn capturing_notifier_records() {
        let n = CapturingNotifier::new();
        n.send(Notification::InvalInode { inode: 1 }).unwrap();
        n.send(Notification::InvalEntry { parent: 1, name: b"x".to_vec() })
            .unwrap();
        let got = n.drain();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn drop_on_full_increments_counter() {
        struct AlwaysFull;
        impl Notifier for AlwaysFull {
            fn send(&self, _: Notification) -> Result<(), NotifierError> {
                Err(NotifierError::QueueFull)
            }
        }

        let n = DropOnFullNotifier::new(AlwaysFull);
        for _ in 0..3 {
            n.send(Notification::InvalInode { inode: 1 }).unwrap();
        }
        assert_eq!(n.dropped_count(), 3);
    }
}
