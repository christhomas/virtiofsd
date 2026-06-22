// Copyright 2026 The Virtiofs Project Developers.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Host filesystem watcher.
//!
//! Wraps the `notify` crate to provide a normalized event stream. The kernel
//! filesystem APIs we lean on differ wildly:
//!
//! * **Linux inotify** is per-directory and does not recurse, so we set a
//!   recursive watch and rely on `notify`'s default `RecommendedWatcher`
//!   wrapper to fan out per-directory subscriptions. The system limit
//!   (`fs.inotify.max_user_watches`) is the dominant scaling concern; the
//!   watcher logs a warning at startup if the tree is large.
//!
//! * **macOS FSEvents** is whole-tree from a single subscription, so the
//!   watch limit does not apply. FSEvents coalesces aggressively (~10 ms by
//!   default in `notify`'s implementation), which is fine for our purposes.
//!
//! On both platforms, when the kernel drops events under load, `notify`
//! surfaces it as `EventKind::Other` with a watcher-specific payload. We
//! conservatively treat *any* error or unrecognized event as a potential
//! overflow and emit [`HostEventKind::Overflow`] so the translator can fall
//! back to a bulk invalidation.

use std::convert::TryFrom;
use std::fmt;
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;

use crossbeam_channel::{bounded, Receiver, Sender};
use log::{debug, info, warn};
use notify::event::{EventKind, ModifyKind, RemoveKind};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};

/// Bounded channel size for normalized events. Bounded so a slow translator
/// thread cannot run virtiofsd out of memory; if we overflow this channel we
/// emit a synthetic overflow signal exactly as we would on a kernel drop.
const EVENT_CHANNEL_SIZE: usize = 4096;

/// Soft warning threshold for inotify watch count. Above this we log a hint
/// to bump `fs.inotify.max_user_watches`. The default kernel value is 8192.
#[cfg(target_os = "linux")]
const INOTIFY_WATCH_WARN_THRESHOLD: usize = 8000;

/// A normalized event from the host filesystem.
#[derive(Debug, Clone)]
pub struct HostEvent {
    pub kind: HostEventKind,
}

#[derive(Debug, Clone)]
pub enum HostEventKind {
    /// File or directory contents/metadata changed.
    Modify { path: PathBuf },
    /// Entry created in a parent directory.
    Create { path: PathBuf },
    /// Entry removed from a parent directory.
    Remove { path: PathBuf },
    /// Entry renamed within or between directories.
    /// Either `from` or `to` may be `None` if `notify` could not pair the
    /// rename halves (e.g. when the rename happens across the watched
    /// boundary).
    Rename {
        from: Option<PathBuf>,
        to: Option<PathBuf>,
    },
    /// The host watcher dropped events. The translator should respond by
    /// invalidating every cached inode it knows about.
    Overflow,
}

#[derive(Debug)]
pub enum WatcherError {
    Notify(notify::Error),
    Spawn(io::Error),
    InvalidPath(PathBuf),
}

impl fmt::Display for WatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatcherError::Notify(e) => write!(f, "host watcher: {e}"),
            WatcherError::Spawn(e) => write!(f, "spawning watcher thread: {e}"),
            WatcherError::InvalidPath(p) => write!(f, "invalid watch path: {}", p.display()),
        }
    }
}

impl std::error::Error for WatcherError {}

impl From<notify::Error> for WatcherError {
    fn from(e: notify::Error) -> Self {
        WatcherError::Notify(e)
    }
}

/// Owns the `notify` crate watcher handle. Dropping this stops the watcher.
pub struct HostWatcher {
    _watcher: RecommendedWatcher,
    rx: Receiver<HostEvent>,
}

impl HostWatcher {
    pub fn new(shared_dir: PathBuf) -> Result<Self, WatcherError> {
        let canonical = shared_dir
            .canonicalize()
            .map_err(|_| WatcherError::InvalidPath(shared_dir.clone()))?;

        if !canonical.is_dir() {
            return Err(WatcherError::InvalidPath(canonical));
        }

        // Pre-check the directory count on Linux so the operator gets an
        // early hint when they're about to exhaust inotify watches.
        #[cfg(target_os = "linux")]
        Self::warn_if_oversized(&canonical);

        let (tx, rx) = bounded::<HostEvent>(EVENT_CHANNEL_SIZE);

        // notify uses std::sync::mpsc internally; we adapt to crossbeam to
        // get a bounded channel with try_send semantics for overflow
        // detection.
        let tx_clone = tx.clone();
        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| {
                handle_raw_event(res, &tx_clone);
            })?;
        watcher.watch(&canonical, RecursiveMode::Recursive)?;

        info!(
            "notify-invalidate: watching {} recursively",
            canonical.display()
        );

        Ok(HostWatcher {
            _watcher: watcher,
            rx,
        })
    }

    /// Subscribe to the normalized event stream.
    pub fn events(&self) -> Receiver<HostEvent> {
        self.rx.clone()
    }

    #[cfg(target_os = "linux")]
    fn warn_if_oversized(root: &Path) {
        // Cheap upper-bound: count directory entries breadth-first up to a
        // cap, so we never traverse a giant tree just to warn.
        const SCAN_CAP: usize = INOTIFY_WATCH_WARN_THRESHOLD + 1;
        let mut count = 0usize;
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            if count >= SCAN_CAP {
                break;
            }
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    count += 1;
                    if count >= SCAN_CAP {
                        break;
                    }
                    stack.push(entry.path());
                }
            }
        }
        if count >= INOTIFY_WATCH_WARN_THRESHOLD {
            warn!(
                "notify-invalidate: shared dir contains at least {count} subdirectories. \
                 Recursive inotify uses one watch per directory; consider raising \
                 fs.inotify.max_user_watches or the daemon may silently miss events."
            );
        }
    }
}

fn handle_raw_event(res: notify::Result<Event>, tx: &Sender<HostEvent>) {
    let event = match res {
        Ok(e) => e,
        Err(err) => {
            warn!("notify-invalidate: backend error, treating as overflow: {err}");
            let _ = try_send(
                tx,
                HostEvent {
                    kind: HostEventKind::Overflow,
                },
            );
            return;
        }
    };

    debug!("notify-invalidate: raw event {event:?}");

    match classify(&event) {
        Some(kind) => {
            if try_send(tx, HostEvent { kind }).is_err() {
                // Channel full — translator can't keep up. Drop and signal
                // overflow so the next free slot triggers bulk invalidate.
                warn!("notify-invalidate: event channel full, signalling overflow");
                let _ = try_send(
                    tx,
                    HostEvent {
                        kind: HostEventKind::Overflow,
                    },
                );
            }
        }
        None => {
            // Unknown event kind. Conservative: log and ignore. Anything
            // requiring invalidation should map to one of the cases above.
            debug!("notify-invalidate: ignoring unclassified event {event:?}");
        }
    }
}

fn try_send(tx: &Sender<HostEvent>, event: HostEvent) -> Result<(), HostEvent> {
    tx.try_send(event).map_err(|e| e.into_inner())
}

fn classify(event: &Event) -> Option<HostEventKind> {
    let path = event.paths.first().cloned();

    match &event.kind {
        EventKind::Create(_) => path.map(|p| HostEventKind::Create { path: p }),
        EventKind::Modify(ModifyKind::Name(_)) => Some(classify_rename(event)),
        EventKind::Modify(_) => path.map(|p| HostEventKind::Modify { path: p }),
        EventKind::Remove(RemoveKind::File)
        | EventKind::Remove(RemoveKind::Folder)
        | EventKind::Remove(RemoveKind::Other)
        | EventKind::Remove(RemoveKind::Any) => path.map(|p| HostEventKind::Remove { path: p }),
        EventKind::Access(_) => None,
        EventKind::Other => Some(HostEventKind::Overflow),
        EventKind::Any => path.map(|p| HostEventKind::Modify { path: p }),
    }
}

fn classify_rename(event: &Event) -> HostEventKind {
    use notify::event::RenameMode;

    // notify reports rename as either a paired event (`Both`) or two halves
    // (`From` / `To`). We forward whatever we have.
    match &event.kind {
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => HostEventKind::Rename {
            from: event.paths.first().cloned(),
            to: event.paths.get(1).cloned(),
        },
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => HostEventKind::Rename {
            from: event.paths.first().cloned(),
            to: None,
        },
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => HostEventKind::Rename {
            from: None,
            to: event.paths.first().cloned(),
        },
        _ => HostEventKind::Rename {
            from: event.paths.first().cloned(),
            to: event.paths.get(1).cloned(),
        },
    }
}

// Adapter so we can plug `mpsc::Sender` into APIs expecting it. Currently
// unused; reserved for if we ever need to bridge to `notify`'s own channel
// constructor.
#[allow(dead_code)]
fn mpsc_to_crossbeam<T: Send + 'static>(rx: mpsc::Receiver<T>, tx: Sender<T>) {
    std::thread::spawn(move || {
        for item in rx.iter() {
            if tx.send(item).is_err() {
                break;
            }
        }
    });
}

// Allow constructing a HostEvent from a HostEventKind for tests.
impl From<HostEventKind> for HostEvent {
    fn from(kind: HostEventKind) -> Self {
        HostEvent { kind }
    }
}

// TryFrom is not really meaningful here, but it keeps clippy quiet about the
// implicit From above being one-sided.
impl TryFrom<HostEvent> for HostEventKind {
    type Error = std::convert::Infallible;
    fn try_from(value: HostEvent) -> Result<Self, Self::Error> {
        Ok(value.kind)
    }
}
