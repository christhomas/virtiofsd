// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Platform-neutral sandbox abstraction.
//!
//! On Linux, uses namespaces/pivot_root/seccomp.
//! On macOS, uses chroot-based sandbox (no namespace support).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::str::FromStr;
use std::{error, fmt, io};

// ── Shared types ────────────────────────────────────────────────────────────

/// Mechanism to be used for setting up the sandbox.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SandboxMode {
    /// Create the sandbox using Linux namespaces.
    Namespace,
    /// Create the sandbox using chroot.
    Chroot,
    /// Don't attempt to isolate the process inside a sandbox.
    None,
}

impl FromStr for SandboxMode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "namespace" => Ok(SandboxMode::Namespace),
            "chroot" => Ok(SandboxMode::Chroot),
            "none" => Ok(SandboxMode::None),
            _ => Err("Unknown sandbox mode"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Failed to bind mount `/proc/self/fd` into a temporary directory.
    BindMountProcSelfFd(io::Error),
    /// Failed to bind mount shared directory.
    BindMountSharedDir(io::Error),
    /// Failed to change to the old root directory.
    ChdirOldRoot(io::Error),
    /// Failed to change to the new root directory.
    ChdirNewRoot(io::Error),
    /// Call to libc::chroot returned an error.
    Chroot(io::Error),
    /// Failed to change to the root directory after the chroot call.
    ChrootChdir(io::Error),
    /// Failed to clean the properties of the mount point.
    CleanMount(io::Error),
    /// Failed to create a temporary directory.
    CreateTempDir(io::Error),
    /// Failed to drop supplemental groups.
    DropSupplementalGroups(io::Error),
    /// Call to libc::fork returned an error.
    Fork(io::Error),
    /// Failed to get the number of supplemental groups.
    GetSupplementalGroups(io::Error),
    /// Error bind-mounting a directory.
    MountBind(io::Error),
    /// Failed to mount old root.
    MountOldRoot(io::Error),
    /// Error mounting proc.
    MountProc(io::Error),
    /// Failed to mount new root.
    MountNewRoot(io::Error),
    /// Error mounting target directory.
    MountTarget(io::Error),
    /// Failed to open `/proc/self/mountinfo`.
    OpenMountinfo(io::Error),
    /// Failed to open new root.
    OpenNewRoot(io::Error),
    /// Failed to open old root.
    OpenOldRoot(io::Error),
    /// Failed to stat new root.
    StatNewRoot(io::Error),
    /// Failed to stat old root.
    StatOldRoot(io::Error),
    /// Failed to open `/proc/self`.
    OpenProcSelf(io::Error),
    /// Failed to open `/proc/self/fd`.
    OpenProcSelfFd(io::Error),
    /// Error switching root directory.
    PivotRoot(io::Error),
    /// Failed to remove temporary directory.
    RmdirTempDir(io::Error),
    /// Failed to lazily unmount old root.
    UmountOldRoot(io::Error),
    /// Failed to lazily unmount temporary directory.
    UmountTempDir(io::Error),
    /// Call to libc::unshare returned an error.
    Unshare(io::Error),
    /// Failed to execute `newgidmap(1)`.
    WriteGidMap(String),
    /// Failed to write to `/proc/self/setgroups`.
    WriteSetGroups(io::Error),
    /// Failed to execute `newuidmap(1)`.
    WriteUidMap(String),
    /// Sandbox mode unavailable for non-privileged users
    SandboxModeInvalidUID,
    /// Setting uid_map is only allowed inside a namespace for non-privileged users
    SandboxModeInvalidUidMap,
    /// Setting gid_map is only allowed inside a namespace for non-privileged users
    SandboxModeInvalidGidMap,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Error::{
            SandboxModeInvalidGidMap, SandboxModeInvalidUID, SandboxModeInvalidUidMap, WriteGidMap,
            WriteUidMap,
        };
        match self {
            SandboxModeInvalidUID => {
                write!(
                    f,
                    "sandbox mode 'chroot' can only be used by \
                    root (Use '--sandbox namespace' instead)"
                )
            }
            SandboxModeInvalidUidMap => {
                write!(
                    f,
                    "uid_map can only be used by unprivileged user where sandbox mod is namespace \
                    (Use '--sandbox namespace' instead)"
                )
            }
            SandboxModeInvalidGidMap => {
                write!(
                    f,
                    "gid_map can only be used by unprivileged user where sandbox mod is namespace \
                    (Use '--sandbox namespace' instead)"
                )
            }
            WriteUidMap(msg) => write!(f, "write to uid map failed: {msg}"),
            WriteGidMap(msg) => write!(f, "write to gid map failed: {msg}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

// ── Platform re-exports ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::Sandbox;

#[cfg(target_os = "macos")]
pub use macos::Sandbox;
