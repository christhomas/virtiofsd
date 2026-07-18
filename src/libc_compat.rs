// SPDX-License-Identifier: BSD-3-Clause

//! Re-export of libc with macOS compatibility additions.
//!
//! On macOS, types like `stat64`, `statvfs64`, `ino64_t`, `off64_t` do not
//! exist because all types are already 64-bit. This module provides aliases
//! so that code written for Linux compiles on macOS too.

#![allow(non_camel_case_types)]

// Re-export everything from libc
pub use libc::*;

// macOS-only additions: type aliases and stub constants/functions
#[cfg(target_os = "macos")]
mod macos_compat {
    #![allow(non_camel_case_types)]

    pub type stat64 = libc::stat;
    pub type statvfs64 = libc::statvfs;
    pub type ino64_t = libc::ino_t;
    pub type off64_t = libc::off_t;

    /// `O_TMPFILE` does not exist on macOS. Defined as 0 for compilation;
    /// callers must cfg-gate any code path that actually uses it.
    pub const O_TMPFILE: libc::c_int = 0;

    /// `O_DIRECT` does not exist on macOS. Defined as 0.
    pub const O_DIRECT: libc::c_int = 0;

    /// `O_NOATIME` does not exist on macOS. Defined as 0.
    pub const O_NOATIME: libc::c_int = 0;

    /// `CLONE_FS` does not exist on macOS. Defined as 0.
    pub const CLONE_FS: libc::c_int = 0;

    /// `fstatvfs64` on macOS is just `fstatvfs`.
    ///
    /// # Safety
    /// Same requirements as `libc::fstatvfs`.
    pub unsafe fn fstatvfs64(fd: libc::c_int, buf: *mut statvfs64) -> libc::c_int {
        libc::fstatvfs(fd, buf)
    }

    /// `fdatasync` on macOS: use `fcntl(F_FULLFSYNC)`.
    ///
    /// # Safety
    /// fd must be a valid open file descriptor.
    pub unsafe fn fdatasync(fd: libc::c_int) -> libc::c_int {
        libc::fcntl(fd, libc::F_FULLFSYNC)
    }

    /// `unshare()` does not exist on macOS. No-op that returns success.
    ///
    /// # Safety
    /// Always safe (no-op).
    pub unsafe fn unshare(_flags: libc::c_int) -> libc::c_int {
        0
    }
}

#[cfg(target_os = "macos")]
pub use macos_compat::*;
