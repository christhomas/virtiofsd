// SPDX-License-Identifier: BSD-3-Clause

//! Platform-neutral OS library abstractions.
//!
//! This module re-exports platform-specific implementations so callers
//! do not need `#[cfg]` gates.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

// ── Shared helpers ──────────────────────────────────────────────────────────

use std::io::{self, Error, Result};

/// A helper function that checks the return value of a C function call
/// and wraps it in a `Result` type, returning the `errno` code as `Err`.
pub(crate) fn check_retval<T: From<i8> + PartialEq>(t: T) -> Result<T> {
    if t == T::from(-1_i8) {
        Err(Error::last_os_error())
    } else {
        Ok(t)
    }
}

// ── Shared types (cross-platform) ───────────────────────────────────────────

use std::fs::File;
use std::os::unix::io::RawFd;

/// Readable end of a pipe.
pub struct PipeReader(File);

impl io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.0.read(buf)
    }
}

/// Writable end of a pipe.
pub struct PipeWriter(File);

impl io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        use std::io::Write;
        self.0.flush()
    }
}

/// An RAII implementation of a scoped file mode creation mask (umask).
/// When this structure is dropped (falls out of scope), the previous
/// value of the mask is restored.
pub struct ScopedUmask {
    umask: libc::mode_t,
}

impl ScopedUmask {
    pub fn new(new_umask: u32) -> Self {
        Self {
            umask: umask(new_umask),
        }
    }
}

impl Drop for ScopedUmask {
    fn drop(&mut self) {
        umask(self.umask);
    }
}

/// Safe wrapper for `umask(2)`
pub fn umask(mask: u32) -> u32 {
    // SAFETY: this call doesn't modify any memory and there is no need
    // to check the return value because this system call always succeeds.
    unsafe { libc::umask(mask) }
}

/// Safe wrapper for `fchdir(2)`
pub fn fchdir(fd: RawFd) -> Result<()> {
    check_retval(unsafe { libc::fchdir(fd) })?;
    Ok(())
}

/// Safe wrapper for `fchmod(2)`
pub fn fchmod(fd: RawFd, mode: libc::mode_t) -> Result<()> {
    check_retval(unsafe { libc::fchmod(fd, mode) })?;
    Ok(())
}

/// Safe wrapper for `fchmodat(2)`
pub fn fchmodat(dirfd: RawFd, pathname: String, mode: libc::mode_t, flags: i32) -> Result<()> {
    use std::ffi::CString;
    let pathname =
        CString::new(pathname).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pathname = pathname.as_ptr();

    check_retval(unsafe { libc::fchmodat(dirfd, pathname, mode, flags) })?;
    Ok(())
}

/// Safe wrapper around `openat(2)`.
pub fn openat(
    dir: &impl std::os::unix::io::AsRawFd,
    pathname: &std::ffi::CStr,
    flags: i32,
    mode: Option<u32>,
) -> Result<RawFd> {
    use std::os::unix::io::AsRawFd;
    let mode = u64::from(mode.unwrap_or(0));

    check_retval(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            pathname.as_ptr(),
            flags as libc::c_int,
            mode,
        )
    })
}

// ── Platform re-exports ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::{
    // OsFacts
    OsFacts,
    // Mount operations
    mount, umount2,
    // open_tree / move_mount (Linux-specific mount API)
    open_tree, move_mount, MOVE_MOUNT_F_EMPTY_PATH,
    // openat2-based safe open
    do_open_relative_to,
    // File handle operations
    CFileHandle, name_to_handle_at, open_by_handle_at,
    // IO flags and vectored IO
    WritevFlags, ReadvFlags, writev_at, readv_at,
    // Pipe
    pipe,
    // Credential helpers
    seteffuid, seteffgid, setsupgroup, dropsupgroups,
};

#[cfg(target_os = "macos")]
pub use macos::{
    OsFacts,
    mount, umount2,
    open_tree, move_mount, MOVE_MOUNT_F_EMPTY_PATH,
    do_open_relative_to,
    CFileHandle, name_to_handle_at, open_by_handle_at,
    WritevFlags, ReadvFlags, writev_at, readv_at,
    pipe,
    seteffuid, seteffgid, setsupgroup, dropsupgroups,
};
