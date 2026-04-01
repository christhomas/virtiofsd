// SPDX-License-Identifier: BSD-3-Clause

//! macOS platform implementations for oslib functions.

use super::check_retval;
use super::{PipeReader, PipeWriter};
use crate::soft_idmap::{HostGid, HostUid, Id};
use bitflags::bitflags;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Result};
use std::os::unix::io::{AsRawFd, BorrowedFd, RawFd};
use std::os::unix::prelude::FromRawFd;

/// Simple object to collect basic facts about the OS.
/// On macOS, `openat2` is never available.
pub struct OsFacts {
    pub has_openat2: bool,
}

#[allow(clippy::new_without_default)]
impl OsFacts {
    #[must_use]
    pub fn new() -> Self {
        Self {
            has_openat2: false,
        }
    }
}

/// mount() -- no-op stub on macOS.
/// The sandbox on macOS does not use Linux mount namespaces.
///
/// # Errors
///
/// Always returns `Err(ENOSYS)` on macOS.
pub fn mount(
    _source: Option<&str>,
    _target: &str,
    _fstype: Option<&str>,
    _flags: u64,
) -> Result<()> {
    // TODO(macos): Implement if macOS sandbox needs mount operations
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// umount2() -- no-op stub on macOS.
///
/// # Errors
///
/// Always returns `Err(ENOSYS)` on macOS.
pub fn umount2(_target: &str, _flags: i32) -> Result<()> {
    // TODO(macos): Implement if macOS sandbox needs unmount operations
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// open_tree() -- not available on macOS.
///
/// # Errors
///
/// Always returns `Err(ENOSYS)`.
pub fn open_tree(
    _dir: Option<&dyn AsRawFd>,
    _pathname: &CStr,
    _flags: u32,
) -> Result<RawFd> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

pub const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x00000004;

/// move_mount() -- not available on macOS.
///
/// # Errors
///
/// Always returns `Err(ENOSYS)`.
pub fn move_mount(
    _from_dir: Option<&dyn AsRawFd>,
    _from_path: &CStr,
    _to_dir: Option<&dyn AsRawFd>,
    _to_path: &CStr,
    _flags: u32,
) -> Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// macOS replacement for Linux `openat2(2)` with `RESOLVE_IN_ROOT`.
///
/// Uses `openat()` with `O_NOFOLLOW` and manual path traversal to prevent
/// escaping the root directory. Each path component is opened individually
/// with `O_NOFOLLOW` to catch symlinks.
///
/// # Safety
///
/// The caller must ensure that dirfd is a valid file descriptor.
pub fn do_open_relative_to(
    dir: &impl AsRawFd,
    pathname: &CStr,
    flags: i32,
    mode: Option<u32>,
) -> Result<RawFd> {
    let mode = u64::from(mode.unwrap_or(0)) & 0o7777;

    // TODO(macos): Full symlink-safe path traversal for parity with
    // RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS. For now, use a simple
    // openat with O_NOFOLLOW which prevents following the final symlink
    // but does not prevent intermediate symlink escapes.
    let path_str = pathname.to_str().unwrap_or("");

    if path_str.is_empty() || path_str == "." {
        // Opening the directory itself
        return check_retval(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                pathname.as_ptr(),
                flags | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        });
    }

    // Walk each component with O_NOFOLLOW | O_DIRECTORY to prevent symlink escapes
    let components: Vec<&str> = path_str
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();

    if components.is_empty() {
        return check_retval(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                pathname.as_ptr(),
                flags | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        });
    }

    // Open intermediate directories with O_NOFOLLOW | O_DIRECTORY
    let mut current_fd = dir.as_raw_fd();
    let mut owned_fds: Vec<RawFd> = Vec::new();

    for (i, component) in components.iter().enumerate() {
        if *component == ".." {
            // Prevent escaping root -- reject .. components
            for fd in &owned_fds {
                unsafe { libc::close(*fd) };
            }
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }

        let c_component = CString::new(*component)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if i < components.len() - 1 {
            // Intermediate component: open as directory, no follow
            let fd = check_retval(unsafe {
                libc::openat(
                    current_fd,
                    c_component.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                )
            })
            .map_err(|e| {
                for fd in &owned_fds {
                    unsafe { libc::close(*fd) };
                }
                e
            })?;
            owned_fds.push(fd);
            current_fd = fd;
        } else {
            // Final component: open with caller's flags
            let result = check_retval(unsafe {
                libc::openat(
                    current_fd,
                    c_component.as_ptr(),
                    flags | libc::O_NOFOLLOW,
                    mode as libc::c_uint,
                )
            });

            for fd in &owned_fds {
                unsafe { libc::close(*fd) };
            }

            return result;
        }
    }

    // Should not reach here
    for fd in &owned_fds {
        unsafe { libc::close(*fd) };
    }
    Err(io::Error::from_raw_os_error(libc::EINVAL))
}

// ── File handle abstraction ─────────────────────────────────────────────────

/// macOS does not have `name_to_handle_at` / `open_by_handle_at`.
/// We provide a compatible `CFileHandle` type that stores dev+ino.

const MAX_HANDLE_SZ: usize = 128;

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct CFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; MAX_HANDLE_SZ],
}

impl Default for CFileHandle {
    fn default() -> Self {
        CFileHandle {
            handle_bytes: MAX_HANDLE_SZ as u32,
            handle_type: 0,
            f_handle: [0; MAX_HANDLE_SZ],
        }
    }
}

impl CFileHandle {
    pub fn as_bytes(&self) -> &[u8] {
        &self.f_handle[..(self.handle_bytes as usize)]
    }

    pub fn handle_type(&self) -> libc::c_int {
        self.handle_type
    }
}

impl std::convert::TryFrom<&crate::passthrough::file_handle::SerializableFileHandle>
    for CFileHandle
{
    type Error = io::Error;

    fn try_from(
        sfh: &crate::passthrough::file_handle::SerializableFileHandle,
    ) -> io::Result<Self> {
        let sfh_bytes = sfh.as_bytes();
        if sfh_bytes.len() > MAX_HANDLE_SZ {
            return Err(crate::util::other_io_error("File handle too long"));
        }
        let mut f_handle = [0u8; MAX_HANDLE_SZ];
        f_handle[..sfh_bytes.len()].copy_from_slice(sfh_bytes);

        Ok(CFileHandle {
            handle_bytes: sfh_bytes.len() as u32,
            handle_type: sfh.handle_type(),
            f_handle,
        })
    }
}

/// macOS stub for `name_to_handle_at`.
/// Uses `fstatat` to fill in dev+ino as a pseudo file handle.
///
/// # Errors
///
/// Returns `Err(EOPNOTSUPP)` since macOS has no real file handle support.
pub fn name_to_handle_at(
    _dirfd: &impl AsRawFd,
    _pathname: &CStr,
    _file_handle: &mut CFileHandle,
    _mount_id: &mut libc::c_int,
    _flags: libc::c_int,
) -> Result<()> {
    // TODO(macos): Implement dev+ino based pseudo file handles
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

/// macOS stub for `open_by_handle_at`.
///
/// # Errors
///
/// Returns `Err(EOPNOTSUPP)` since macOS has no real file handle support.
pub fn open_by_handle_at(
    _mount_fd: &impl AsRawFd,
    _file_handle: &CFileHandle,
    _flags: libc::c_int,
) -> Result<File> {
    // TODO(macos): Implement reopen via stored path
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

// ── IO flags ────────────────────────────────────────────────────────────────

bitflags! {
    /// Write flags -- macOS has no per-call IO flags, so this is empty.
    pub struct WritevFlags: i32 {
        // No macOS equivalents for RWF_* flags
    }
}

bitflags! {
    /// Read flags -- macOS has no per-call IO flags, so this is empty.
    pub struct ReadvFlags: i32 {
        // No macOS equivalents for RWF_* flags
    }
}

/// Safe wrapper for `pwritev(2)` (macOS does not have `pwritev2`).
///
/// Flags are accepted for API compatibility but ignored (macOS has no per-call IO flags).
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid.
pub unsafe fn writev_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    _flags: Option<WritevFlags>,
) -> Result<usize> {
    // macOS pwritev does not support flags; we use pwritev.
    let bytes_written = check_retval(unsafe {
        libc::pwritev(
            fd.as_raw_fd(),
            iovecs.as_ptr(),
            iovecs.len() as libc::c_int,
            offset,
        )
    })?;
    Ok(bytes_written as usize)
}

/// Safe wrapper for `preadv(2)` (macOS does not have `preadv2`).
///
/// Flags are accepted for API compatibility but ignored.
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid.
pub unsafe fn readv_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    _flags: Option<ReadvFlags>,
) -> Result<usize> {
    let bytes_read = check_retval(unsafe {
        libc::preadv(
            fd.as_raw_fd(),
            iovecs.as_ptr(),
            iovecs.len() as libc::c_int,
            offset,
        )
    })?;
    Ok(bytes_read as usize)
}

pub fn pipe() -> io::Result<(PipeReader, PipeWriter)> {
    let mut fds: [RawFd; 2] = [-1, -1];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    // Set O_CLOEXEC on both ends (macOS does not have pipe2)
    for &fd in &fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(io::Error::last_os_error());
        }
    }

    Ok((
        PipeReader(unsafe { File::from_raw_fd(fds[0]) }),
        PipeWriter(unsafe { File::from_raw_fd(fds[1]) }),
    ))
}

// ── Credential helpers ──────────────────────────────────────────────────────

/// Set effective user ID.
/// On macOS, we use `seteuid()` directly.
/// Note: macOS does not have per-thread credentials like Linux.
pub fn seteffuid(uid: HostUid) -> io::Result<()> {
    // TODO(macos): macOS seteuid is process-wide, not per-thread.
    // This may cause issues with concurrent credential switching.
    check_retval(unsafe { libc::seteuid(uid.into_inner()) })?;
    Ok(())
}

/// Set effective group ID.
pub fn seteffgid(gid: HostGid) -> io::Result<()> {
    check_retval(unsafe { libc::setegid(gid.into_inner()) })?;
    Ok(())
}

/// Set supplementary groups.
pub fn setsupgroup(gids: &[HostGid]) -> io::Result<()> {
    check_retval(unsafe {
        libc::setgroups(
            gids.len() as libc::c_int,
            gids.as_ptr() as *const libc::gid_t,
        )
    })?;
    Ok(())
}

/// Drop all supplementary groups.
pub fn dropsupgroups() -> io::Result<()> {
    check_retval(unsafe { libc::setgroups(0, std::ptr::null::<libc::gid_t>()) })?;
    Ok(())
}
