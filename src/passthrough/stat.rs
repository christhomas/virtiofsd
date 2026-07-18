// Copyright 2021 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_os = "macos")]
use crate::libc_compat as libc;

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
mod file_status;
#[cfg(target_os = "linux")]
use crate::oslib;
#[cfg(target_os = "linux")]
use file_status::{statx_st, STATX_BASIC_STATS, STATX_MNT_ID};

const EMPTY_CSTR: &[u8] = b"\0";

pub type MountId = u64;

pub struct StatExt {
    pub st: libc::stat64,
    pub mnt_id: MountId,
}

#[cfg(target_os = "linux")]
/*
 * Fields in libc::statx are only valid if their respective flag in
 * .stx_mask is set.  This trait provides functions that allow safe
 * access to the libc::statx components we are interested in.
 *
 * (The implementations of these functions need to check whether the
 * associated flag is set, and then extract the respective information
 * to return it.)
 */
trait SafeStatXAccess {
    fn stat64(&self) -> Option<libc::stat64>;
    fn mount_id(&self) -> Option<MountId>;
}

#[cfg(target_os = "linux")]
impl SafeStatXAccess for statx_st {
    fn stat64(&self) -> Option<libc::stat64> {
        fn makedev(maj: libc::c_uint, min: libc::c_uint) -> libc::dev_t {
            libc::makedev(maj, min)
        }

        if self.stx_mask & STATX_BASIC_STATS != 0 {
            /*
             * Unfortunately, we cannot use an initializer to create the
             * stat64 object, because it may contain padding and reserved
             * fields (depending on the architecture), and it does not
             * implement the Default trait.
             * So we take a zeroed struct and set what we can.
             * (Zero in all fields is wrong, but safe.)
             */
            let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };

            st.st_dev = makedev(self.stx_dev_major, self.stx_dev_minor);
            st.st_ino = self.stx_ino;
            st.st_mode = self.stx_mode as _;
            st.st_nlink = self.stx_nlink as _;
            st.st_uid = self.stx_uid;
            st.st_gid = self.stx_gid;
            st.st_rdev = makedev(self.stx_rdev_major, self.stx_rdev_minor);
            st.st_size = self.stx_size as _;
            st.st_blksize = self.stx_blksize as _;
            st.st_blocks = self.stx_blocks as _;
            st.st_atime = self.stx_atime.tv_sec;
            st.st_atime_nsec = self.stx_atime.tv_nsec as _;
            st.st_mtime = self.stx_mtime.tv_sec;
            st.st_mtime_nsec = self.stx_mtime.tv_nsec as _;
            st.st_ctime = self.stx_ctime.tv_sec;
            st.st_ctime_nsec = self.stx_ctime.tv_nsec as _;

            Some(st)
        } else {
            None
        }
    }

    fn mount_id(&self) -> Option<MountId> {
        if self.stx_mask & STATX_MNT_ID != 0 {
            Some(self.stx_mnt_id)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn get_mount_id(dir: &impl AsRawFd, path: &CStr) -> Option<MountId> {
    let mut mount_id: libc::c_int = 0;
    let mut c_fh = oslib::CFileHandle::default();

    oslib::name_to_handle_at(dir, path, &mut c_fh, &mut mount_id, libc::AT_EMPTY_PATH)
        .ok()
        .and(Some(mount_id as MountId))
}

// Only works on Linux, and libc::SYS_statx is only defined for these
// environments
/// Performs a statx() syscall.  libc provides libc::statx() that does
/// the same, however, the system's libc may not have a statx() wrapper
/// (e.g. glibc before 2.28), so linking to it may fail.
/// libc::syscall() and libc::SYS_statx are always present, though, so
/// we can safely rely on them.
#[cfg(target_os = "linux")]
unsafe fn do_statx(
    dirfd: libc::c_int,
    pathname: *const libc::c_char,
    flags: libc::c_int,
    mask: libc::c_uint,
    statxbuf: *mut statx_st,
) -> libc::c_int {
    libc::syscall(libc::SYS_statx, dirfd, pathname, flags, mask, statxbuf) as libc::c_int
}

// Real statx() that depends on do_statx()
#[cfg(target_os = "linux")]
pub fn statx(dir: &impl AsRawFd, path: Option<&CStr>) -> io::Result<StatExt> {
    let mut stx_ui = MaybeUninit::<statx_st>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let path = path.unwrap_or_else(|| unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) });

    // Safe because the kernel will only write data in `stx_ui` and we
    // check the return value.
    let res = unsafe {
        do_statx(
            dir.as_raw_fd(),
            path.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            STATX_BASIC_STATS | STATX_MNT_ID,
            stx_ui.as_mut_ptr(),
        )
    };
    if res >= 0 {
        // Safe because we are only going to use the SafeStatXAccess
        // trait methods
        let stx = unsafe { stx_ui.assume_init() };

        // if `statx()` doesn't provide the mount id (before kernel 5.8),
        // let's try `name_to_handle_at()`, if everything fails just use 0
        let mnt_id = stx
            .mount_id()
            .or_else(|| get_mount_id(dir, path))
            .unwrap_or(0);

        Ok(StatExt {
            st: stx
                .stat64()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?,
            mnt_id,
        })
    } else {
        Err(io::Error::last_os_error())
    }
}

/// macOS: statx() is not available. Use fstatat() instead.
/// Mount IDs are not available on macOS, so we use st_dev as a substitute.
// TODO(macos): st_dev is not a true mount ID and may not be unique across
// bind mounts or certain filesystem configurations. This could cause issues
// with submount announcement.
#[cfg(target_os = "macos")]
pub fn statx(dir: &impl AsRawFd, path: Option<&CStr>) -> io::Result<StatExt> {
    // On macOS, stat and stat64 are the same (always 64-bit).
    let mut st_buf = unsafe { MaybeUninit::<libc::stat>::zeroed().assume_init() };

    let res = match path {
        Some(p) => unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                p.as_ptr(),
                &mut st_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        None => {
            // macOS has no AT_EMPTY_PATH, so use fstat() directly on the fd
            unsafe { libc::fstat(dir.as_raw_fd(), &mut st_buf) }
        }
    };

    // On macOS, libc::stat and libc::stat64 have the same layout
    let st: libc::stat64 = unsafe { std::mem::transmute(st_buf) };
    if res == 0 {
        // Use st_dev as a rough substitute for mount ID on macOS
        let mnt_id = st.st_dev as MountId;
        Ok(StatExt { st, mnt_id })
    } else {
        Err(io::Error::last_os_error())
    }
}
