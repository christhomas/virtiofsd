// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#[cfg(target_os = "macos")]
use crate::libc_compat as libc;

use crate::filesystem::{DirEntry, DirectoryIterator};

#[cfg(target_os = "macos")]
use std::convert::TryInto;
use std::ffi::CStr;
use std::io;
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;

use vm_memory::ByteValued;

#[cfg(target_os = "linux")]
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}
#[cfg(target_os = "linux")]
unsafe impl ByteValued for LinuxDirent64 {}

/// macOS dirent structure for getdirentries.
/// On macOS (arm64/x86_64), struct dirent has:
///   d_ino (u64, offset 0), d_seekoff (u64, offset 8), d_reclen (u16, offset 16),
///   d_namlen (u16, offset 18), d_type (u8, offset 20), then d_name[] at offset 21.
///
/// IMPORTANT: Due to #[repr(C)] alignment padding, size_of::<MacDirent>() = 24,
/// but d_name actually starts at byte 21. Use MACOS_DIRENT_NAME_OFFSET instead
/// of size_of::<MacDirent>() to find the name.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct MacDirent {
    d_ino: libc::ino_t,
    d_seekoff: u64,
    d_reclen: u16,
    d_namlen: u16,
    d_type: u8,
    // d_name follows at byte offset 21 (no padding before it)
}

/// The byte offset where d_name starts in the on-disk dirent structure.
/// This is NOT size_of::<MacDirent>() because the compiler adds 3 bytes of
/// padding after d_type (u8) to reach 8-byte alignment for the struct.
#[cfg(target_os = "macos")]
const MACOS_DIRENT_NAME_OFFSET: usize = 21;

#[cfg(target_os = "macos")]
impl Default for MacDirent {
    fn default() -> Self {
        MacDirent {
            d_ino: 0,
            d_seekoff: 0,
            d_reclen: 0,
            d_namlen: 0,
            d_type: 0,
        }
    }
}

#[cfg(target_os = "macos")]
unsafe impl ByteValued for MacDirent {}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct ReadDir<P> {
    buf: P,
    current: usize,
    end: usize,
}

#[cfg(target_os = "macos")]
pub struct ReadDir<P> {
    /// The full directory contents, read into an owned buffer.
    /// The generic `P` is kept for API compatibility but not used for storage.
    _phantom: std::marker::PhantomData<P>,
    dir_buf: Vec<u8>,
    current: usize,
    end: usize,
    /// Number of entries still to skip before we start returning results.
    /// On macOS/APFS, directory seek positions are unreliable, so we always
    /// read from the beginning and skip `offset` entries by count.
    skip_remaining: usize,
    /// 1-based entry index, used as the FUSE offset for each returned entry.
    entry_index: u64,
}

#[cfg(target_os = "macos")]
impl<P> Default for ReadDir<P> {
    fn default() -> Self {
        ReadDir {
            _phantom: std::marker::PhantomData,
            dir_buf: Vec::new(),
            current: 0,
            end: 0,
            skip_remaining: 0,
            entry_index: 0,
        }
    }
}

#[cfg(target_os = "linux")]
impl<P: DerefMut<Target = [u8]>> ReadDir<P> {
    pub fn new<D: AsRawFd>(dir: &D, offset: libc::off64_t, buf: P) -> io::Result<Self> {
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek64(dir.as_raw_fd(), offset, libc::SEEK_SET) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we used lseek() to get to the correct position
        unsafe { Self::new_no_seek(dir, buf) }
    }

    /// Continue reading from the current position in the directory without seeking.
    ///
    /// # Safety
    /// Caller must ensure the current position is valid, for example, by exclusively using this
    /// function on a given FD, potentially repeatedly.
    pub unsafe fn new_no_seek<D: AsRawFd>(dir: &D, mut buf: P) -> io::Result<Self> {
        // Safe because the kernel guarantees that it will only write to `buf` and we check the
        // return value.
        let res = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir.as_raw_fd(),
                buf.as_mut_ptr() as *mut LinuxDirent64,
                buf.len() as libc::c_int,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ReadDir {
            buf,
            current: 0,
            end: res as usize,
        })
    }
}

/// macOS: Use __getdirentries64 to read directory entries.
// TODO(macos): __getdirentries64 is a private API on macOS. A more portable
// approach would be to use fdopendir/readdir_r, but that doesn't fit the
// buffer-based API as cleanly.
#[cfg(target_os = "macos")]
extern "C" {
    fn __getdirentries64(
        fd: libc::c_int,
        buf: *mut libc::c_char,
        bufsize: libc::c_int,
        basep: *mut libc::off_t,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
impl<P: DerefMut<Target = [u8]>> ReadDir<P> {
    /// On macOS/APFS, directory seek positions are unreliable. Instead of
    /// seeking to `offset`, we always read from the beginning and treat
    /// `offset` as the number of entries to skip. Each entry is assigned a
    /// 1-based index as its FUSE offset.
    pub fn new<D: AsRawFd>(dir: &D, offset: libc::off64_t, _buf: P) -> io::Result<Self> {
        // Always rewind to the start of the directory.
        let res = unsafe { libc::lseek(dir.as_raw_fd(), 0, libc::SEEK_SET) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut rd = unsafe { Self::new_no_seek(dir, _buf)? };
        rd.skip_remaining = offset as usize;
        // entry_index starts at 0; it will be incremented as we iterate
        // (including during skips), so after skipping N entries it will be N.
        Ok(rd)
    }

    /// # Safety
    /// Caller must ensure the fd is valid.
    pub unsafe fn new_no_seek<D: AsRawFd>(dir: &D, _buf: P) -> io::Result<Self> {
        // Read the entire directory into an owned buffer. We use a growing
        // Vec because the FUSE-provided buffer may be too small for large
        // directories (e.g. node_modules with 500+ entries). We read in
        // 32KB chunks until __getdirentries64 returns 0 (end of directory).
        let mut dir_buf = Vec::with_capacity(32 * 1024);
        let chunk_size = 32 * 1024;

        loop {
            let old_len = dir_buf.len();
            dir_buf.resize(old_len + chunk_size, 0);

            let mut basep: libc::off_t = 0;
            let res = unsafe {
                __getdirentries64(
                    dir.as_raw_fd(),
                    dir_buf[old_len..].as_mut_ptr() as *mut libc::c_char,
                    chunk_size as libc::c_int,
                    &mut basep,
                )
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
            if res == 0 {
                dir_buf.truncate(old_len);
                break;
            }
            dir_buf.truncate(old_len + res as usize);
        }

        let end = dir_buf.len();
        Ok(ReadDir {
            _phantom: std::marker::PhantomData,
            dir_buf,
            current: 0,
            end,
            skip_remaining: 0,
            entry_index: 0,
        })
    }
}

#[cfg(target_os = "linux")]
impl<P> ReadDir<P> {
    /// Returns the number of bytes from the internal buffer that have not yet been consumed.
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.current)
    }
}

#[cfg(target_os = "macos")]
impl<P> ReadDir<P> {
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.current)
    }
}

#[cfg(target_os = "linux")]
impl<P: Deref<Target = [u8]>> DirectoryIterator for ReadDir<P> {
    fn next(&mut self) -> Option<DirEntry<'_>> {
        let rem = &self.buf[self.current..self.end];
        if rem.is_empty() {
            return None;
        }

        // We only use debug asserts here because these values are coming from the kernel and we
        // trust them implicitly.
        debug_assert!(
            rem.len() >= size_of::<LinuxDirent64>(),
            "not enough space left in `rem`"
        );

        let (front, back) = rem.split_at(size_of::<LinuxDirent64>());

        let dirent64 =
            LinuxDirent64::from_slice(front).expect("unable to get LinuxDirent64 from slice");

        let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
        debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

        // The kernel will pad the name with additional nul bytes until it is 8-byte aligned so
        // we need to strip those off here.
        let name = strip_padding(&back[..namelen]);
        let entry = DirEntry {
            ino: dirent64.d_ino,
            offset: dirent64.d_off as u64,
            type_: dirent64.d_ty as u32,
            name,
        };

        debug_assert!(
            rem.len() >= dirent64.d_reclen as usize,
            "rem is smaller than `d_reclen`"
        );
        self.current += dirent64.d_reclen as usize;

        Some(entry)
    }
}

#[cfg(target_os = "macos")]
impl<P: Deref<Target = [u8]>> DirectoryIterator for ReadDir<P> {
    fn next(&mut self) -> Option<DirEntry<'_>> {
        loop {
            let rem = &self.dir_buf[self.current..self.end];
            if rem.is_empty() || rem.len() < MACOS_DIRENT_NAME_OFFSET {
                return None;
            }

            // Parse the fixed-size fields manually from the byte buffer to
            // avoid alignment issues.
            let d_ino = u64::from_ne_bytes(rem[0..8].try_into().unwrap());
            // d_seekoff at [8..16] — not used (unreliable on APFS)
            let d_reclen = u16::from_ne_bytes(rem[16..18].try_into().unwrap());
            let d_namlen = u16::from_ne_bytes(rem[18..20].try_into().unwrap()) as usize;
            let d_type = rem[20];

            if d_reclen == 0 || d_reclen as usize > rem.len() {
                return None;
            }

            self.current += d_reclen as usize;
            self.entry_index += 1;

            // Skip entries that the guest has already seen.
            if self.skip_remaining > 0 {
                self.skip_remaining -= 1;
                continue;
            }

            let name_start = MACOS_DIRENT_NAME_OFFSET;
            let name_end = name_start + d_namlen;
            if name_end > rem.len() {
                return None;
            }

            let name = if name_end < rem.len() && rem[name_end] == 0 {
                unsafe { CStr::from_bytes_with_nul_unchecked(&rem[name_start..=name_end]) }
            } else {
                strip_padding(&rem[name_start..name_end])
            };

            return Some(DirEntry {
                ino: d_ino,
                offset: self.entry_index,
                type_: d_type as u32,
                name,
            });
        }
    }
}

// Like `CStr::from_bytes_with_nul` but strips any bytes after the first '\0'-byte. Panics if `b`
// doesn't contain any '\0' bytes.
fn strip_padding(b: &[u8]) -> &CStr {
    // It would be nice if we could use memchr here but that's locked behind an unstable gate.
    let pos = b
        .iter()
        .position(|&c| c == 0)
        .expect("`b` doesn't contain any nul bytes");

    // Safe because we are creating this string with the first nul-byte we found so we can
    // guarantee that it is nul-terminated and doesn't contain any interior nuls.
    unsafe { CStr::from_bytes_with_nul_unchecked(&b[..=pos]) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn padded_cstrings() {
        assert_eq!(strip_padding(b".\0\0\0\0\0\0\0").to_bytes(), b".");
        assert_eq!(strip_padding(b"..\0\0\0\0\0\0").to_bytes(), b"..");
        assert_eq!(
            strip_padding(b"normal cstring\0").to_bytes(),
            b"normal cstring"
        );
        assert_eq!(strip_padding(b"\0\0\0\0").to_bytes(), b"");
        assert_eq!(
            strip_padding(b"interior\0nul bytes\0\0\0").to_bytes(),
            b"interior"
        );
    }

    #[test]
    #[should_panic(expected = "`b` doesn't contain any nul bytes")]
    fn no_nul_byte() {
        strip_padding(b"no nul bytes in string");
    }
}
