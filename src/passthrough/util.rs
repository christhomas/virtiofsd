// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

use crate::util::{other_io_error, ErrorContext, ResultErrorContext};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{fmt, io};

/// Translate Linux open(2) flags to macOS open(2) flags.
///
/// The FUSE protocol sends open flags using Linux numeric values. On macOS,
/// some flags have different numeric values, so we must translate before
/// passing them to the macOS kernel.
#[cfg(target_os = "macos")]
pub fn translate_linux_open_flags(linux_flags: i32) -> i32 {
    // Linux flag constants (from <asm-generic/fcntl.h> / <bits/fcntl-linux.h>)
    const LINUX_O_RDONLY: i32 = 0o0;
    const LINUX_O_WRONLY: i32 = 0o1;
    const LINUX_O_RDWR: i32 = 0o2;
    const LINUX_O_ACCMODE: i32 = 0o3;
    const LINUX_O_CREAT: i32 = 0o100;
    const LINUX_O_EXCL: i32 = 0o200;
    const LINUX_O_NOCTTY: i32 = 0o400;
    const LINUX_O_TRUNC: i32 = 0o1000;
    const LINUX_O_APPEND: i32 = 0o2000;
    const LINUX_O_NONBLOCK: i32 = 0o4000;
    const LINUX_O_DSYNC: i32 = 0o10000;
    const LINUX_O_DIRECTORY: i32 = 0o200000;
    const LINUX_O_NOFOLLOW: i32 = 0o400000;
    const LINUX_O_CLOEXEC: i32 = 0o2000000;
    const LINUX_O_SYNC: i32 = 0o4010000;

    let mut mac_flags: i32 = 0;

    // Access mode (low 2 bits are the same on both platforms)
    mac_flags |= match linux_flags & LINUX_O_ACCMODE {
        LINUX_O_RDONLY => libc::O_RDONLY,
        LINUX_O_WRONLY => libc::O_WRONLY,
        LINUX_O_RDWR => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };

    // Map individual flags
    if linux_flags & LINUX_O_CREAT != 0 {
        mac_flags |= libc::O_CREAT;
    }
    if linux_flags & LINUX_O_EXCL != 0 {
        mac_flags |= libc::O_EXCL;
    }
    if linux_flags & LINUX_O_NOCTTY != 0 {
        mac_flags |= libc::O_NOCTTY;
    }
    if linux_flags & LINUX_O_TRUNC != 0 {
        mac_flags |= libc::O_TRUNC;
    }
    if linux_flags & LINUX_O_APPEND != 0 {
        mac_flags |= libc::O_APPEND;
    }
    if linux_flags & LINUX_O_NONBLOCK != 0 {
        mac_flags |= libc::O_NONBLOCK;
    }
    if linux_flags & LINUX_O_DIRECTORY != 0 {
        mac_flags |= libc::O_DIRECTORY;
    }
    if linux_flags & LINUX_O_NOFOLLOW != 0 {
        mac_flags |= libc::O_NOFOLLOW;
    }
    if linux_flags & LINUX_O_CLOEXEC != 0 {
        mac_flags |= libc::O_CLOEXEC;
    }
    if linux_flags & LINUX_O_SYNC != 0 {
        mac_flags |= libc::O_SYNC;
    }
    if linux_flags & LINUX_O_DSYNC != 0 {
        mac_flags |= libc::O_DSYNC;
    }
    // O_DIRECT: macOS has no direct equivalent, silently drop it
    // O_NOATIME: macOS has no equivalent, silently drop it
    // O_LARGEFILE: not meaningful on macOS (always 64-bit), drop it

    mac_flags
}

/// On Linux, flags are already native — pass through unchanged.
#[cfg(target_os = "linux")]
#[inline]
pub fn translate_linux_open_flags(linux_flags: i32) -> i32 {
    linux_flags
}

/// FUSE wire `whence` values for `lseek` (Linux numbering).
///
/// The FUSE protocol always uses Linux's numeric values, regardless of the
/// host platform. macOS and Linux agree on `SEEK_SET`/`SEEK_CUR`/`SEEK_END`
/// (0/1/2) but the values for `SEEK_DATA` and `SEEK_HOLE` are swapped:
///
/// |               | Linux | macOS |
/// |---------------|-------|-------|
/// | `SEEK_DATA`   | 3     | 4     |
/// | `SEEK_HOLE`   | 4     | 3     |
///
/// Passing the FUSE-wire value straight to `libc::lseek(2)` on macOS makes
/// the kernel interpret "find next data" as "find next hole" and vice versa,
/// which causes consumers like `qemu-img convert` and `cp --sparse=auto` to
/// see real files as one big hole and copy zeros.
pub const LINUX_SEEK_SET: i32 = 0;
pub const LINUX_SEEK_CUR: i32 = 1;
pub const LINUX_SEEK_END: i32 = 2;
pub const LINUX_SEEK_DATA: i32 = 3;
pub const LINUX_SEEK_HOLE: i32 = 4;

/// Translate a FUSE-wire `whence` value (Linux numbering) to the native
/// `whence` value for `libc::lseek(2)` on the host.
#[cfg(target_os = "macos")]
pub fn translate_linux_seek_whence(linux_whence: i32) -> io::Result<i32> {
    match linux_whence {
        LINUX_SEEK_SET => Ok(libc::SEEK_SET),
        LINUX_SEEK_CUR => Ok(libc::SEEK_CUR),
        LINUX_SEEK_END => Ok(libc::SEEK_END),
        LINUX_SEEK_DATA => Ok(libc::SEEK_DATA),
        LINUX_SEEK_HOLE => Ok(libc::SEEK_HOLE),
        _ => Err(einval()),
    }
}

/// On Linux the FUSE-wire value is already native.
#[cfg(target_os = "linux")]
#[inline]
pub fn translate_linux_seek_whence(linux_whence: i32) -> io::Result<i32> {
    Ok(linux_whence)
}

/// Best-effort emulation of Linux `fallocate(fd, mode=0, offset, length)`
/// on macOS.
///
/// Linux semantics for mode 0:
///   * Allocate disk blocks for `[offset, offset+length)`.
///   * Grow the file to at least `offset + length` bytes if smaller.
///   * Subsequent writes in that range are guaranteed not to ENOSPC.
///   * If the file is already at least `offset + length` bytes, leave
///     the size alone.
///
/// macOS has no exact equivalent. We approximate as follows:
///
///   1. Reject every mode but 0 with `EOPNOTSUPP`. Sparse-aware tools
///      (qemu-img, cp) probe with `FALLOC_FL_PUNCH_HOLE` etc.; failing
///      cleanly lets them fall back to writes.
///   2. If `target_size <= current_size`, do nothing and return Ok(()).
///   3. Otherwise, try `fcntl(F_PREALLOCATE)` for the bytes past EOF —
///      contiguous first, non-contiguous on fallback. **Ignore failure**:
///      F_PREALLOCATE is fundamentally best-effort on Apple filesystems
///      and many code paths reject it (network mounts, sparse files,
///      certain APFS configurations). Hard-failing here would convert
///      a transient performance hint into a fatal error, which is
///      strictly worse than just letting the eventual write allocate.
///   4. `ftruncate` to the target size. This is the part that gives
///      callers the size guarantee they actually rely on.
///
/// **Why this exists in a helper rather than inline:** the original
/// implementation called `fcntl(F_PREALLOCATE)` with `F_PEOFPOSMODE`
/// and a non-zero `fst_offset`. Apple's API requires `fst_offset == 0`
/// when using `F_PEOFPOSMODE` — the field means "bytes past EOF", not
/// "absolute offset" — so any FUSE fallocate with a non-zero offset
/// failed with EINVAL. That EINVAL surfaced from the guest as
/// `qemu-img: error while writing at byte 0: Invalid argument` and
/// killed every disk-image conversion onto a virtio-fs share.
/// Putting the emulation in its own function lets the unit tests
/// exercise the real syscall sequence on macOS hosts.
#[cfg(target_os = "macos")]
pub fn macos_emulate_fallocate(
    fd: libc::c_int,
    mode: u32,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if mode != 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let current_size = st.st_size as u64;
    let target_size = offset.saturating_add(length);

    if target_size <= current_size {
        return Ok(());
    }

    let bytes_past_eof = target_size - current_size;
    let mut fstore = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG as libc::c_uint,
        fst_posmode: libc::F_PEOFPOSMODE as libc::c_int,
        fst_offset: 0,
        fst_length: bytes_past_eof as libc::off_t,
        fst_bytesalloc: 0,
    };
    let mut res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fstore) };
    if res == -1 {
        fstore.fst_flags = libc::F_ALLOCATEALL as libc::c_uint;
        res = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut fstore) };
    }
    let _ = res; // intentionally ignored — see doc comment

    let res = unsafe { libc::ftruncate(fd, target_size as libc::off_t) };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Safe wrapper around libc::openat().
pub fn openat(dir_fd: &impl AsRawFd, path: &str, flags: libc::c_int) -> io::Result<File> {
    let path_cstr =
        CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Safe because:
    // - CString::new() has returned success and thus guarantees `path_cstr` is a valid
    //   NUL-terminated string
    // - this does not modify any memory
    // - we check the return value
    // We do not check `flags` because if the kernel cannot handle poorly specified flags then we
    // have much bigger problems.
    let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), path_cstr.as_ptr(), flags) };
    if fd >= 0 {
        // Safe because we just opened this fd
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Same as `openat()`, but produces more verbose errors.
///
/// Do not use this for operations where the error is returned to the guest, as the raw OS error
/// value will be clobbered.
pub fn openat_verbose(dir_fd: &impl AsRawFd, path: &str, flags: libc::c_int) -> io::Result<File> {
    openat(dir_fd, path, flags).err_context(|| path)
}

/// Open `/proc/self/fd/{fd}` with the given flags to effectively duplicate the given `fd` with new
/// flags (e.g. to turn an `O_PATH` file descriptor into one that can be used for I/O).
#[cfg(target_os = "linux")]
pub fn reopen_fd_through_proc(
    fd: &impl AsRawFd,
    flags: libc::c_int,
    proc_self_fd: &File,
) -> io::Result<File> {
    // Clear the `O_NOFOLLOW` flag if it is set since we need to follow the `/proc/self/fd` symlink
    // to get the file.
    openat(
        proc_self_fd,
        format!("{}", fd.as_raw_fd()).as_str(),
        flags & !libc::O_NOFOLLOW,
    )
}

/// macOS: /proc/self/fd does not exist. Use fcntl(F_GETPATH) to get the path,
/// then reopen it with the requested flags.
// TODO(macos): This approach has a TOCTOU race: the path could change between
// F_GETPATH and the subsequent open(). Also, F_GETPATH may fail for certain
// fd types (e.g. pipes, sockets).
#[cfg(target_os = "macos")]
pub fn reopen_fd_through_proc(
    fd: &impl AsRawFd,
    flags: libc::c_int,
    _proc_self_fd: &File,
) -> io::Result<File> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if ret == -1 {
        let err = io::Error::last_os_error();
        log::debug!(
            "reopen_fd_through_proc: F_GETPATH failed for fd {}: {}",
            fd.as_raw_fd(),
            err
        );
        return Err(err);
    }
    let path = CStr::from_bytes_until_nul(&buf)
        .map_err(|_| other_io_error("F_GETPATH returned invalid path"))?;
    log::debug!(
        "reopen_fd_through_proc: fd {} -> path {:?}, flags=0x{:x}",
        fd.as_raw_fd(),
        path,
        flags & !libc::O_NOFOLLOW
    );
    let new_fd = unsafe { libc::open(path.as_ptr(), flags & !libc::O_NOFOLLOW) };
    if new_fd < 0 {
        let err = io::Error::last_os_error();
        log::debug!("reopen_fd_through_proc: open failed: {}", err);
        Err(err)
    } else {
        Ok(unsafe { File::from_raw_fd(new_fd) })
    }
}

/// Returns true if it's safe to open this inode without O_PATH.
pub fn is_safe_inode(mode: u32) -> bool {
    // Only regular files and directories are considered safe to be opened from the file
    // server without O_PATH.
    matches!(mode & libc::S_IFMT as u32, m if m == libc::S_IFREG as u32 || m == libc::S_IFDIR as u32)
}

pub fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

pub fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

pub fn erofs() -> io::Error {
    io::Error::from_raw_os_error(libc::EROFS)
}

/**
 * Errors that `get_path_by_fd()` can encounter.
 *
 * This specialized error type exists so that
 * [`crate::passthrough::device_state::preserialization::proc_paths`] can decide which errors it
 * considers recoverable.
 */
#[derive(Debug)]
pub(crate) enum FdPathError {
    /// `readlinkat()` failed with the contained error.
    ReadLink(io::Error),

    /// Link name is too long. Only produced on Linux (via `/proc/self/fd`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    TooLong,

    /// Link name is not a valid C string.
    InvalidCString(io::Error),

    /// Returned path (contained string) is not a plain file path.
    NotAFile(String),

    /// Returned path (contained string) is reported to be deleted, i.e. no longer valid.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Deleted(String),
}

/// Looks up an FD's path through /proc/self/fd
#[cfg(target_os = "linux")]
pub(crate) fn get_path_by_fd(
    fd: &impl AsRawFd,
    proc_self_fd: &impl AsRawFd,
) -> Result<CString, FdPathError> {
    let fname = format!("{}\0", fd.as_raw_fd());
    let fname_cstr = CStr::from_bytes_with_nul(fname.as_bytes()).unwrap();

    let max_len = libc::PATH_MAX as usize; // does not include final NUL byte
    let mut link_target = vec![0u8; max_len + 1]; // make space for NUL byte

    let ret = unsafe {
        libc::readlinkat(
            proc_self_fd.as_raw_fd(),
            fname_cstr.as_ptr(),
            link_target.as_mut_ptr().cast::<libc::c_char>(),
            max_len,
        )
    };
    if ret < 0 {
        return Err(FdPathError::ReadLink(io::Error::last_os_error()));
    } else if ret as usize == max_len {
        return Err(FdPathError::TooLong);
    }

    link_target.truncate(ret as usize + 1);
    let link_target_cstring = CString::from_vec_with_nul(link_target)
        .map_err(|err| FdPathError::InvalidCString(other_io_error(err)))?;
    let link_target_str = link_target_cstring.to_string_lossy();

    let pre_slash = link_target_str.split('/').next().unwrap();
    if pre_slash.contains(':') {
        return Err(FdPathError::NotAFile(link_target_str.into_owned()));
    }

    if let Some(path) = link_target_str.strip_suffix(" (deleted)") {
        return Err(FdPathError::Deleted(path.to_owned()));
    }

    Ok(link_target_cstring)
}

/// macOS: /proc/self/fd does not exist. Use fcntl(F_GETPATH) to resolve the path.
#[cfg(target_os = "macos")]
pub(crate) fn get_path_by_fd(
    fd: &impl AsRawFd,
    _proc_self_fd: &impl AsRawFd,
) -> Result<CString, FdPathError> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if ret == -1 {
        return Err(FdPathError::ReadLink(io::Error::last_os_error()));
    }

    // Find the NUL terminator
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if nul_pos == 0 {
        return Err(FdPathError::ReadLink(other_io_error(
            "F_GETPATH returned empty path",
        )));
    }
    buf.truncate(nul_pos + 1); // include the NUL byte

    let path_cstring = CString::from_vec_with_nul(buf)
        .map_err(|err| FdPathError::InvalidCString(other_io_error(err)))?;
    let path_str = path_cstring.to_string_lossy();

    let pre_slash = path_str.split('/').next().unwrap();
    if pre_slash.contains(':') {
        return Err(FdPathError::NotAFile(path_str.into_owned()));
    }

    Ok(path_cstring)
}

impl From<FdPathError> for io::Error {
    fn from(err: FdPathError) -> Self {
        match err {
            FdPathError::ReadLink(err) => err.context("readlink"),
            FdPathError::TooLong => other_io_error("Path returned from readlink is too long"),
            FdPathError::InvalidCString(err) => err.context("readlink returned invalid path"),
            FdPathError::NotAFile(path) => other_io_error(format!("Not a file ({path})")),
            FdPathError::Deleted(path) => other_io_error(format!("Inode deleted ({path})")),
        }
    }
}

impl fmt::Display for FdPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FdPathError::ReadLink(err) => write!(f, "readlink: {err}"),
            FdPathError::TooLong => write!(f, "Path returned from readlink is too long"),
            FdPathError::InvalidCString(err) => write!(f, "readlink returned invalid path: {err}"),
            FdPathError::NotAFile(path) => write!(f, "Not a file ({path})"),
            FdPathError::Deleted(path) => write!(f, "Inode deleted ({path})"),
        }
    }
}

impl std::error::Error for FdPathError {}

/// Debugging helper function: Turn the given file descriptor into a string representation we can
/// show the user.  If `proc_self_fd` is given, try to obtain the actual path through the symlink
/// in /proc/self/fd; otherwise (or on error), just print the integer representation (as
/// "{fd:%i}").
pub fn printable_fd(fd: &impl AsRawFd, proc_self_fd: Option<&impl AsRawFd>) -> String {
    if let Some(Ok(path)) = proc_self_fd.map(|psf| get_path_by_fd(fd, psf)) {
        match path.into_string() {
            Ok(s) => s,
            Err(err) => err.into_cstring().to_string_lossy().into_owned(),
        }
    } else {
        format!("{{fd:{}}}", fd.as_raw_fd())
    }
}

pub fn relative_path<'a>(path: &'a CStr, prefix: &CStr) -> io::Result<&'a CStr> {
    let mut relative_path = path
        .to_bytes_with_nul()
        .strip_prefix(prefix.to_bytes())
        .ok_or_else(|| {
            other_io_error(format!(
                "Path {path:?} is outside the directory ({prefix:?})"
            ))
        })?;

    // Remove leading / if left
    while let Some(prefixless) = relative_path.strip_prefix(b"/") {
        relative_path = prefixless;
    }

    // Must succeed: Was a `CStr` before, converted to `&[u8]` via `to_bytes_with_nul()`, so must
    // still contain exactly one NUL byte at the end of the slice
    Ok(CStr::from_bytes_with_nul(relative_path).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seek_whence_constants_match_linux_abi() {
        // FUSE wire values are fixed by the Linux kernel ABI. If these
        // constants ever drift, every guest's lseek will silently break.
        assert_eq!(LINUX_SEEK_SET, 0);
        assert_eq!(LINUX_SEEK_CUR, 1);
        assert_eq!(LINUX_SEEK_END, 2);
        assert_eq!(LINUX_SEEK_DATA, 3);
        assert_eq!(LINUX_SEEK_HOLE, 4);
    }

    #[test]
    fn translate_linux_seek_whence_basic_modes() {
        // 0/1/2 are identical on Linux and macOS, so they round-trip on both
        // platforms without surprises.
        assert_eq!(
            translate_linux_seek_whence(LINUX_SEEK_SET).unwrap(),
            libc::SEEK_SET
        );
        assert_eq!(
            translate_linux_seek_whence(LINUX_SEEK_CUR).unwrap(),
            libc::SEEK_CUR
        );
        assert_eq!(
            translate_linux_seek_whence(LINUX_SEEK_END).unwrap(),
            libc::SEEK_END
        );
    }

    #[test]
    fn translate_linux_seek_whence_data_and_hole() {
        // The whole point of the helper: SEEK_DATA/SEEK_HOLE must come out
        // as the host's native libc value, not the wire value. On macOS
        // these are swapped (Linux 3/4 vs macOS 4/3); on Linux it's a
        // pass-through. Either way, the wire value `LINUX_SEEK_DATA` must
        // map to `libc::SEEK_DATA` and `LINUX_SEEK_HOLE` to `libc::SEEK_HOLE`.
        assert_eq!(
            translate_linux_seek_whence(LINUX_SEEK_DATA).unwrap(),
            libc::SEEK_DATA
        );
        assert_eq!(
            translate_linux_seek_whence(LINUX_SEEK_HOLE).unwrap(),
            libc::SEEK_HOLE
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn translate_linux_seek_whence_actually_swaps_on_macos() {
        // Belt-and-braces: explicitly assert the numeric swap that was the
        // original bug. If this ever fails, either macOS changed its ABI
        // (extraordinarily unlikely) or someone "simplified" the translator
        // to a pass-through. Both outcomes silently corrupt qemu-img output.
        assert_eq!(libc::SEEK_HOLE, 3);
        assert_eq!(libc::SEEK_DATA, 4);
        assert_eq!(translate_linux_seek_whence(LINUX_SEEK_DATA).unwrap(), 4);
        assert_eq!(translate_linux_seek_whence(LINUX_SEEK_HOLE).unwrap(), 3);
    }

    #[test]
    fn translate_linux_seek_whence_rejects_unknown() {
        // macOS must reject values it cannot map; Linux passes the value
        // straight through and lets lseek(2) reject it at the syscall.
        #[cfg(target_os = "macos")]
        {
            let err = translate_linux_seek_whence(99).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(translate_linux_seek_whence(99).unwrap(), 99);
        }
    }

    /// macOS-only fallocate emulation tests. They exercise the real
    /// syscall sequence against a tmpfile, not a mock — anything else
    /// would have missed the `F_PEOFPOSMODE` / `fst_offset` interaction
    /// that broke production. Linux uses native fallocate so these are
    /// macOS-gated.
    #[cfg(target_os = "macos")]
    mod fallocate {
        use super::*;
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        fn tempfile_with(bytes: &[u8]) -> std::fs::File {
            let mut f = tempfile::tempfile().expect("tempfile");
            if !bytes.is_empty() {
                f.write_all(bytes).unwrap();
                f.flush().unwrap();
            }
            f
        }

        fn size_of(f: &std::fs::File) -> u64 {
            f.metadata().unwrap().len()
        }

        #[test]
        fn fallocate_grows_empty_file() {
            // Regression: original implementation passed FUSE offset=0 with
            // F_PEOFPOSMODE which actually worked, but the `ftruncate(offset+length)`
            // call relied on F_PREALLOCATE not failing first. The new code
            // skips straight to ftruncate via the helper.
            let f = tempfile_with(&[]);
            macos_emulate_fallocate(f.as_raw_fd(), 0, 0, 1024).unwrap();
            assert_eq!(size_of(&f), 1024);
        }

        #[test]
        fn fallocate_grows_at_nonzero_offset() {
            // The real bug: a non-zero offset combined with F_PEOFPOSMODE
            // returns EINVAL on Darwin, because F_PEOFPOSMODE requires
            // `fst_offset == 0`. qemu-img convert hits this path because
            // it allocates ranges past the qcow2 header. If this test fails,
            // every disk-image conversion onto virtio-fs will abort with
            // "error while writing at byte 0: Invalid argument".
            let f = tempfile_with(&[]);
            macos_emulate_fallocate(f.as_raw_fd(), 0, 4096, 8192).unwrap();
            assert_eq!(size_of(&f), 4096 + 8192);
        }

        #[test]
        fn fallocate_does_not_shrink_when_target_smaller() {
            // Linux fallocate(mode=0) explicitly leaves the file size
            // alone when offset+length <= current size. A naive
            // `ftruncate(offset+length)` would shrink the file and
            // throw away data. This test pins that we don't.
            let f = tempfile_with(&[0xAB; 10_000]);
            assert_eq!(size_of(&f), 10_000);
            macos_emulate_fallocate(f.as_raw_fd(), 0, 0, 4096).unwrap();
            assert_eq!(size_of(&f), 10_000);
        }

        #[test]
        fn fallocate_extends_only_to_target() {
            // Edge case: target size partially overlaps existing file.
            // Existing 2000 bytes + offset 1500 + length 1000 = target 2500.
            // We must extend to 2500, not truncate to 1500 and re-extend.
            let f = tempfile_with(&[0xAB; 2000]);
            macos_emulate_fallocate(f.as_raw_fd(), 0, 1500, 1000).unwrap();
            assert_eq!(size_of(&f), 2500);
        }

        #[test]
        fn fallocate_rejects_nonzero_mode_with_eopnotsupp() {
            // FUSE clients probe with FALLOC_FL_PUNCH_HOLE / KEEP_SIZE /
            // ZERO_RANGE. We don't implement them; returning EOPNOTSUPP
            // is the contract that lets the guest fall back to writes.
            // The errno_to_linux table separately verifies that
            // EOPNOTSUPP=102 maps to Linux 95 (not 102=ENETRESET).
            let f = tempfile_with(&[]);
            for mode in [1u32, 2, 3, 8, 16] {
                let err = macos_emulate_fallocate(f.as_raw_fd(), mode, 0, 1024).unwrap_err();
                assert_eq!(
                    err.raw_os_error(),
                    Some(libc::EOPNOTSUPP),
                    "mode {mode} must reject with EOPNOTSUPP"
                );
            }
        }

        #[test]
        fn fallocate_zero_length_is_noop() {
            let f = tempfile_with(&[0xAB; 100]);
            macos_emulate_fallocate(f.as_raw_fd(), 0, 0, 0).unwrap();
            assert_eq!(size_of(&f), 100);
        }
    }

    /// macOS-only: pin the syscall contract this port depends on for symlink
    /// lookups. On Darwin, `openat(dirfd, name, O_RDONLY|O_NOFOLLOW)` returns
    /// `ELOOP` for any symlink leaf — not just chained or dangling ones, but
    /// every symlink. That is why every guest FUSE `LOOKUP` of a symlink (the
    /// `pnpm` `.pnpm` layout, `rm` of a dangling link, `ls -la` of a symlink)
    /// was failing with "Too many levels of symbolic links" through this
    /// port. `O_SYMLINK` is Darwin's equivalent of Linux's `O_PATH | O_NOFOLLOW`.
    /// If either of these contracts ever drifts, the symlink fix in
    /// `open_relative_to`/`readlink` will silently break — these tests pin
    /// both the bug and the fix.
    #[cfg(target_os = "macos")]
    mod macos_symlink_open {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;
        use std::path::Path;

        struct TestTree {
            dir: tempfile::TempDir,
        }

        impl TestTree {
            fn new() -> Self {
                let dir = tempfile::tempdir().expect("tempdir");
                let root = dir.path();
                std::fs::write(root.join("real.txt"), b"hello").unwrap();
                // chain: link3 -> link2 -> link1 -> link_to_real -> real.txt
                std::os::unix::fs::symlink("real.txt", root.join("link_to_real")).unwrap();
                std::os::unix::fs::symlink("link_to_real", root.join("link1")).unwrap();
                std::os::unix::fs::symlink("link1", root.join("link2")).unwrap();
                std::os::unix::fs::symlink("link2", root.join("link3")).unwrap();
                // dangling: target doesn't exist
                std::os::unix::fs::symlink("no_such_target_anywhere", root.join("link_dangling"))
                    .unwrap();
                Self { dir }
            }

            fn open_dirfd(&self) -> std::fs::File {
                use std::os::fd::FromRawFd;
                let cpath = CString::new(self.dir.path().as_os_str().as_encoded_bytes()).unwrap();
                let fd = unsafe {
                    libc::open(
                        cpath.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                assert!(fd >= 0, "open dir: {}", std::io::Error::last_os_error());
                unsafe { std::fs::File::from_raw_fd(fd) }
            }

            fn path(&self) -> &Path {
                self.dir.path()
            }
        }

        fn openat_with(dirfd: i32, name: &str, flags: i32) -> std::io::Result<i32> {
            let cname = CString::new(name).unwrap();
            let fd = unsafe { libc::openat(dirfd, cname.as_ptr(), flags, 0) };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(fd)
            }
        }

        #[test]
        fn nofollow_on_symlink_errors_with_eloop_pre_fix() {
            // Documents the Darwin behavior the fix exists to work around.
            // `openat(..., O_RDONLY | O_NOFOLLOW)` is what the pre-fix code
            // path did on macOS (`O_PATH_OR_RDONLY = O_RDONLY` + `O_NOFOLLOW`
            // added in `open_relative_to`). Any symlink — chained, dangling,
            // or pointing to a real file — failed with `ELOOP`. If this test
            // ever stops returning `ELOOP`, Apple has changed the behavior
            // and the workaround can be revisited.
            let tree = TestTree::new();
            let dir = tree.open_dirfd();
            for name in &["link_to_real", "link1", "link3", "link_dangling"] {
                let err = match openat_with(
                    dir.as_raw_fd(),
                    name,
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                ) {
                    Ok(fd) => {
                        unsafe { libc::close(fd) };
                        panic!("{} should fail with ELOOP under O_NOFOLLOW", name);
                    }
                    Err(e) => e,
                };
                assert_eq!(
                    err.raw_os_error(),
                    Some(libc::ELOOP),
                    "{name}: expected ELOOP, got {err}"
                );
            }
        }

        #[test]
        fn o_symlink_opens_symlink_itself() {
            // The fix: `O_SYMLINK` (Darwin) substitutes for Linux's
            // `O_PATH | O_NOFOLLOW`. Opening any symlink succeeds and the
            // resulting fd refers to the symlink itself — `fstat` reports
            // `S_IFLNK`. Verifies the substitution in `open_relative_to`
            // produces a usable inode reference for symlinks (which is what
            // `do_lookup` needs to stat them and return a `FUSE` `LOOKUP`
            // reply).
            let tree = TestTree::new();
            let dir = tree.open_dirfd();
            for name in &["link_to_real", "link1", "link3", "link_dangling"] {
                let fd = openat_with(
                    dir.as_raw_fd(),
                    name,
                    libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
                )
                .unwrap_or_else(|e| panic!("{} O_SYMLINK open failed: {}", name, e));
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let r = unsafe { libc::fstat(fd, &mut st) };
                assert_eq!(r, 0, "fstat {name}: {}", std::io::Error::last_os_error());
                assert_eq!(
                    st.st_mode as u32 & libc::S_IFMT as u32,
                    libc::S_IFLNK as u32,
                    "{name}: O_SYMLINK fd should report S_IFLNK"
                );
                unsafe { libc::close(fd) };
            }
        }

        #[test]
        fn o_symlink_is_noop_for_regular_files_and_dirs() {
            // `O_SYMLINK` must not change behavior for non-symlink leaves —
            // otherwise the substitution in `open_relative_to` would break
            // every non-symlink lookup. `O_SYMLINK` on a regular file opens
            // for read normally; on a directory opens the directory.
            let tree = TestTree::new();
            let dir = tree.open_dirfd();
            let fd = openat_with(
                dir.as_raw_fd(),
                "real.txt",
                libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
            )
            .expect("regular file open should succeed");
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
            assert_eq!(
                st.st_mode as u32 & libc::S_IFMT as u32,
                libc::S_IFREG as u32
            );
            unsafe { libc::close(fd) };

            let fd = openat_with(
                dir.as_raw_fd(),
                ".",
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_SYMLINK | libc::O_CLOEXEC,
            )
            .expect("directory open should succeed");
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
            assert_eq!(
                st.st_mode as u32 & libc::S_IFMT as u32,
                libc::S_IFDIR as u32
            );
            unsafe { libc::close(fd) };
        }

        #[test]
        fn readlink_works_via_fgetpath_on_o_symlink_fd() {
            // `readlinkat(fd, "", buf, n)` returns `ENOENT` on Darwin because
            // there is no `AT_EMPTY_PATH`. The fix in `mod.rs::readlink`
            // resolves the symlink fd's path via `F_GETPATH` and then calls
            // `readlink(path, ...)`. Both pieces must work: pin them here so
            // `readlink()` over FUSE doesn't silently return `ENOENT`.
            let tree = TestTree::new();
            let dir = tree.open_dirfd();
            for (name, expected) in &[
                ("link_to_real", "real.txt"),
                ("link1", "link_to_real"),
                ("link3", "link2"),
                ("link_dangling", "no_such_target_anywhere"),
            ] {
                let fd = openat_with(
                    dir.as_raw_fd(),
                    name,
                    libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC,
                )
                .expect("O_SYMLINK open");

                // Confirm the empty-path readlinkat does NOT work on Darwin
                // — this is the contract reason we need the F_GETPATH path.
                let mut sink = [0u8; 256];
                let r = unsafe {
                    libc::readlinkat(
                        fd,
                        b"\0".as_ptr() as *const libc::c_char,
                        sink.as_mut_ptr() as *mut libc::c_char,
                        sink.len(),
                    )
                };
                assert!(
                    r < 0,
                    "{}: readlinkat(fd, \"\") unexpectedly succeeded on Darwin",
                    name
                );

                // F_GETPATH → readlink(path) path that the fix uses.
                let mut pbuf = vec![0u8; libc::PATH_MAX as usize];
                let r = unsafe { libc::fcntl(fd, libc::F_GETPATH, pbuf.as_mut_ptr()) };
                assert_eq!(r, 0, "F_GETPATH for {name}");

                let mut tbuf = vec![0u8; libc::PATH_MAX as usize];
                let n = unsafe {
                    libc::readlink(
                        pbuf.as_ptr() as *const libc::c_char,
                        tbuf.as_mut_ptr() as *mut libc::c_char,
                        tbuf.len(),
                    )
                };
                assert!(
                    n > 0,
                    "readlink for {name}: {}",
                    std::io::Error::last_os_error()
                );
                let target = std::str::from_utf8(&tbuf[..n as usize]).unwrap();
                assert_eq!(target, *expected, "{name} target");

                // Sanity check: F_GETPATH on an O_SYMLINK fd should still
                // resolve to a path that lives under the tree.
                let path_nul = pbuf.iter().position(|&b| b == 0).unwrap_or(pbuf.len());
                let path = std::str::from_utf8(&pbuf[..path_nul]).unwrap();
                let root = std::fs::canonicalize(tree.path()).unwrap();
                let root_str = root.to_str().unwrap();
                assert!(
                    path.starts_with(root_str),
                    "{}: F_GETPATH path {:?} not under tree {:?}",
                    name,
                    path,
                    root_str
                );

                unsafe { libc::close(fd) };
            }
        }
    }
}
