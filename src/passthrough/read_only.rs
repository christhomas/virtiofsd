// Copyright 2024 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a read-only variant of [`PassthroughFs`].
//!
//! Implements a wrapper around [`PassthroughFs`] ([`PassthroughFsRo`]) that prohibits all
//! operations that would modify anything within the shared directory.  This wrapper implements the
//! [`FileSystem`] and [`SerializableFileSystem`] traits, so can be used as a virtiofsd filesystem
//! driver.

#[cfg(target_os = "macos")]
use crate::libc_compat as libc;

use super::util::{einval, erofs};
use super::PassthroughFs;
use crate::filesystem::{
    Context, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply, OpenOptions,
    SerializableFileSystem, SetattrValid, SetxattrFlags, ZeroCopyReader, ZeroCopyWriter,
};
use crate::fuse;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// Wrapper around `PassthroughFs`, prohibiting modifications.
///
/// Prevent any operation that would modify the underlying filesystem.
pub struct PassthroughFsRo(PassthroughFs);

impl PassthroughFsRo {
    /// Create a `PassthroughFsRo` filesystem.
    ///
    /// Internally creates a `PassthroughFs` filesystem using the `cfg` configuration, then wraps
    /// it in the `PassthroughFsRo` type.
    pub fn new(cfg: super::Config) -> io::Result<Self> {
        let inner = PassthroughFs::new(cfg)?;
        Ok(PassthroughFsRo(inner))
    }

    /// Forward to the inner filesystem so callers can opt-in to push-based
    /// cache invalidation even on read-only mounts (the host can still
    /// modify the underlying tree out-of-band).
    pub fn enable_dentry_index(
        &mut self,
    ) -> std::sync::Arc<crate::passthrough::dentry_index::DentryIndex> {
        self.0.enable_dentry_index()
    }

    /// Internal: Run an `open()`-like function without allowing modifications or write access.
    ///
    /// That means:
    /// - Prevent access modes other than `O_RDONLY` and the following flags:
    ///   - O_EXCL: We filter out `O_CREAT`, and then, its behavior will be undefined (except for
    ///     block devices, which don’t really work with virtio-fs anyway).  In any case, on a
    ///     read-only filesystem, `O_CREAT | O_EXCL` will always give an error.
    ///   - O_TMPFILE: Not allowed with `O_RDONLY`.
    ///   - O_TRUNC: Undefined behavior with `O_RDONLY`, might truncate anyway.
    /// - Filter out `O_CREAT`, and return `EROFS` if the path does not exist yet
    ///
    /// `open_fn` runs the underlying open function, taking the potentially modified flags as an
    /// argument.
    fn rofs_open<R, F: FnOnce(u32) -> io::Result<R>>(flags: u32, open_fn: F) -> io::Result<R> {
        match read_only_open(flags, HOST_KEEPS_O_PATH)? {
            ReadOnlyOpen::Open(flags) => open_fn(flags),
            // Try to open without CREAT, if that fails, return EROFS
            ReadOnlyOpen::OpenExisting(flags) => open_fn(flags).map_err(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    erofs()
                } else {
                    err
                }
            }),
        }
    }
}

/// What a read-only share does with an open the guest asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadOnlyOpen {
    /// Open with these flags, still in the guest's encoding.
    Open(u32),
    /// The guest asked for `O_CREAT`. Open with these flags, which no longer carry it, and answer
    /// `EROFS` if the file does not exist.
    OpenExisting(u32),
}

/// Whether the host's open(2) honours a guest's `O_PATH`, and so ignores the guest's other flags.
#[cfg(target_os = "linux")]
const HOST_KEEPS_O_PATH: bool = true;
/// Whether the host's open(2) honours a guest's `O_PATH`, and so ignores the guest's other flags.
#[cfg(target_os = "macos")]
const HOST_KEEPS_O_PATH: bool = false;

/// Decide what a read-only share does with the open flags `flags` a guest sent.
fn read_only_open(flags: u32, host_keeps_o_path: bool) -> io::Result<ReadOnlyOpen> {
    let _ = host_keeps_o_path;
    let cflags: libc::c_int = flags
        .try_into()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    #[cfg(target_os = "linux")]
    let o_path = libc::O_PATH;
    #[cfg(target_os = "macos")]
    let o_path = libc::O_RDONLY; // O_PATH not available on macOS
    if cflags & o_path != 0 {
        return Ok(ReadOnlyOpen::Open(flags));
    }
    if cflags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(erofs());
    }
    if cflags & libc::O_EXCL == libc::O_EXCL {
        return Err(erofs());
    }
    if cflags & libc::O_TMPFILE == libc::O_TMPFILE {
        return Err(einval());
    }
    if cflags & libc::O_TRUNC == libc::O_TRUNC {
        return Err(einval());
    }
    if cflags & libc::O_CREAT == 0 {
        Ok(ReadOnlyOpen::Open(flags))
    } else {
        Ok(ReadOnlyOpen::OpenExisting(flags & !(libc::O_CREAT as u32)))
    }
}

/// Create function definitions that always fall through to the corresponding function on `self.0`
macro_rules! ops_allow {
    {
        $(
            fn $name:ident$(<$($gen_name:ident: $gen_trait:path),*>)?(
                &self
                $(, $($par_name:ident: $par_type:ty),*)?
                $(,)?
            )$( -> $ret:ty)?;
        )*
    } => {
        $(
            fn $name$(<$($gen_name: $gen_trait),*>)?(
                &self
                $(, $($par_name: $par_type),*)?
            )$( -> $ret)? {
                self.0.$name($($($par_name),*)?)
            }
        )*
    }
}

/// Create function definitions that always return `Err(erofs())`
macro_rules! ops_forbid {
    {
        $(
            fn $name:ident$(<$($gen_name:ident: $gen_trait:path),*>)?(
                &self
                $(, $($par_name:ident: $par_type:ty),*)?
                $(,)?
            ) -> io::Result<$ret_ok:ty>;
        )*
    } => {
        $(
            fn $name$(<$($gen_name: $gen_trait),*>)?(
                &self
                $(, $($par_name: $par_type),*)?
            ) -> io::Result<$ret_ok> {
                Err(erofs())
            }
        )*
    }
}

impl FileSystem for PassthroughFsRo {
    type Inode = <PassthroughFs as FileSystem>::Inode;
    type Handle = <PassthroughFs as FileSystem>::Handle;
    type DirIter = <PassthroughFs as FileSystem>::DirIter;

    // Execute these functions without restrictions
    ops_allow! {
        fn init(&self, capable: FsOptions) -> io::Result<FsOptions>;
        fn destroy(&self);
        fn lookup(&self, ctx: Context, parent: Self::Inode, name: &CStr) -> io::Result<Entry>;
        fn forget(&self, ctx: Context, inode: Self::Inode, count: u64);
        fn batch_forget(&self, ctx: Context, requests: Vec<(Self::Inode, u64)>);
        fn getattr(&self,
            ctx: Context,
            inode: Self::Inode,
            handle: Option<Self::Handle>,
        ) -> io::Result<(fuse::Attr, Duration)>;
        fn readlink(&self, ctx: Context, inode: Self::Inode) -> io::Result<Vec<u8>>;
        fn read<W: ZeroCopyWriter>(
            &self,
            ctx: Context,
            inode: Self::Inode,
            handle: Self::Handle,
            w: W,
            size: u32,
            offset: u64,
            lock_owner: Option<u64>,
            flags: u32,
        ) -> io::Result<usize>;
        fn flush(
            &self,
            ctx: Context,
            inode: Self::Inode,
            handle: Self::Handle,
            lock_owner: u64,
        ) -> io::Result<()>;
        fn fsync(
            &self,
            ctx: Context,
            inode: Self::Inode,
            datasync: bool,
            handle: Self::Handle,
        ) -> io::Result<()>;
        fn release(
            &self,
            ctx: Context,
            inode: Self::Inode,
            flags: u32,
            handle: Self::Handle,
            flush: bool,
            flock_release: bool,
            lock_owner: Option<u64>,
        ) -> io::Result<()>;
        fn statfs(&self, ctx: Context, inode: Self::Inode) -> io::Result<libc::statvfs64>;
        fn getxattr(
            &self,
            ctx: Context,
            inode: Self::Inode,
            name: &CStr,
            size: u32,
        ) -> io::Result<GetxattrReply>;
        fn listxattr(
            &self,
            ctx: Context,
            inode: Self::Inode,
            size: u32,
        ) -> io::Result<ListxattrReply>;
        fn readdir(
            &self,
            ctx: Context,
            inode: Self::Inode,
            handle: Self::Handle,
            size: u32,
            offset: u64,
        ) -> io::Result<Self::DirIter>;
        fn fsyncdir(
            &self,
            ctx: Context,
            inode: Self::Inode,
            datasync: bool,
            handle: Self::Handle,
        ) -> io::Result<()>;
        fn releasedir(
            &self,
            ctx: Context,
            inode: Self::Inode,
            flags: u32,
            handle: Self::Handle,
        ) -> io::Result<()>;
        fn lseek(
            &self,
            ctx: Context,
            inode: Self::Inode,
            handle: Self::Handle,
            offset: u64,
            whence: u32,
        ) -> io::Result<u64>;
        fn syncfs(&self, ctx: Context, inode: Self::Inode) -> io::Result<()>;
    }

    // Refuse to run these functions, always returning EROFS.
    // Note: We assume that these functions must always fail on a read-only filesystem, so failing
    // without further checks should be safe and reasonable.  However, the Linux kernel treats
    // EROFS more like a final barrier, i.e. something that is returned only if the operation would
    // succeed on a writable filesystem.  For example, on an -o ro filesystem, `mkdir()` will not
    // return EROFS immediately, but first check whether the path already exists, and if so, return
    // EEXIST instead.  That would be complicated though (and might introduce TOCTTOU problems), so
    // unconditionally returning EROFS seems like a more viable option for us.
    // (FWIW, the FUSE kernel driver does not seem to special-case EEXIST.)
    ops_forbid! {
        fn setattr(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _attr: fuse::SetattrIn,
            _handle: Option<Self::Handle>,
            _valid: SetattrValid,
        ) -> io::Result<(fuse::Attr, Duration)>;
        fn symlink(
            &self,
            _ctx: Context,
            _linkname: &CStr,
            _parent: Self::Inode,
            _name: &CStr,
            _extensions: Extensions,
        ) -> io::Result<Entry>;
        fn mknod(
            &self,
            _ctx: Context,
            _parent: Self::Inode,
            _name: &CStr,
            _mode: u32,
            _rdev: u32,
            _umask: u32,
            _extensions: Extensions,
        ) -> io::Result<Entry>;
        fn mkdir(
            &self,
            _ctx: Context,
            _parent: Self::Inode,
            _name: &CStr,
            _mode: u32,
            _umask: u32,
            _extensions: Extensions,
        ) -> io::Result<Entry>;
        fn unlink(&self, _ctx: Context, _parent: Self::Inode, _name: &CStr) -> io::Result<()>;
        fn rmdir(&self, _ctx: Context, _parent: Self::Inode, _name: &CStr) -> io::Result<()>;
        fn rename(
            &self,
            _ctx: Context,
            _olddir: Self::Inode,
            _oldname: &CStr,
            _newdir: Self::Inode,
            _newname: &CStr,
            _flags: u32,
        ) -> io::Result<()>;
        fn link(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _newparent: Self::Inode,
            _newname: &CStr,
        ) -> io::Result<Entry>;
        fn write<R: ZeroCopyReader>(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _r: R,
            _size: u32,
            _offset: u64,
            _lock_owner: Option<u64>,
            _delayed_write: bool,
            _kill_priv: bool,
            _flags: u32,
        ) -> io::Result<usize>;
        fn fallocate(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _handle: Self::Handle,
            _mode: u32,
            _offset: u64,
            _length: u64,
        ) -> io::Result<()>;
        fn setxattr(
            &self,
            _ctx: Context,
            _inode: Self::Inode,
            _name: &CStr,
            _value: &[u8],
            _flags: u32,
            _extra_flags: SetxattrFlags,
        ) -> io::Result<()>;
        fn removexattr(&self, _ctx: Context, _inode: Self::Inode, _name: &CStr) -> io::Result<()>;
        fn copyfilerange(
            &self,
            _ctx: Context,
            _inode_in: Self::Inode,
            _handle_in: Self::Handle,
            _offset_in: u64,
            _inode_out: Self::Inode,
            _handle_out: Self::Handle,
            _offset_out: u64,
            _len: u64,
            _flags: u64,
        ) -> io::Result<usize>;
    }

    fn open(
        &self,
        ctx: Context,
        inode: Self::Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        Self::rofs_open(flags, |flags| self.0.open(ctx, inode, kill_priv, flags))
    }

    fn create(
        &self,
        ctx: Context,
        parent: Self::Inode,
        name: &CStr,
        _mode: u32,
        kill_priv: bool,
        flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        // We never want to create, but we should allow opening existing files
        let entry = self.lookup(ctx, parent, name).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                erofs()
            } else {
                err
            }
        })?;
        let (handle, opts) = self.open(ctx, entry.inode, kill_priv, flags)?;
        Ok((entry, handle, opts))
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Self::Inode,
        flags: u32,
    ) -> io::Result<(Option<Self::Handle>, OpenOptions)> {
        Self::rofs_open(flags, |flags| self.0.opendir(ctx, inode, flags))
    }

    fn access(&self, ctx: Context, inode: Self::Inode, mask: u32) -> io::Result<()> {
        if mask & libc::W_OK as u32 != 0 {
            Err(erofs())
        } else {
            self.0.access(ctx, inode, mask)
        }
    }
}

impl SerializableFileSystem for PassthroughFsRo {
    ops_allow! {
        fn prepare_serialization(&self, cancel: Arc<AtomicBool>);
        fn serialize(&self, state_pipe: File) -> io::Result<()>;
        fn deserialize_and_apply(&self, state_pipe: File) -> io::Result<()>;
    }
}

#[cfg(test)]
mod tests {
    use super::{read_only_open, ReadOnlyOpen};
    use std::io;

    // A Linux guest's open flags, written out from the kernel's headers rather than taken from
    // the host's `libc`, so these tests read the same on every host. These are
    // `include/uapi/asm-generic/fcntl.h`'s, which x86_64 and aarch64 share.
    const O_RDONLY: u32 = 0o0;
    const O_WRONLY: u32 = 0o1;
    const O_RDWR: u32 = 0o2;
    const O_CREAT: u32 = 0o100;
    const O_EXCL: u32 = 0o200;
    const O_TRUNC: u32 = 0o1000;
    const O_APPEND: u32 = 0o2000;
    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC: u32 = 0o2000000;
    const O_PATH: u32 = 0o10000000;
    const __O_TMPFILE: u32 = 0o20000000;

    /// The flags that differ by guest architecture: `(arch, O_DIRECT, O_LARGEFILE,
    /// O_DIRECTORY)`, from `arch/arm64/include/uapi/asm/fcntl.h` against the generic header.
    /// `O_TMPFILE` is `__O_TMPFILE | O_DIRECTORY`, so it differs too.
    const ARCHES: [(&str, u32, u32, u32); 2] = [
        ("x86_64", 0o40000, 0o100000, 0o200000),
        ("aarch64", 0o200000, 0o400000, 0o40000),
    ];

    /// Every case that does not involve `O_PATH` is decided the same way on either kind of host.
    const HOSTS: [bool; 2] = [true, false];

    fn errno(result: io::Result<ReadOnlyOpen>) -> Option<i32> {
        match result {
            Ok(open) => panic!("expected an error, got {:?}", open),
            Err(err) => err.raw_os_error(),
        }
    }

    /// The opens a guest makes to read: each architecture's `O_LARGEFILE`, which a 64-bit kernel
    /// adds to every open, with flags that do not write. On macOS every one of these used to
    /// fail with `EINVAL`, because `O_TMPFILE` there is a stand-in defined as 0.
    #[test]
    fn a_read_only_open_is_allowed() {
        for (arch, direct, largefile, directory) in ARCHES {
            for host in HOSTS {
                for extra in [
                    0,
                    O_CLOEXEC,
                    direct,
                    directory,
                    O_NONBLOCK,
                    O_APPEND,
                    O_CLOEXEC | O_NONBLOCK | directory,
                ] {
                    let flags = O_RDONLY | largefile | extra;
                    assert_eq!(
                        read_only_open(flags, host).unwrap_or_else(|e| panic!(
                            "{}, host keeps O_PATH {}: {:#o}: {}",
                            arch, host, flags, e
                        )),
                        ReadOnlyOpen::Open(flags),
                        "{arch}, host keeps O_PATH {host}: {flags:#o}"
                    );
                }
            }
        }
    }

    #[test]
    fn write_access_is_erofs() {
        for host in HOSTS {
            for flags in [O_WRONLY, O_RDWR, O_RDWR | O_CREAT, O_WRONLY | O_TRUNC] {
                assert_eq!(
                    errno(read_only_open(flags, host)),
                    Some(libc::EROFS),
                    "{flags:#o}"
                );
            }
        }
    }

    /// Linux's `O_EXCL` is Darwin's `O_CREAT`, and Darwin's `O_EXCL` is Linux's `O_NONBLOCK`.
    #[test]
    fn o_excl_is_erofs() {
        for host in HOSTS {
            for flags in [O_EXCL, O_CREAT | O_EXCL] {
                assert_eq!(
                    errno(read_only_open(flags, host)),
                    Some(libc::EROFS),
                    "{flags:#o}"
                );
            }
        }
    }

    /// `O_TRUNC` with `O_RDONLY` is undefined and could truncate the file, so it is refused.
    /// Linux's `O_TRUNC` is Darwin's `O_CREAT`, and Darwin's `O_TRUNC` is Linux's `O_APPEND`.
    #[test]
    fn o_trunc_is_einval() {
        for host in HOSTS {
            for flags in [O_TRUNC, O_TRUNC | O_CREAT] {
                assert_eq!(
                    errno(read_only_open(flags, host)),
                    Some(libc::EINVAL),
                    "{flags:#o}"
                );
            }
        }
    }

    /// `O_CREAT` opens the file if it is there, and the guest's `O_CREAT` bit is what is cleared.
    #[test]
    fn o_creat_opens_only_an_existing_file() {
        for (arch, _, largefile, _) in ARCHES {
            for host in HOSTS {
                assert_eq!(
                    read_only_open(O_CREAT | O_CLOEXEC | largefile, host).unwrap(),
                    ReadOnlyOpen::OpenExisting(O_CLOEXEC | largefile),
                    "{arch}"
                );
            }
        }
    }

    /// `O_TMPFILE` carries the guest architecture's `O_DIRECTORY`, so testing for it with the
    /// host's value missed another architecture's. Any `__O_TMPFILE` bit is refused, which the
    /// guest's kernel would have refused already without `O_DIRECTORY`.
    #[test]
    fn o_tmpfile_is_einval_for_each_arch() {
        for (arch, _, largefile, directory) in ARCHES {
            for host in HOSTS {
                for flags in [__O_TMPFILE | directory, __O_TMPFILE] {
                    assert_eq!(
                        errno(read_only_open(flags | largefile, host)),
                        Some(libc::EINVAL),
                        "{arch}: {flags:#o}"
                    );
                }
                assert_eq!(
                    errno(read_only_open(O_RDWR | __O_TMPFILE | directory, host)),
                    Some(libc::EROFS),
                    "{arch}"
                );
            }
        }
    }

    /// A Linux host opens `O_PATH` without reading the other flags, so it is let through as it
    /// always was. macOS has no `O_PATH`: the translation drops it and would honour the access
    /// mode, so there the other checks still apply.
    #[test]
    fn o_path_bypasses_the_checks_only_where_the_host_keeps_it() {
        let flags = O_PATH | O_WRONLY | O_TRUNC;
        assert_eq!(
            read_only_open(flags, true).unwrap(),
            ReadOnlyOpen::Open(flags)
        );
        assert_eq!(errno(read_only_open(flags, false)), Some(libc::EROFS));
        assert_eq!(
            read_only_open(O_PATH, false).unwrap(),
            ReadOnlyOpen::Open(O_PATH)
        );
    }

    /// The written-out values checked against something that is not this code: on a Linux host
    /// `libc` gives the host architecture's own, which is what a native guest sends.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_libc_values_are_checked_as_the_flags_they_name() {
        let flags = |f: libc::c_int| f as u32;
        let decide = |f| read_only_open(flags(f), true);
        assert_eq!(
            decide(libc::O_RDONLY | libc::O_DIRECT | libc::O_NONBLOCK).unwrap(),
            ReadOnlyOpen::Open(flags(libc::O_DIRECT | libc::O_NONBLOCK))
        );
        assert_eq!(
            decide(libc::O_DIRECTORY | libc::O_CLOEXEC).unwrap(),
            ReadOnlyOpen::Open(flags(libc::O_DIRECTORY | libc::O_CLOEXEC))
        );
        assert_eq!(
            decide(libc::O_CREAT | libc::O_NOFOLLOW).unwrap(),
            ReadOnlyOpen::OpenExisting(flags(libc::O_NOFOLLOW))
        );
        assert_eq!(
            decide(libc::O_PATH | libc::O_WRONLY).unwrap(),
            ReadOnlyOpen::Open(flags(libc::O_PATH | libc::O_WRONLY))
        );
        assert_eq!(errno(decide(libc::O_RDWR)), Some(libc::EROFS));
        assert_eq!(errno(decide(libc::O_EXCL)), Some(libc::EROFS));
        assert_eq!(errno(decide(libc::O_TRUNC)), Some(libc::EINVAL));
        assert_eq!(errno(decide(libc::O_TMPFILE)), Some(libc::EINVAL));
    }
}
