// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::descriptor_utils::{Reader, Writer};
use crate::filesystem::{
    Context, DirEntry, DirectoryIterator, Entry, Extensions, FileSystem, GetxattrReply,
    ListxattrReply, SecContext, SerializableFileSystem, ZeroCopyReader, ZeroCopyWriter,
};
use crate::fuse::*;
use crate::passthrough::util::einval;
use crate::soft_idmap::GuestGid;
use crate::{oslib, Error, Result};
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use vm_memory::ByteValued;

const FUSE_BUFFER_HEADER_SIZE: u32 = 0x1000;
const MAX_BUFFER_SIZE: u32 = 1 << 20;

/// Translate a native errno value to a Linux errno value.
///
/// The FUSE protocol uses Linux errno values. On Linux this is a no-op, but on macOS
/// many errno values differ and must be translated before being sent to the guest kernel.
#[cfg(target_os = "linux")]
#[inline]
fn errno_to_linux(errno: i32) -> i32 {
    errno
}

#[cfg(target_os = "macos")]
fn errno_to_linux(errno: i32) -> i32 {
    // The FUSE protocol uses Linux errno values. macOS and Linux agree on
    // 1..=34 (EPERM..ERANGE), then diverge wildly. Each entry below is the
    // numeric value Apple ships in <sys/errno.h> mapped to its Linux peer
    // in <asm-generic/errno.h>. Unmapped values pass through unchanged
    // because they are either (a) macOS-only (EAUTH, EPWROFF, ENOPOLICY,
    // EOWNERDEAD-on-old-versions, ...) with no sensible Linux equivalent,
    // or (b) already in the agreed 1..=34 range.
    //
    // If you change anything here, also update `errno_to_linux_table` in
    // the test module — that's the regression net that catches the kind of
    // silently-wrong entry that previously translated EOPNOTSUPP to
    // ENETRESET and broke `qemu-img convert` over virtio-fs.
    match errno {
        35 => 11,  // EAGAIN/EWOULDBLOCK: macOS=35,  Linux=11
        36 => 115, // EINPROGRESS:        macOS=36,  Linux=115
        37 => 114, // EALREADY:           macOS=37,  Linux=114
        38 => 88,  // ENOTSOCK:           macOS=38,  Linux=88
        39 => 89,  // EDESTADDRREQ:       macOS=39,  Linux=89
        40 => 90,  // EMSGSIZE:           macOS=40,  Linux=90
        41 => 91,  // EPROTOTYPE:         macOS=41,  Linux=91
        42 => 92,  // ENOPROTOOPT:        macOS=42,  Linux=92
        43 => 93,  // EPROTONOSUPPORT:    macOS=43,  Linux=93
        44 => 94,  // ESOCKTNOSUPPORT:    macOS=44,  Linux=94
        45 => 95,  // ENOTSUP/EOPNOTSUPP: macOS=45,  Linux=95 (POSIX-flavor)
        46 => 96,  // EPFNOSUPPORT:       macOS=46,  Linux=96
        47 => 97,  // EAFNOSUPPORT:       macOS=47,  Linux=97
        48 => 98,  // EADDRINUSE:         macOS=48,  Linux=98
        49 => 99,  // EADDRNOTAVAIL:      macOS=49,  Linux=99
        50 => 100, // ENETDOWN:           macOS=50,  Linux=100
        51 => 101, // ENETUNREACH:        macOS=51,  Linux=101
        52 => 102, // ENETRESET:          macOS=52,  Linux=102
        53 => 103, // ECONNABORTED:       macOS=53,  Linux=103
        54 => 104, // ECONNRESET:         macOS=54,  Linux=104
        55 => 105, // ENOBUFS:            macOS=55,  Linux=105
        56 => 106, // EISCONN:            macOS=56,  Linux=106
        57 => 107, // ENOTCONN:           macOS=57,  Linux=107
        58 => 108, // ESHUTDOWN:          macOS=58,  Linux=108
        59 => 109, // ETOOMANYREFS:       macOS=59,  Linux=109
        60 => 110, // ETIMEDOUT:          macOS=60,  Linux=110
        61 => 111, // ECONNREFUSED:       macOS=61,  Linux=111
        62 => 40,  // ELOOP:              macOS=62,  Linux=40
        63 => 36,  // ENAMETOOLONG:       macOS=63,  Linux=36
        64 => 112, // EHOSTDOWN:          macOS=64,  Linux=112
        65 => 113, // EHOSTUNREACH:       macOS=65,  Linux=113
        66 => 39,  // ENOTEMPTY:          macOS=66,  Linux=39
        69 => 122, // EDQUOT:             macOS=69,  Linux=122
        70 => 116, // ESTALE:             macOS=70,  Linux=116
        77 => 37,  // ENOLCK:             macOS=77,  Linux=37
        78 => 38,  // ENOSYS:             macOS=78,  Linux=38
        84 => 75,  // EOVERFLOW:          macOS=84,  Linux=75
        89 => 125, // ECANCELED:          macOS=89,  Linux=125
        90 => 43,  // EIDRM:              macOS=90,  Linux=43
        91 => 42,  // ENOMSG:             macOS=91,  Linux=42
        92 => 84,  // EILSEQ:             macOS=92,  Linux=84
        93 => 61,  // ENOATTR -> ENODATA: macOS=93,  Linux=61.
        // Without this, APFS returning ENOATTR for missing xattrs
        // (e.g. security.selinux, system.posix_acl_*) reaches the
        // guest as Linux 93=EPROTONOSUPPORT, breaking `ls -la`.
        94 => 74,  // EBADMSG:            macOS=94,  Linux=74
        95 => 72,  // EMULTIHOP:          macOS=95,  Linux=72
        96 => 61,  // ENODATA:            macOS=96,  Linux=61 (same Linux peer as ENOATTR)
        97 => 67,  // ENOLINK:            macOS=97,  Linux=67
        98 => 63,  // ENOSR:              macOS=98,  Linux=63
        99 => 60,  // ENOSTR:             macOS=99,  Linux=60
        100 => 71, // EPROTO:             macOS=100, Linux=71
        101 => 62, // ETIME:              macOS=101, Linux=62
        102 => 95, // EOPNOTSUPP:         macOS=102, Linux=95 (BSD-flavor — the
        // value `libc::EOPNOTSUPP` actually compiles to on Darwin).
        // Until this entry existed, our `fallocate` returning
        // EOPNOTSUPP for unsupported modes reached the guest as
        // Linux 102=ENETRESET, surfacing as
        // "Network dropped connection on reset" out of `qemu-img`.
        104 => 131, // ENOTRECOVERABLE:    macOS=104, Linux=131
        105 => 130, // EOWNERDEAD:         macOS=105, Linux=130
        _ => errno, // Pass through 1..=34 (EPERM..ERANGE — they agree)
                     // and macOS-only values with no Linux peer.
    }
}
const DIRENT_PADDING: [u8; 8] = [0; 8];

const CURRENT_DIR_CSTR: &[u8] = b".";
const PARENT_DIR_CSTR: &[u8] = b"..";

struct ZcReader<'a>(Reader<'a>);

impl ZeroCopyReader for ZcReader<'_> {
    fn write_to_file_at(
        &mut self,
        f: &File,
        mut count: usize,
        mut off: u64,
        flags: Option<oslib::WritevFlags>,
    ) -> io::Result<usize> {
        let start = off;
        while count > 0 {
            let written = self.0.write_to_file_at(f, count, off, flags)?;
            if written == 0 {
                break;
            }
            off = off
                .checked_add(written as u64)
                .ok_or_else(|| io::Error::other("Write wrap-around"))?;
            count = count
                .checked_sub(written)
                .ok_or_else(|| io::Error::other("Write operation wrote more than requested"))?;
        }

        // Must fit: Cannot be greater than `count` originally
        Ok((off - start) as usize)
    }
}

struct ZcWriter<'a>(Writer<'a>);

impl ZeroCopyWriter for ZcWriter<'_> {
    fn read_from_file_at(
        &mut self,
        f: &File,
        mut count: usize,
        mut off: u64,
        flags: Option<oslib::ReadvFlags>,
    ) -> io::Result<usize> {
        let start = off;
        while count > 0 {
            let read = self.0.read_from_file_at(f, count, off, flags)?;
            if read == 0 {
                break;
            }
            off = off
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("Read wrap-around"))?;
            count = count
                .checked_sub(read)
                .ok_or_else(|| io::Error::other("Read operation wrote more than requested"))?;
        }

        // Must fit: Cannot be greater than `count` originally
        Ok((off - start) as usize)
    }
}

pub struct Server<F: FileSystem + Sync> {
    fs: F,
    options: AtomicU64,
}

impl<F: FileSystem + Sync> Server<F> {
    pub fn new(fs: F) -> Server<F> {
        Server {
            fs,
            options: AtomicU64::new(FsOptions::empty().bits()),
        }
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn handle_message<T>(
        &self,
        mut r: Reader,
        w: Writer,
        vu_req: Option<&mut T>,
    ) -> Result<usize> {
        let in_header: InHeader = r.read_obj().map_err(Error::DecodeMessage)?;

        if in_header.len > (MAX_BUFFER_SIZE + FUSE_BUFFER_HEADER_SIZE) {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        if let Ok(opcode) = Opcode::try_from(in_header.opcode) {
            debug!(
                "Received request: opcode={opcode:?} ({}), inode={}, unique={}, pid={}",
                in_header.opcode, in_header.nodeid, in_header.unique, in_header.pid
            );
            match opcode {
                Opcode::Lookup => self.lookup(in_header, r, w),
                Opcode::Forget => self.forget(in_header, r), // No reply.
                Opcode::Getattr => self.getattr(in_header, r, w),
                Opcode::Setattr => self.setattr(in_header, r, w),
                Opcode::Readlink => self.readlink(in_header, w),
                Opcode::Symlink => self.symlink(in_header, r, w),
                Opcode::Mknod => self.mknod(in_header, r, w),
                Opcode::Mkdir => self.mkdir(in_header, r, w),
                Opcode::Unlink => self.unlink(in_header, r, w),
                Opcode::Rmdir => self.rmdir(in_header, r, w),
                Opcode::Rename => self.rename(in_header, r, w),
                Opcode::Link => self.link(in_header, r, w),
                Opcode::Open => self.open(in_header, r, w),
                Opcode::Read => self.read(in_header, r, w),
                Opcode::Write => self.write(in_header, r, w),
                Opcode::Statfs => self.statfs(in_header, w),
                Opcode::Release => self.release(in_header, r, w),
                Opcode::Fsync => self.fsync(in_header, r, w),
                Opcode::Setxattr => self.setxattr(in_header, r, w),
                Opcode::Getxattr => self.getxattr(in_header, r, w),
                Opcode::Listxattr => self.listxattr(in_header, r, w),
                Opcode::Removexattr => self.removexattr(in_header, r, w),
                Opcode::Flush => self.flush(in_header, r, w),
                Opcode::Init => self.init(in_header, r, w),
                Opcode::Opendir => self.opendir(in_header, r, w),
                Opcode::Readdir => self.readdir(in_header, r, w),
                Opcode::Releasedir => self.releasedir(in_header, r, w),
                Opcode::Fsyncdir => self.fsyncdir(in_header, r, w),
                Opcode::Getlk => self.getlk(in_header, r, w),
                Opcode::Setlk => self.setlk(in_header, r, w),
                Opcode::Setlkw => self.setlkw(in_header, r, w),
                Opcode::Access => self.access(in_header, r, w),
                Opcode::Create => self.create(in_header, r, w),
                Opcode::Interrupt => Ok(self.interrupt(in_header)),
                Opcode::Bmap => self.bmap(in_header, r, w),
                Opcode::Destroy => Ok(self.destroy()),
                Opcode::Ioctl => self.ioctl(in_header, r, w),
                Opcode::Poll => self.poll(in_header, r, w),
                Opcode::NotifyReply => self.notify_reply(in_header, r, w),
                Opcode::BatchForget => self.batch_forget(in_header, r, w),
                Opcode::Fallocate => self.fallocate(in_header, r, w),
                Opcode::Readdirplus => self.readdirplus(in_header, r, w),
                Opcode::Rename2 => self.rename2(in_header, r, w),
                Opcode::Lseek => self.lseek(in_header, r, w),
                Opcode::CopyFileRange => self.copyfilerange(in_header, r, w),
                Opcode::SetupMapping => self.setupmapping(in_header, r, w, vu_req),
                Opcode::RemoveMapping => self.removemapping(in_header, r, w, vu_req),
                Opcode::Syncfs => self.syncfs(in_header, w),
                Opcode::TmpFile => self.tmpfile(in_header, r, w),
            }
        } else {
            debug!(
                "Received unknown request: opcode={}, inode={}",
                in_header.opcode, in_header.nodeid
            );
            reply_error(
                io::Error::from_raw_os_error(libc::ENOSYS),
                in_header.unique,
                w,
            )
        }
    }

    fn setupmapping<T>(
        &self,
        in_header: InHeader,
        _r: Reader,
        w: Writer,
        _vu_req: Option<&mut T>,
    ) -> Result<usize> {
        reply_error(
            io::Error::from_raw_os_error(libc::ENOSYS),
            in_header.unique,
            w,
        )
    }

    fn removemapping<T>(
        &self,
        in_header: InHeader,
        _r: Reader,
        w: Writer,
        _vu_req: Option<&mut T>,
    ) -> Result<usize> {
        reply_error(
            io::Error::from_raw_os_error(libc::ENOSYS),
            in_header.unique,
            w,
        )
    }

    fn lookup(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0u8; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(buf.as_ref())?;

        match self
            .fs
            .lookup(Context::from(in_header), in_header.nodeid.into(), name)
        {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn forget(&self, in_header: InHeader, mut r: Reader) -> Result<usize> {
        let ForgetIn { nlookup } = r.read_obj().map_err(Error::DecodeMessage)?;

        self.fs
            .forget(Context::from(in_header), in_header.nodeid.into(), nlookup);

        // There is no reply for forget messages.
        Ok(0)
    }

    fn getattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetattrIn { flags, fh, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if (flags & GETATTR_FH) != 0 {
            Some(fh.into())
        } else {
            None
        };

        match self
            .fs
            .getattr(Context::from(in_header), in_header.nodeid.into(), handle)
        {
            Ok((attr, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr,
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let setattr_in: SetattrIn = r.read_obj().map_err(Error::DecodeMessage)?;

        let handle = if setattr_in.valid & FATTR_FH != 0 {
            Some(setattr_in.fh.into())
        } else {
            None
        };

        let valid = SetattrValid::from_bits_truncate(setattr_in.valid);

        match self.fs.setattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            setattr_in,
            handle,
            valid,
        ) {
            Ok((attr, timeout)) => {
                let out = AttrOut {
                    attr_valid: timeout.as_secs(),
                    attr_valid_nsec: timeout.subsec_nanos(),
                    dummy: 0,
                    attr,
                };
                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn readlink(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .readlink(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(linkname) => {
                // We need to disambiguate the option type here even though it is `None`.
                reply_ok(None::<u8>, Some(&linkname), in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn symlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        // Unfortunately the name and linkname are encoded one after another and
        // separated by a nul character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let mut components = buf.split_inclusive(|c| *c == b'\0');

        let name = components.next().ok_or(Error::MissingParameter)?;
        let linkname = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len() + linkname.len(), buf.as_slice())?;

        match self.fs.symlink(
            Context::from(in_header),
            bytes_to_cstr(linkname)?,
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mknod(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MknodIn {
            mode, rdev, umask, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MknodIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mknod(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            rdev,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn mkdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let MkdirIn { mode, umask } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<MkdirIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        match self.fs.mkdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            umask,
            extensions,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn unlink(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.unlink(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rmdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.rmdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn do_rename(
        &self,
        in_header: InHeader,
        msg_size: usize,
        newdir: u64,
        flags: u32,
        mut r: Reader,
        w: Writer,
    ) -> Result<usize> {
        let buflen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(msg_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; buflen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (oldname, newname) = buf.split_at(split_pos);

        match self.fs.rename(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(oldname)?,
            newdir.into(),
            bytes_to_cstr(newname)?,
            flags,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn rename(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let RenameIn { newdir } = r.read_obj().map_err(Error::DecodeMessage)?;

        self.do_rename(in_header, size_of::<RenameIn>(), newdir, 0, r, w)
    }

    fn rename2(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let Rename2In { newdir, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        // FUSE rename flags use Linux kernel values. Define compat constants for macOS.
        #[cfg(target_os = "linux")]
        let flags =
            flags & (libc::RENAME_EXCHANGE | libc::RENAME_NOREPLACE | libc::RENAME_WHITEOUT);
        #[cfg(target_os = "macos")]
        let flags = {
            // Linux constants: RENAME_NOREPLACE=1, RENAME_EXCHANGE=2, RENAME_WHITEOUT=4
            const LINUX_RENAME_NOREPLACE: u32 = 1;
            const LINUX_RENAME_EXCHANGE: u32 = 2;
            const LINUX_RENAME_WHITEOUT: u32 = 4;
            flags & (LINUX_RENAME_NOREPLACE | LINUX_RENAME_EXCHANGE | LINUX_RENAME_WHITEOUT)
        };

        self.do_rename(in_header, size_of::<Rename2In>(), newdir, flags, r, w)
    }

    fn link(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LinkIn { oldnodeid } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<LinkIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        match self.fs.link(
            Context::from(in_header),
            oldnodeid.into(),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
        ) {
            Ok(entry) => {
                let out = EntryOut::from(entry);

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn open(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn {
            flags, open_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.open(
            Context::from(in_header),
            in_header.nodeid.into(),
            kill_priv,
            flags,
        ) {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn read(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh,
            offset,
            size,
            read_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let owner = if read_flags & READ_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        // Split the writer into 2 pieces: one for the `OutHeader` and the rest for the data.
        let data_writer = ZcWriter(w.split_at(size_of::<OutHeader>()).unwrap());

        match self.fs.read(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_writer,
            size,
            offset,
            owner,
            flags,
        ) {
            Ok(count) => {
                // Don't use `reply_ok` because we need to set a custom size length for the
                // header.
                let out = OutHeader {
                    len: (size_of::<OutHeader>() + count) as u32,
                    error: 0,
                    unique: in_header.unique,
                };

                debug!("Replying OK, header: {out:?}");
                w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
                Ok(out.len as usize)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn write(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let WriteIn {
            fh,
            offset,
            size,
            write_flags,
            lock_owner,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let owner = if write_flags & WRITE_LOCKOWNER != 0 {
            Some(lock_owner)
        } else {
            None
        };

        let delayed_write = write_flags & WRITE_CACHE != 0;
        let kill_priv = write_flags & WRITE_KILL_PRIV != 0;

        let data_reader = ZcReader(r);

        match self.fs.write(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            data_reader,
            size,
            offset,
            owner,
            delayed_write,
            kill_priv,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn statfs(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .statfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(st) => reply_ok(Some(Kstatfs::from(st)), None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn release(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn {
            fh,
            flags,
            release_flags,
            lock_owner,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let flush = release_flags & RELEASE_FLUSH != 0;
        let flock_release = release_flags & RELEASE_FLOCK_UNLOCK != 0;
        let lock_owner = if flush || flock_release {
            Some(lock_owner)
        } else {
            None
        };

        match self.fs.release(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
            flush,
            flock_release,
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsync(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsync(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn setxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));
        let (
            SetxattrIn {
                size,
                flags,
                setxattr_flags,
                ..
            },
            setxattrin_size,
        ) = if options.contains(FsOptions::SETXATTR_EXT) {
            (
                r.read_obj().map_err(Error::DecodeMessage)?,
                size_of::<SetxattrIn>(),
            )
        } else {
            let SetxattrInCompat { size, flags } = r.read_obj().map_err(Error::DecodeMessage)?;
            (
                SetxattrIn {
                    size,
                    flags,
                    setxattr_flags: 0,
                    padding: 0,
                },
                size_of::<SetxattrInCompat>(),
            )
        };

        // The name and value and encoded one after another and separated by a '\0' character.
        let len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(setxattrin_size))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut buf = vec![0; len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        // We want to include the '\0' byte in the first slice.
        let split_pos = buf
            .iter()
            .position(|c| *c == b'\0')
            .map(|p| p + 1)
            .ok_or(Error::MissingParameter)?;

        let (name, value) = buf.split_at(split_pos);

        if size != value.len() as u32 {
            return Err(Error::InvalidXattrSize((size, value.len())));
        }

        match self.fs.setxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            value,
            flags,
            SetxattrFlags::from_bits_truncate(setxattr_flags),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<GetxattrIn>()))
            .ok_or(Error::InvalidHeaderLength)?;
        let mut name = vec![0; namelen];

        r.read_exact(&mut name).map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self.fs.getxattr(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(&name)?,
            size,
        ) {
            Ok(GetxattrReply::Value(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(GetxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn listxattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let GetxattrIn { size, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        match self
            .fs
            .listxattr(Context::from(in_header), in_header.nodeid.into(), size)
        {
            Ok(ListxattrReply::Names(val)) => reply_ok(None::<u8>, Some(&val), in_header.unique, w),
            Ok(ListxattrReply::Count(count)) => {
                let out = GetxattrOut {
                    size: count,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn removexattr(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let namelen = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; namelen];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;

        let name = bytes_to_cstr(&buf)?;

        match self
            .fs
            .removexattr(Context::from(in_header), in_header.nodeid.into(), name)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn flush(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FlushIn { fh, lock_owner, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.flush(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            lock_owner,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn init(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let InitInCompat {
            major,
            minor,
            max_readahead,
            flags,
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let options = FsOptions::from_bits_truncate(flags as u64);

        let InitInExt { flags2, .. } = if options.contains(FsOptions::INIT_EXT) {
            r.read_obj().map_err(Error::DecodeMessage)?
        } else {
            InitInExt::default()
        };

        if major < KERNEL_VERSION {
            error!("Unsupported fuse protocol version: {major}.{minor}");
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        if major > KERNEL_VERSION {
            // Wait for the kernel to reply back with a 7.X version.
            let out = InitOut {
                major: KERNEL_VERSION,
                minor: KERNEL_MINOR_VERSION,
                ..Default::default()
            };

            return reply_ok(Some(out), None, in_header.unique, w);
        }

        if minor < MIN_KERNEL_MINOR_VERSION {
            error!("Unsupported fuse protocol minor version: {major}.{minor}");
            return reply_error(
                io::Error::from_raw_os_error(libc::EPROTO),
                in_header.unique,
                w,
            );
        }

        // These fuse features are supported by this server by default.
        let supported = FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::BIG_WRITES
            | FsOptions::AUTO_INVAL_DATA
            | FsOptions::ASYNC_DIO
            | FsOptions::HAS_IOCTL_DIR
            | FsOptions::ATOMIC_O_TRUNC
            | FsOptions::MAX_PAGES
            | FsOptions::SUBMOUNTS
            | FsOptions::INIT_EXT
            | FsOptions::CREATE_SUPP_GROUP
            | FsOptions::ALLOW_IDMAP;

        let flags_64 = ((flags2 as u64) << 32) | (flags as u64);
        let capable = FsOptions::from_bits_truncate(flags_64);

        let page_size: u32 = unsafe { libc::sysconf(libc::_SC_PAGESIZE).try_into().unwrap() };
        let max_pages = ((MAX_BUFFER_SIZE - 1) / page_size) + 1;

        match self.fs.init(capable) {
            Ok(want) => {
                let enabled = (capable & (want | supported)).bits();
                self.options.store(enabled, Ordering::Relaxed);

                let out = InitOut {
                    major: KERNEL_VERSION,
                    minor: KERNEL_MINOR_VERSION,
                    max_readahead,
                    flags: enabled as u32,
                    max_background: u16::MAX,
                    congestion_threshold: (u16::MAX / 4) * 3,
                    max_write: MAX_BUFFER_SIZE,
                    time_gran: 1, // nanoseconds
                    max_pages: max_pages.try_into().unwrap(),
                    map_alignment: 0,
                    flags2: (enabled >> 32) as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn opendir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let OpenIn { flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .opendir(Context::from(in_header), in_header.nodeid.into(), flags)
        {
            Ok((handle, opts)) => {
                let out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn readdir(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let available_bytes = w.available_bytes();
        if available_bytes < size as usize {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        // Skip over enough bytes for the header.
        let unique = in_header.unique;
        let mut cursor = w.split_at(size_of::<OutHeader>()).unwrap();
        let result = match self.fs.readdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            size,
            offset,
        ) {
            Ok(mut entries) => {
                let mut total_written = 0;
                let mut err = None;
                while let Some(dirent) = entries.next() {
                    let remaining = (size as usize).saturating_sub(total_written);
                    match add_dirent(&mut cursor, remaining, dirent, None) {
                        // No more space left in the buffer.
                        Ok(0) => break,
                        Ok(bytes_written) => {
                            total_written += bytes_written;
                        }
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                if let Some(err) = err {
                    Err(err)
                } else {
                    Ok(total_written)
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(total_written) => reply_readdir(total_written, unique, w),
            Err(e) => reply_error(e, unique, w),
        }
    }

    fn handle_dirent<'d>(
        &self,
        in_header: &InHeader,
        dir_entry: DirEntry<'d>,
    ) -> io::Result<(DirEntry<'d>, Entry)> {
        let parent = in_header.nodeid.into();
        let name = dir_entry.name.to_bytes();
        let entry = if name == CURRENT_DIR_CSTR || name == PARENT_DIR_CSTR {
            // We use 0 for the inode value to indicate a negative entry.
            Entry {
                inode: 0,
                generation: 0,
                // Don't do lookups on the current directory or the parent directory, i.e. leave
                // most fields 0.
                attr: Attr {
                    ino: dir_entry.ino,
                    mode: dir_entry.type_ << 12,
                    ..Default::default()
                },
                attr_timeout: Duration::from_secs(0),
                entry_timeout: Duration::from_secs(0),
            }
        } else {
            self.fs
                .lookup(Context::from(*in_header), parent, dir_entry.name)?
        };

        Ok((dir_entry, entry))
    }

    fn readdirplus(&self, in_header: InHeader, mut r: Reader, mut w: Writer) -> Result<usize> {
        let ReadIn {
            fh, offset, size, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        if size > MAX_BUFFER_SIZE {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        let available_bytes = w.available_bytes();
        if available_bytes < size as usize {
            return reply_error(
                io::Error::from_raw_os_error(libc::ENOMEM),
                in_header.unique,
                w,
            );
        }

        // Skip over enough bytes for the header.
        let unique = in_header.unique;
        let mut cursor = w.split_at(size_of::<OutHeader>()).unwrap();
        let result = match self.fs.readdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            size,
            offset,
        ) {
            Ok(mut entries) => {
                let mut total_written = 0;
                let mut err = None;
                while let Some(dirent) = entries.next() {
                    let mut entry_inode = None;
                    let bytes_written =
                        self.handle_dirent(&in_header, dirent).and_then(|(d, e)| {
                            entry_inode = Some(e.inode);
                            let remaining = (size as usize).saturating_sub(total_written);
                            add_dirent(&mut cursor, remaining, d, Some(e))
                        });
                    match bytes_written {
                        Ok(0) => {
                            // No more space left in the buffer but we need to undo the lookup
                            // that created the Entry or we will end up with mismatched lookup
                            // counts.
                            if let Some(inode) = entry_inode {
                                self.fs.forget(Context::from(in_header), inode.into(), 1);
                            }
                            break;
                        }
                        Ok(bytes_written) => {
                            total_written += bytes_written;
                        }
                        Err(e) => {
                            if let Some(inode) = entry_inode {
                                self.fs.forget(Context::from(in_header), inode.into(), 1);
                            }

                            if total_written == 0 {
                                // We haven't filled any entries yet so we can just propagate
                                // the error.
                                err = Some(e);
                            }

                            // We already filled in some entries. Returning an error now will
                            // cause lookup count mismatches for those entries so just return
                            // whatever we already have.
                            break;
                        }
                    }
                }
                if let Some(err) = err {
                    Err(err)
                } else {
                    Ok(total_written)
                }
            }
            Err(e) => Err(e),
        };

        match result {
            Ok(total_written) => reply_readdir(total_written, unique, w),
            Err(e) => reply_error(e, unique, w),
        }
    }

    fn releasedir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let ReleaseIn { fh, flags, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.releasedir(
            Context::from(in_header),
            in_header.nodeid.into(),
            flags,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn fsyncdir(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FsyncIn {
            fh, fsync_flags, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;
        let datasync = fsync_flags & 0x1 != 0;

        match self.fs.fsyncdir(
            Context::from(in_header),
            in_header.nodeid.into(),
            datasync,
            fh.into(),
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn getlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.getlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlk(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlk() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn setlkw(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.setlkw() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn access(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let AccessIn { mask, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self
            .fs
            .access(Context::from(in_header), in_header.nodeid.into(), mask)
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn create(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CreateIn {
            flags,
            mode,
            umask,
            open_flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        let remaining_len = (in_header.len as usize)
            .checked_sub(size_of::<InHeader>())
            .and_then(|l| l.checked_sub(size_of::<CreateIn>()))
            .ok_or(Error::InvalidHeaderLength)?;

        let mut buf = vec![0; remaining_len];

        r.read_exact(&mut buf).map_err(Error::DecodeMessage)?;
        let mut components = buf.split_inclusive(|c| *c == b'\0');
        let name = components.next().ok_or(Error::MissingParameter)?;

        let options = FsOptions::from_bits_truncate(self.options.load(Ordering::Relaxed));

        let extensions = get_extensions(options, name.len(), buf.as_slice())?;

        let kill_priv = open_flags & OPEN_KILL_SUIDGID != 0;

        match self.fs.create(
            Context::from(in_header),
            in_header.nodeid.into(),
            bytes_to_cstr(name)?,
            mode,
            kill_priv,
            flags,
            umask,
            extensions,
        ) {
            Ok((entry, handle, opts)) => {
                let entry_out = EntryOut::from(entry);
                let open_out = OpenOut {
                    fh: handle.map(Into::into).unwrap_or(0),
                    open_flags: opts.bits(),
                    ..Default::default()
                };

                // Kind of a hack to write both structs.
                reply_ok(
                    Some(entry_out),
                    Some(open_out.as_slice()),
                    in_header.unique,
                    w,
                )
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn interrupt(&self, _in_header: InHeader) -> usize {
        0
    }

    fn bmap(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.bmap() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    /// Public so the `VhostUserBackend` implementation can call this on device reset
    pub fn destroy(&self) -> usize {
        // No reply to this function.
        self.fs.destroy();
        self.options
            .store(FsOptions::empty().bits(), Ordering::Relaxed);

        0
    }

    fn ioctl(&self, in_header: InHeader, _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.ioctl() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn poll(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.poll() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn notify_reply(&self, in_header: InHeader, mut _r: Reader, w: Writer) -> Result<usize> {
        if let Err(e) = self.fs.notify_reply() {
            reply_error(e, in_header.unique, w)
        } else {
            Ok(0)
        }
    }

    fn batch_forget(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let BatchForgetIn { count, .. } = r.read_obj().map_err(Error::DecodeMessage)?;

        if let Some(size) = (count as usize).checked_mul(size_of::<ForgetOne>()) {
            if size > MAX_BUFFER_SIZE as usize {
                return reply_error(
                    io::Error::from_raw_os_error(libc::ENOMEM),
                    in_header.unique,
                    w,
                );
            }
        } else {
            return reply_error(
                io::Error::from_raw_os_error(libc::EOVERFLOW),
                in_header.unique,
                w,
            );
        }

        let mut requests = Vec::with_capacity(count as usize);
        for _ in 0..count {
            requests.push(
                r.read_obj::<ForgetOne>()
                    .map(|f| (f.nodeid.into(), f.nlookup))
                    .map_err(Error::DecodeMessage)?,
            );
        }

        self.fs.batch_forget(Context::from(in_header), requests);

        // No reply for forget messages.
        Ok(0)
    }

    fn fallocate(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let FallocateIn {
            fh,
            offset,
            length,
            mode,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.fallocate(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            mode,
            offset,
            length,
        ) {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn lseek(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let LseekIn {
            fh, offset, whence, ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.lseek(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh.into(),
            offset,
            whence,
        ) {
            Ok(offset) => {
                let out = LseekOut { offset };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn copyfilerange(&self, in_header: InHeader, mut r: Reader, w: Writer) -> Result<usize> {
        let CopyfilerangeIn {
            fh_in,
            off_in,
            nodeid_out,
            fh_out,
            off_out,
            len,
            flags,
            ..
        } = r.read_obj().map_err(Error::DecodeMessage)?;

        match self.fs.copyfilerange(
            Context::from(in_header),
            in_header.nodeid.into(),
            fh_in.into(),
            off_in,
            nodeid_out.into(),
            fh_out.into(),
            off_out,
            len,
            flags,
        ) {
            Ok(count) => {
                let out = WriteOut {
                    size: count as u32,
                    ..Default::default()
                };

                reply_ok(Some(out), None, in_header.unique, w)
            }
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn syncfs(&self, in_header: InHeader, w: Writer) -> Result<usize> {
        match self
            .fs
            .syncfs(Context::from(in_header), in_header.nodeid.into())
        {
            Ok(()) => reply_ok(None::<u8>, None, in_header.unique, w),
            Err(e) => reply_error(e, in_header.unique, w),
        }
    }

    fn tmpfile(&self, in_header: InHeader, _r: Reader, w: Writer) -> Result<usize> {
        let e = self
            .fs
            .tmpfile()
            .err()
            .unwrap_or_else(|| panic!("unsupported operation"));
        reply_error(e, in_header.unique, w)
    }
}

impl<F: FileSystem + SerializableFileSystem + Sync> SerializableFileSystem for Server<F> {
    fn prepare_serialization(&self, cancel: Arc<AtomicBool>) {
        self.fs.prepare_serialization(cancel)
    }

    fn serialize(&self, state_pipe: File) -> io::Result<()> {
        self.fs.serialize(state_pipe)
    }

    fn deserialize_and_apply(&self, state_pipe: File) -> io::Result<()> {
        self.fs.deserialize_and_apply(state_pipe)
    }
}

fn reply_readdir(len: usize, unique: u64, mut w: Writer) -> Result<usize> {
    let out = OutHeader {
        len: (size_of::<OutHeader>() + len) as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {out:?}");
    w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
    w.flush().map_err(Error::FlushMessage)?;
    Ok(out.len as usize)
}

fn reply_ok<T: ByteValued>(
    out: Option<T>,
    data: Option<&[u8]>,
    unique: u64,
    mut w: Writer,
) -> Result<usize> {
    let mut len = size_of::<OutHeader>();

    if out.is_some() {
        len += size_of::<T>();
    }

    if let Some(data) = data {
        len += data.len();
    }

    let header = OutHeader {
        len: len as u32,
        error: 0,
        unique,
    };

    debug!("Replying OK, header: {header:?}");

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    if let Some(out) = out {
        w.write_all(out.as_slice()).map_err(Error::EncodeMessage)?;
    }

    if let Some(data) = data {
        w.write_all(data).map_err(Error::EncodeMessage)?;
    }

    debug_assert_eq!(len, w.bytes_written());
    Ok(w.bytes_written())
}

fn strerror(error: i32) -> String {
    let mut err_desc: Vec<u8> = vec![0; 256];
    let buf_ptr = err_desc.as_mut_ptr() as *mut libc::c_char;

    // Safe because libc::strerror_r writes in err_desc at most err_desc.len() bytes
    unsafe {
        // We ignore the returned value since the two possible error values are:
        // EINVAL and ERANGE, in the former err_desc will be "Unknown error #"
        // and in the latter the message will be truncated to fit err_desc
        libc::strerror_r(error, buf_ptr, err_desc.len());
    }
    let err_desc = err_desc.split(|c| *c == b'\0').next().unwrap();
    String::from_utf8(err_desc.to_vec()).unwrap_or_else(|_| "".to_owned())
}

fn reply_error(e: io::Error, unique: u64, mut w: Writer) -> Result<usize> {
    let native_errno = e.raw_os_error().unwrap_or(libc::EIO);
    let header = OutHeader {
        len: size_of::<OutHeader>() as u32,
        error: -errno_to_linux(native_errno),
        unique,
    };

    debug!(
        "Replying ERROR, header: OutHeader {{ error: {} ({}), unique: {}, len: {} }}",
        header.error,
        strerror(-header.error),
        header.unique,
        header.len
    );

    w.write_all(header.as_slice())
        .map_err(Error::EncodeMessage)?;

    debug_assert_eq!(header.len as usize, w.bytes_written());
    Ok(w.bytes_written())
}

fn bytes_to_cstr(buf: &[u8]) -> Result<&CStr> {
    // Convert to a `CStr` first so that we can drop the '\0' byte at the end
    // and make sure there are no interior '\0' bytes.
    CStr::from_bytes_with_nul(buf).map_err(Error::InvalidCString)
}

fn add_dirent(
    cursor: &mut Writer,
    max: usize,
    d: DirEntry,
    entry: Option<Entry>,
) -> io::Result<usize> {
    // Strip the trailing '\0'.
    let name = d.name.to_bytes();
    if name.len() > u32::MAX as usize {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }

    let dirent_len = size_of::<Dirent>()
        .checked_add(name.len())
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    // Directory entries must be padded to 8-byte alignment.  If adding 7 causes
    // an overflow then this dirent cannot be properly padded.
    let padded_dirent_len = dirent_len
        .checked_add(7)
        .map(|l| l & !7)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

    let total_len = if entry.is_some() {
        padded_dirent_len
            .checked_add(size_of::<EntryOut>())
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?
    } else {
        padded_dirent_len
    };

    if max < total_len {
        Ok(0)
    } else {
        if let Some(entry) = entry {
            cursor.write_all(EntryOut::from(entry).as_slice())?;
        }

        let dirent = Dirent {
            ino: d.ino,
            off: d.offset,
            namelen: name.len() as u32,
            type_: d.type_,
        };

        cursor.write_all(dirent.as_slice())?;
        cursor.write_all(name)?;

        // We know that `dirent_len` <= `padded_dirent_len` due to the check above
        // so there's no need for checked arithmetic.
        let padding = padded_dirent_len - dirent_len;
        if padding > 0 {
            cursor.write_all(&DIRENT_PADDING[..padding])?;
        }

        Ok(total_len)
    }
}

fn take_object<T: ByteValued>(data: &[u8]) -> Result<(T, &[u8])> {
    if data.len() < size_of::<T>() {
        return Err(Error::DecodeMessage(einval()));
    }

    let (object_bytes, remaining_bytes) = data.split_at(size_of::<T>());
    // SAFETY: `T` implements `ByteValued` that guarantees that it is safe to instantiate
    // `T` with random data.
    let object: T = unsafe { std::ptr::read_unaligned(object_bytes.as_ptr() as *const T) };
    Ok((object, remaining_bytes))
}

fn parse_security_context(nr_secctx: u32, data: &[u8]) -> Result<Option<SecContext>> {
    // Although the FUSE security context extension allows sending several security contexts,
    // currently the guest kernel only sends one.
    if nr_secctx > 1 {
        return Err(Error::DecodeMessage(einval()));
    } else if nr_secctx == 0 {
        // No security context sent. May be no LSM supports it.
        return Ok(None);
    }

    let (secctx, data) = take_object::<Secctx>(data)?;

    if secctx.size == 0 {
        return Err(Error::DecodeMessage(einval()));
    }

    let mut components = data.split_inclusive(|c| *c == b'\0');
    let secctx_name = components.next().ok_or(Error::MissingParameter)?;
    let (_, data) = data.split_at(secctx_name.len());

    if data.len() < secctx.size as usize {
        return Err(Error::DecodeMessage(einval()));
    }

    // Fuse client aligns the whole security context block to 64 byte
    // boundary. So it is possible that after actual security context
    // of secctx.size, there are some null padding bytes left. If
    // we ever parse more data after secctx, we will have to take those
    // null bytes into account. Total size (including null bytes) is
    // available in SecctxHeader->size.
    let (remaining, _) = data.split_at(secctx.size as usize);

    let fuse_secctx = SecContext {
        name: CString::from_vec_with_nul(secctx_name.to_vec()).map_err(Error::InvalidCString2)?,
        secctx: remaining.to_vec(),
    };

    Ok(Some(fuse_secctx))
}

fn parse_sup_groups(data: &[u8]) -> Result<Vec<GuestGid>> {
    const LINUX_NRGROUPS_MAX: u32 = 65536;

    let (group_header, mut group_id_bytes) = take_object::<SuppGroups>(data)?;

    // Keep in mind that extensions are padded to 8 bytes
    // related functions in the kernel
    // `get_create_supp_group` and `fuse_ext_size` in fs/fuse/dir.c
    // `FUSE_REC_ALIGN` in include/uapi/linux/fuse.h
    if group_header.nr_groups > LINUX_NRGROUPS_MAX
        || data.len()
            != (size_of::<SuppGroups>() + size_of::<u32>() * group_header.nr_groups as usize)
                .next_multiple_of(8)
    {
        return Err(Error::DecodeMessage(einval()));
    }

    let mut groups = Vec::with_capacity(group_header.nr_groups as _);
    while groups.len() < group_header.nr_groups as usize {
        let gid;
        (gid, group_id_bytes) = take_object::<u32>(group_id_bytes)?;
        groups.push(gid.into());
    }

    Ok(groups)
}

fn get_extensions(options: FsOptions, skip: usize, request_bytes: &[u8]) -> Result<Extensions> {
    let mut extensions = Extensions::default();

    if !(options.contains(FsOptions::SECURITY_CTX)
        || options.contains(FsOptions::CREATE_SUPP_GROUP))
    {
        return Ok(extensions);
    }

    // It's not guaranty to receive an extension even if it's supported by the guest kernel
    if request_bytes.len() < skip {
        return Err(Error::DecodeMessage(einval()));
    }

    // We need to track if a SecCtx was received, because it's valid
    // for the guest to send an empty SecCtx (i.e, nr_secctx == 0)
    let mut secctx_received = false;

    let mut buf = &request_bytes[skip..];
    while !buf.is_empty() {
        let (extension_header, remaining_bytes) = take_object::<ExtHeader>(buf)?;

        let extension_size = (extension_header.size as usize)
            .checked_sub(size_of::<ExtHeader>())
            .ok_or(Error::InvalidHeaderLength)?;

        let (current_extension_bytes, next_extension_bytes) =
            remaining_bytes.split_at(extension_size);

        let ext_type = ExtType::try_from(extension_header.ext_type)
            .map_err(|_| Error::DecodeMessage(einval()))?;

        match ext_type {
            ExtType::SecCtx(nr_secctx) => {
                if !options.contains(FsOptions::SECURITY_CTX) || secctx_received {
                    return Err(Error::DecodeMessage(einval()));
                }

                secctx_received = true;
                extensions.secctx = parse_security_context(nr_secctx, current_extension_bytes)?;
                debug!("Extension received: {nr_secctx} SecCtx");
            }
            ExtType::SupGroups => {
                if !options.contains(FsOptions::CREATE_SUPP_GROUP)
                    || !extensions.sup_gids.is_empty()
                {
                    return Err(Error::DecodeMessage(einval()));
                }

                extensions.sup_gids = parse_sup_groups(current_extension_bytes)?;
                debug!("Extension received: SupGroups({:?})", extensions.sup_gids);
            }
        }

        // Let's process the next extension
        buf = next_extension_bytes;
    }

    // The SupGroup extension can be missing, since it is only sent if needed.
    // A SecCtx is always sent in create/synlink/mknod/mkdir if supported.
    if options.contains(FsOptions::SECURITY_CTX) && !secctx_received {
        return Err(Error::MissingExtension);
    }

    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Linux, errno values match the FUSE wire protocol — translation is a no-op.
    #[cfg(target_os = "linux")]
    #[test]
    fn errno_to_linux_is_identity_on_linux() {
        for v in [
            libc::EPERM,
            libc::ENOENT,
            libc::EAGAIN,
            libc::EOPNOTSUPP,
            libc::ENETRESET,
            libc::ECONNREFUSED,
            libc::ENODATA,
            libc::EOWNERDEAD,
        ] {
            assert_eq!(
                errno_to_linux(v),
                v,
                "errno {v} should pass through on Linux"
            );
        }
    }

    /// macOS-side values that share the 1..=34 range with Linux (EPERM..ERANGE)
    /// must pass through unchanged. If anyone ever "helpfully" adds a remap for
    /// one of these, it silently corrupts the most common errors guests see.
    #[cfg(target_os = "macos")]
    #[test]
    fn errno_to_linux_low_range_is_identity() {
        for v in 1..=34 {
            assert_eq!(
                errno_to_linux(v),
                v,
                "errno {v} (low range) must pass through unchanged"
            );
        }
    }

    /// Authoritative table of `(macOS_errno, Linux_errno, name)` triples used
    /// by the `errno_to_linux` regression test. If you change `errno_to_linux`,
    /// update this table — and only this table — and CI catches any drift.
    ///
    /// macOS values are taken from `<sys/errno.h>` shipped with the Command
    /// Line Tools; Linux values from `<asm-generic/errno.h>`. Never hand-edit
    /// either column without cross-checking those headers.
    #[cfg(target_os = "macos")]
    const ERRNO_MAP: &[(i32, i32, &str)] = &[
        (35, 11, "EAGAIN"),
        (36, 115, "EINPROGRESS"),
        (37, 114, "EALREADY"),
        (38, 88, "ENOTSOCK"),
        (39, 89, "EDESTADDRREQ"),
        (40, 90, "EMSGSIZE"),
        (41, 91, "EPROTOTYPE"),
        (42, 92, "ENOPROTOOPT"),
        (43, 93, "EPROTONOSUPPORT"),
        (44, 94, "ESOCKTNOSUPPORT"),
        (45, 95, "ENOTSUP/EOPNOTSUPP_POSIX"),
        (46, 96, "EPFNOSUPPORT"),
        (47, 97, "EAFNOSUPPORT"),
        (48, 98, "EADDRINUSE"),
        (49, 99, "EADDRNOTAVAIL"),
        (50, 100, "ENETDOWN"),
        (51, 101, "ENETUNREACH"),
        (52, 102, "ENETRESET"),
        (53, 103, "ECONNABORTED"),
        (54, 104, "ECONNRESET"),
        (55, 105, "ENOBUFS"),
        (56, 106, "EISCONN"),
        (57, 107, "ENOTCONN"),
        (58, 108, "ESHUTDOWN"),
        (59, 109, "ETOOMANYREFS"),
        (60, 110, "ETIMEDOUT"),
        (61, 111, "ECONNREFUSED"),
        (62, 40, "ELOOP"),
        (63, 36, "ENAMETOOLONG"),
        (64, 112, "EHOSTDOWN"),
        (65, 113, "EHOSTUNREACH"),
        (66, 39, "ENOTEMPTY"),
        (69, 122, "EDQUOT"),
        (70, 116, "ESTALE"),
        (77, 37, "ENOLCK"),
        (78, 38, "ENOSYS"),
        (84, 75, "EOVERFLOW"),
        (89, 125, "ECANCELED"),
        (90, 43, "EIDRM"),
        (91, 42, "ENOMSG"),
        (92, 84, "EILSEQ"),
        (93, 61, "ENOATTR -> ENODATA"),
        (94, 74, "EBADMSG"),
        (95, 72, "EMULTIHOP"),
        (96, 61, "ENODATA"),
        (97, 67, "ENOLINK"),
        (98, 63, "ENOSR"),
        (99, 60, "ENOSTR"),
        (100, 71, "EPROTO"),
        (101, 62, "ETIME"),
        (102, 95, "EOPNOTSUPP_BSD"),
        (104, 131, "ENOTRECOVERABLE"),
        (105, 130, "EOWNERDEAD"),
    ];

    #[cfg(target_os = "macos")]
    #[test]
    fn errno_to_linux_table() {
        for &(mac_errno, linux_errno, name) in ERRNO_MAP {
            assert_eq!(
                errno_to_linux(mac_errno),
                linux_errno,
                "macOS {name} (errno {mac_errno}) must translate to Linux {linux_errno}"
            );
        }
    }

    /// Specific regressions worth pinning so reading the test list tells the
    /// story of what previously broke.
    #[cfg(target_os = "macos")]
    #[test]
    fn errno_to_linux_eopnotsupp_is_not_enetreset() {
        // libc::EOPNOTSUPP on Darwin is the BSD-flavor 102. Without an
        // explicit entry it falls through unchanged, and Linux reads 102 as
        // ENETRESET ("Network dropped connection on reset"). That's the
        // exact bug that broke `qemu-img convert` over virtio-fs.
        assert_eq!(libc::EOPNOTSUPP, 102);
        assert_eq!(errno_to_linux(libc::EOPNOTSUPP), 95);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn errno_to_linux_enoattr_becomes_enodata() {
        // APFS returns ENOATTR (93) for missing xattrs. On Linux the FUSE
        // expectation is ENODATA (61). Without translation, `ls -la`
        // probing for `security.selinux` / `system.posix_acl_access`
        // sees Linux 93=EPROTONOSUPPORT and falls into a slow error path.
        assert_eq!(errno_to_linux(93), 61);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn errno_to_linux_macos_only_codes_pass_through() {
        // EAUTH (80), ENEEDAUTH (81), EPWROFF (82), EDEVERR (83),
        // EBADEXEC (85), EBADARCH (86), ESHLIBVERS (87), EBADMACHO (88),
        // ENOPOLICY (103), EQFULL (106). None has a meaningful Linux peer;
        // pass through and let the guest see the raw value.
        for v in [80, 81, 82, 83, 85, 86, 87, 88, 103, 106] {
            assert_eq!(
                errno_to_linux(v),
                v,
                "macOS-only errno {v} must pass through unchanged"
            );
        }
    }
}
