// In-process integration tests that drive the `PassthroughFs` FUSE `FileSystem`
// implementation directly against a real macOS temp directory.
//
// There is NO VM, NO daemon, NO vhost-user socket here: we construct a
// `PassthroughFs` rooted at a `tempfile::TempDir`, call `init()` once, and then
// invoke the `FileSystem` trait methods exactly as `server.rs` would, but purely
// in-process. This exercises the macOS-specific passthrough code paths
// (getdirentries64 paging, O_SYMLINK, xattr syscalls, ...) without a guest.
//
// The whole file is gated to macOS: it asserts macOS-native behaviour (e.g. the
// raw errno returned by the xattr syscalls) and is meaningless on Linux.
#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use tempfile::TempDir;

use virtiofsd::filesystem::{
    Context, DirectoryIterator, Extensions, FileSystem, GetxattrReply, ListxattrReply,
    SetxattrFlags, ZeroCopyReader, ZeroCopyWriter,
};
use virtiofsd::fuse::{FsOptions, ROOT_ID};
use virtiofsd::oslib::{ReadvFlags, WritevFlags};
use virtiofsd::passthrough::{Config, InodeFileHandlesMode, PassthroughFs};
use virtiofsd::soft_idmap::{GuestGid, GuestUid};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `Context` whose uid/gid match the current process's *effective*
/// uid/gid. This is mandatory: `PassthroughFs` impersonates the guest via
/// seteuid/setegid per request, and as a non-root test process that only works
/// (as a no-op) when the requested ids already equal our effective ids.
fn current_ctx() -> Context {
    // Safe: geteuid/getegid never fail.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    Context {
        uid: GuestUid::from(uid),
        gid: GuestGid::from(gid),
        pid: 0,
    }
}

/// Create a fixture temp dir, build a `PassthroughFs` rooted at it, run `init()`
/// once, and return both. `xattr` is enabled so the xattr tests work; it is
/// harmless for the others.
fn setup() -> (TempDir, PassthroughFs) {
    let dir = TempDir::new().expect("create temp dir");
    let root = dir.path().to_str().expect("temp path is utf-8").to_string();

    let cfg = Config {
        root_dir: root,
        inode_file_handles: InodeFileHandlesMode::Never,
        xattr: true,
        ..Default::default()
    };

    let fs = PassthroughFs::new(cfg).expect("PassthroughFs::new");
    fs.init(FsOptions::empty()).expect("fs.init");
    (dir, fs)
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no interior nul")
}

/// Look up `name` under `parent`, returning the resulting inode.
fn lookup_inode(fs: &PassthroughFs, parent: u64, name: &str) -> u64 {
    let entry = fs
        .lookup(current_ctx(), parent, cstr(name).as_c_str())
        .unwrap_or_else(|e| panic!("lookup {:?} failed: {}", name, e));
    entry.inode
}

// ---------------------------------------------------------------------------
// In-memory ZeroCopy shims for the read/write path.
//
// `PassthroughFs::write` calls `ZeroCopyReader::write_to_file_at` (guest -> file)
// and `PassthroughFs::read` calls `ZeroCopyWriter::read_from_file_at`
// (file -> guest). Both use `pwrite`/`pread` under the hood so the fd offset is
// untouched. We pass `&mut shim` to `fs.read`/`fs.write` (the blanket
// `impl ZeroCopy* for &mut T` in filesystem.rs makes that a valid `W`/`R`),
// so the shim is only borrowed and its buffer/cursor remain inspectable after
// the call.
// ---------------------------------------------------------------------------

/// Source of bytes copied into a file (models the guest payload of a write).
struct VecReader {
    data: Vec<u8>,
    pos: usize,
}

impl ZeroCopyReader for VecReader {
    fn write_to_file_at(
        &mut self,
        f: &File,
        count: usize,
        off: u64,
        _flags: Option<WritevFlags>,
    ) -> io::Result<usize> {
        let n = count.min(self.data.len() - self.pos);
        // Safe: writing `n` bytes from an owned buffer to a valid fd.
        let w = unsafe {
            libc::pwrite(
                f.as_raw_fd(),
                self.data[self.pos..].as_ptr() as *const libc::c_void,
                n,
                off as libc::off_t,
            )
        };
        if w < 0 {
            return Err(io::Error::last_os_error());
        }
        self.pos += w as usize;
        Ok(w as usize)
    }
}

/// Sink of bytes copied out of a file (models the guest buffer of a read).
struct VecWriter {
    data: Vec<u8>,
}

impl ZeroCopyWriter for VecWriter {
    fn read_from_file_at(
        &mut self,
        f: &File,
        count: usize,
        off: u64,
        _flags: Option<ReadvFlags>,
    ) -> io::Result<usize> {
        let mut buf = vec![0u8; count];
        // Safe: reading up to `count` bytes from a valid fd into an owned buffer.
        let r = unsafe {
            libc::pread(
                f.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                count,
                off as libc::off_t,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        self.data.extend_from_slice(&buf[..r as usize]);
        Ok(r as usize)
    }
}

/// Look up (creating first via host `std::fs` if needed) and open a file for
/// read/write, returning `(inode, handle)`.
fn open_rdwr(fs: &PassthroughFs, name: &str) -> (u64, u64) {
    let inode = lookup_inode(fs, ROOT_ID, name);
    let (handle_opt, _opts) = fs
        .open(current_ctx(), inode, false, libc::O_RDWR as u32)
        .expect("open O_RDWR");
    let handle = handle_opt.expect("open returned a handle");
    (inode, handle)
}

/// Page through an entire directory the way the FUSE server does: repeatedly
/// call `readdir`, consuming at most `PAGE` entries per call, tracking the last
/// entry offset, and re-calling `readdir` with that offset until a call yields
/// no entries. Returns every entry name seen (including "." / "..").
fn read_all_dir_names(fs: &PassthroughFs, inode: u64) -> Vec<CString> {
    // Cap entries consumed per readdir call so that the skip/offset logic is
    // actually exercised across multiple pages (the macOS `ReadDir` reads the
    // whole directory each call and skips `offset` entries by count). 137 is
    // deliberately not a divisor of 500 so partial final pages are hit.
    const PAGE: usize = 137;

    let ctx = current_ctx();
    let (handle_opt, _opts) = fs.opendir(ctx, inode, 0).expect("opendir");
    let handle = handle_opt.expect("opendir returned a handle");

    let mut names = Vec::new();
    let mut offset: u64 = 0;
    loop {
        let mut rd = fs
            .readdir(ctx, inode, handle, 4096, offset)
            .expect("readdir");
        let mut got_any = false;
        let mut n = 0;
        while n < PAGE {
            match DirectoryIterator::next(&mut rd) {
                Some(entry) => {
                    got_any = true;
                    offset = entry.offset;
                    names.push(entry.name.to_owned());
                    n += 1;
                }
                None => break,
            }
        }
        if !got_any {
            break;
        }
    }

    fs.releasedir(ctx, inode, 0, handle).expect("releasedir");
    names
}

// ---------------------------------------------------------------------------
// Test 1: construction succeeds
// ---------------------------------------------------------------------------

#[test]
fn new_succeeds_against_temp_root() {
    // Would have caught the ENOSYS-at-startup regression: `PassthroughFs::new`
    // probes file-handle support, which must be forced off on macOS.
    let dir = TempDir::new().expect("temp dir");
    let cfg = Config {
        root_dir: dir.path().to_str().unwrap().to_string(),
        inode_file_handles: InodeFileHandlesMode::Never,
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).expect("PassthroughFs::new must succeed on macOS");
    fs.init(FsOptions::empty())
        .expect("init must succeed on macOS");
}

// ---------------------------------------------------------------------------
// Test 2: lookup hit and miss
// ---------------------------------------------------------------------------

#[test]
fn lookup_hit_and_miss() {
    let (dir, fs) = setup();
    fs::write(dir.path().join("present.txt"), b"hi").unwrap();

    let entry = fs
        .lookup(current_ctx(), ROOT_ID, cstr("present.txt").as_c_str())
        .expect("lookup of existing file");
    assert_ne!(entry.inode, 0, "existing file must have a non-zero inode");

    let miss = fs.lookup(current_ctx(), ROOT_ID, cstr("nope.txt").as_c_str());
    // `Entry` does not implement `Debug`, so use `.err()` rather than `expect_err`.
    let err = miss.err().expect("lookup of missing file must fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "missing lookup must be ENOENT, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: getattr reports the correct size
// ---------------------------------------------------------------------------

#[test]
fn getattr_reports_size() {
    let (dir, fs) = setup();
    let contents = b"hello world!"; // 12 bytes
    fs::write(dir.path().join("sized.txt"), contents).unwrap();

    let inode = lookup_inode(&fs, ROOT_ID, "sized.txt");
    let (attr, _timeout) = fs
        .getattr(current_ctx(), inode, None)
        .expect("getattr on file");
    assert_eq!(
        attr.size,
        contents.len() as u64,
        "getattr size must match bytes written"
    );
}

// ---------------------------------------------------------------------------
// Test 4: readdir returns all ~500 entries with no dupes / truncation
// ---------------------------------------------------------------------------

#[test]
fn readdir_returns_all_500_entries() {
    let (dir, fs) = setup();

    let big = dir.path().join("bigdir");
    fs::create_dir(&big).unwrap();
    const N: usize = 500;
    let mut expected: Vec<String> = Vec::with_capacity(N);
    for i in 0..N {
        let name = format!("file_{i:04}");
        fs::write(big.join(&name), b"").unwrap();
        expected.push(name);
    }

    let inode = lookup_inode(&fs, ROOT_ID, "bigdir");
    let raw = read_all_dir_names(&fs, inode);

    // Drop "." and ".." and convert to owned Strings.
    let mut got: Vec<String> = raw
        .iter()
        .filter_map(|c| c.to_str().ok())
        .filter(|n| *n != "." && *n != "..")
        .map(|n| n.to_string())
        .collect();

    // No duplicates.
    let mut deduped = got.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        got.len(),
        "readdir returned duplicate entries ({} raw vs {} unique)",
        got.len(),
        deduped.len()
    );

    // Exactly the 500 files we created, no truncation.
    got.sort();
    expected.sort();
    assert_eq!(
        got.len(),
        N,
        "expected {N} entries, got {} (truncation/paging bug)",
        got.len()
    );
    assert_eq!(got, expected, "readdir entry set mismatch");
}

// ---------------------------------------------------------------------------
// Test 5: xattr set/get roundtrip + missing-xattr errno
// ---------------------------------------------------------------------------

#[test]
fn setxattr_getxattr_roundtrip_and_missing_errno() {
    let (dir, fs) = setup();
    fs::write(dir.path().join("xattr.txt"), b"body").unwrap();
    let inode = lookup_inode(&fs, ROOT_ID, "xattr.txt");
    let ctx = current_ctx();

    let name = cstr("user.testattr");
    let value = b"the-value";

    fs.setxattr(
        ctx,
        inode,
        name.as_c_str(),
        value,
        0,
        SetxattrFlags::empty(),
    )
    .expect("setxattr");

    // Read it back: pass a generous size so we get the Value variant.
    let reply = fs
        .getxattr(ctx, inode, name.as_c_str(), 256)
        .expect("getxattr");
    match reply {
        GetxattrReply::Value(v) => assert_eq!(v, value, "xattr value roundtrip mismatch"),
        GetxattrReply::Count(c) => panic!("expected Value, got Count({})", c),
    }

    // Missing xattr. Driving `PassthroughFs` directly returns the *native*
    // macOS errno straight from `fgetxattr`, i.e. ENOATTR (93). The
    // Linux-facing translation to ENODATA (61) that the task references lives
    // in `server.rs::errno_to_linux` and is applied only when the reply is
    // marshalled back to the guest -- it is NOT part of `PassthroughFs`, so it
    // cannot be observed in-process. See the test report for details.
    let missing = fs.getxattr(ctx, inode, cstr("user.does_not_exist").as_c_str(), 256);
    // `GetxattrReply` does not implement `Debug`; use `.err()`.
    let err = missing.err().expect("getxattr of missing attr must fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOATTR),
        "missing xattr should surface native macOS ENOATTR (93) at the \
         PassthroughFs layer; server.rs::errno_to_linux later maps 93 -> 61 \
         (Linux ENODATA) before it reaches the guest. Got {err}"
    );
    // Guard the specific numbers the task cares about so the intent is explicit.
    assert_eq!(libc::ENOATTR, 93, "macOS ENOATTR is 93");
    assert_ne!(
        err.raw_os_error(),
        Some(61),
        "not yet translated in-process"
    );
}

// ---------------------------------------------------------------------------
// Test 6: listxattr sees the attribute we set
// ---------------------------------------------------------------------------

#[test]
fn listxattr_lists_set_attr() {
    let (dir, fs) = setup();
    fs::write(dir.path().join("listed.txt"), b"body").unwrap();
    let inode = lookup_inode(&fs, ROOT_ID, "listed.txt");
    let ctx = current_ctx();

    let name = cstr("user.listme");
    fs.setxattr(ctx, inode, name.as_c_str(), b"v", 0, SetxattrFlags::empty())
        .expect("setxattr");

    let reply = fs.listxattr(ctx, inode, 4096).expect("listxattr");
    let names: Vec<String> = match reply {
        ListxattrReply::Names(buf) => buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
        ListxattrReply::Count(c) => panic!("expected Names, got Count({})", c),
    };
    assert!(
        names.iter().any(|n| n == "user.listme"),
        "listxattr must include the attr we set; got {:?}",
        names
    );
}

// ---------------------------------------------------------------------------
// Test 7: symlink + readlink roundtrip; attr shows S_IFLNK
// ---------------------------------------------------------------------------

#[test]
fn symlink_readlink_roundtrip() {
    let (dir, fs) = setup();
    // Create the target so the link is not dangling (not strictly required).
    fs::write(dir.path().join("target.txt"), b"target body").unwrap();
    let ctx = current_ctx();

    let target = cstr("target.txt");
    let linkname = cstr("mylink");
    let entry = fs
        .symlink(
            ctx,
            target.as_c_str(),
            ROOT_ID,
            linkname.as_c_str(),
            Extensions::default(),
        )
        .expect("symlink");

    // The Entry returned by symlink() must already describe a symlink.
    assert_eq!(
        entry.attr.mode & (libc::S_IFMT as u32),
        libc::S_IFLNK as u32,
        "symlink entry attr must be S_IFLNK"
    );

    // readlink must round-trip the target.
    let got = fs.readlink(ctx, entry.inode).expect("readlink");
    assert_eq!(
        got,
        target.as_bytes(),
        "readlink target mismatch: {:?}",
        String::from_utf8_lossy(&got)
    );

    // A fresh lookup of the symlink must also report S_IFLNK (i.e. we did not
    // follow the link).
    let looked = fs
        .lookup(ctx, ROOT_ID, linkname.as_c_str())
        .expect("lookup symlink");
    assert_eq!(
        looked.attr.mode & (libc::S_IFMT as u32),
        libc::S_IFLNK as u32,
        "lookup of symlink must report S_IFLNK"
    );
}

// ---------------------------------------------------------------------------
// Test 8: mkdir / rename / unlink lifecycle
// ---------------------------------------------------------------------------

#[test]
fn mkdir_rename_unlink_lifecycle() {
    let (dir, fs) = setup();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("b.txt"), b"b").unwrap();
    let ctx = current_ctx();

    // mkdir + lookup confirms the new directory.
    let mkdir_entry = fs
        .mkdir(
            ctx,
            ROOT_ID,
            cstr("newdir").as_c_str(),
            0o755,
            0,
            Extensions::default(),
        )
        .expect("mkdir");
    assert_eq!(
        mkdir_entry.attr.mode & (libc::S_IFMT as u32),
        libc::S_IFDIR as u32,
        "mkdir entry must be a directory"
    );
    let looked = fs
        .lookup(ctx, ROOT_ID, cstr("newdir").as_c_str())
        .expect("lookup newdir");
    assert_eq!(
        looked.attr.mode & (libc::S_IFMT as u32),
        libc::S_IFDIR as u32,
        "looked-up newdir must be a directory"
    );

    // rename a.txt -> a2.txt.
    fs.rename(
        ctx,
        ROOT_ID,
        cstr("a.txt").as_c_str(),
        ROOT_ID,
        cstr("a2.txt").as_c_str(),
        0,
    )
    .expect("rename");
    fs.lookup(ctx, ROOT_ID, cstr("a2.txt").as_c_str())
        .expect("renamed target must exist");
    let old = fs.lookup(ctx, ROOT_ID, cstr("a.txt").as_c_str());
    assert_eq!(
        old.err().expect("old name must be gone").raw_os_error(),
        Some(libc::ENOENT),
        "lookup of renamed-away name must be ENOENT"
    );

    // unlink b.txt, then confirm it's gone.
    fs.unlink(ctx, ROOT_ID, cstr("b.txt").as_c_str())
        .expect("unlink");
    let gone = fs.lookup(ctx, ROOT_ID, cstr("b.txt").as_c_str());
    assert_eq!(
        gone.err()
            .expect("unlinked file must be gone")
            .raw_os_error(),
        Some(libc::ENOENT),
        "lookup of unlinked file must be ENOENT"
    );
}

// ---------------------------------------------------------------------------
// Test 9: write then read roundtrip through the real pwrite/pread path
// ---------------------------------------------------------------------------

#[test]
fn write_then_read_roundtrip() {
    let (dir, fs) = setup();
    let path = dir.path().join("rw.txt");
    fs::write(&path, b"").unwrap(); // create empty file
    let ctx = current_ctx();
    let (inode, handle) = open_rdwr(&fs, "rw.txt");

    let payload = b"hello virtiofs\n";
    let mut reader = VecReader {
        data: payload.to_vec(),
        pos: 0,
    };
    let written = fs
        .write(
            ctx,
            inode,
            handle,
            &mut reader,
            payload.len() as u32,
            0,
            None,
            false,
            false,
            0,
        )
        .expect("write");
    assert_eq!(written, payload.len(), "write must report full length");

    // (a) Verify via the real host file.
    let on_disk = fs::read(&path).expect("read back from host");
    assert_eq!(on_disk, payload, "on-disk bytes must match what we wrote");

    // (b) Verify via fs.read into a VecWriter.
    let mut writer = VecWriter { data: Vec::new() };
    let got = fs
        .read(
            ctx,
            inode,
            handle,
            &mut writer,
            payload.len() as u32,
            0,
            None,
            0,
        )
        .expect("read");
    assert_eq!(got, payload.len(), "read must report full length");
    assert_eq!(
        writer.data, payload,
        "fs.read bytes must match what we wrote"
    );

    fs.release(ctx, inode, 0, handle, false, false, None).ok();
}

// ---------------------------------------------------------------------------
// Test 10: write at a non-zero offset leaves a zero hole before it
// ---------------------------------------------------------------------------

#[test]
fn write_at_nonzero_offset() {
    let (dir, fs) = setup();
    let path = dir.path().join("hole.txt");
    fs::write(&path, b"").unwrap();
    let ctx = current_ctx();
    let (inode, handle) = open_rdwr(&fs, "hole.txt");

    const OFF: u64 = 8;
    let payload = b"XYZW"; // 4 bytes at offset 8
    let mut reader = VecReader {
        data: payload.to_vec(),
        pos: 0,
    };
    let written = fs
        .write(
            ctx,
            inode,
            handle,
            &mut reader,
            payload.len() as u32,
            OFF,
            None,
            false,
            false,
            0,
        )
        .expect("write at offset");
    assert_eq!(written, payload.len());

    // File must now be OFF + payload.len() bytes long.
    let on_disk = fs::read(&path).expect("read back");
    assert_eq!(
        on_disk.len() as u64,
        OFF + payload.len() as u64,
        "file size must be offset + written length"
    );
    // A hole of zeros precedes the data.
    assert_eq!(
        &on_disk[..OFF as usize],
        &[0u8; OFF as usize],
        "hole must be zeros"
    );
    // The payload lands exactly at OFF.
    assert_eq!(
        &on_disk[OFF as usize..],
        payload,
        "payload must land at offset"
    );

    // Confirm the same via fs.read at the offset.
    let mut writer = VecWriter { data: Vec::new() };
    let got = fs
        .read(
            ctx,
            inode,
            handle,
            &mut writer,
            payload.len() as u32,
            OFF,
            None,
            0,
        )
        .expect("read at offset");
    assert_eq!(got, payload.len());
    assert_eq!(
        writer.data, payload,
        "fs.read at offset must return payload"
    );

    fs.release(ctx, inode, 0, handle, false, false, None).ok();
}

// ---------------------------------------------------------------------------
// Test 11: large (128 KiB) write + read, exercising the short-copy loop
// ---------------------------------------------------------------------------

#[test]
fn large_write_read_128k() {
    let (dir, fs) = setup();
    let path = dir.path().join("big.bin");
    fs::write(&path, b"").unwrap();
    let ctx = current_ctx();
    let (inode, handle) = open_rdwr(&fs, "big.bin");

    const LEN: usize = 128 * 1024;
    // Known, non-trivial pattern so any misplacement is caught.
    let pattern: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();

    // Write, looping in case a single write_to_file_at reports a short count.
    // `&mut reader` persists `pos` across calls; we advance the file offset in
    // lockstep.
    let mut reader = VecReader {
        data: pattern.clone(),
        pos: 0,
    };
    let mut off: u64 = 0;
    while reader.pos < reader.data.len() {
        let remaining = (reader.data.len() - reader.pos) as u32;
        let n = fs
            .write(
                ctx,
                inode,
                handle,
                &mut reader,
                remaining,
                off,
                None,
                false,
                false,
                0,
            )
            .expect("large write");
        assert!(n > 0, "write made no progress");
        off += n as u64;
    }
    assert_eq!(off as usize, LEN, "total bytes written must equal LEN");

    // Read back, looping on short reads.
    let mut writer = VecWriter { data: Vec::new() };
    let mut roff: u64 = 0;
    while writer.data.len() < LEN {
        let remaining = (LEN - writer.data.len()) as u32;
        let n = fs
            .read(ctx, inode, handle, &mut writer, remaining, roff, None, 0)
            .expect("large read");
        if n == 0 {
            break; // EOF
        }
        roff += n as u64;
    }
    assert_eq!(writer.data.len(), LEN, "read-back length must equal LEN");
    assert_eq!(writer.data, pattern, "128k roundtrip must be byte-exact");

    fs.release(ctx, inode, 0, handle, false, false, None).ok();
}
