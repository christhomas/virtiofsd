// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Translation of the open(2) flags a guest sends into the host's own.
//!
//! The FUSE kernel module forwards the guest's `file->f_flags` as they are, so
//! they are encoded in the Linux values of the *guest's* architecture. Most open
//! flags have the same value on every Linux architecture, but four do not: arm64
//! moves `O_DIRECTORY`, `O_NOFOLLOW`, `O_DIRECT` and `O_LARGEFILE` away from the
//! generic values that x86_64 uses (`arch/arm64/include/uapi/asm/fcntl.h`
//! against `include/uapi/asm-generic/fcntl.h`):
//!
//! | flag          | x86_64     | aarch64    |
//! |---------------|------------|------------|
//! | `O_DIRECTORY` | `0o200000` | `0o40000`  |
//! | `O_NOFOLLOW`  | `0o400000` | `0o100000` |
//! | `O_DIRECT`    | `0o40000`  | `0o200000` |
//! | `O_LARGEFILE` | `0o100000` | `0o400000` |
//!
//! Decoding an arm64 guest's flags with the x86_64 values reads its `O_DIRECT`
//! as `O_DIRECTORY`, so the host's open of a regular file fails with `ENOTDIR`,
//! and its `O_LARGEFILE`, which a 64-bit kernel sets on every open, as
//! `O_NOFOLLOW`.
//!
//! Nothing in the FUSE handshake says which architecture the guest is, so it is
//! configured (`--guest-arch`). It defaults to the host's own, which is always
//! right for a guest under hardware virtualization.

use std::fmt;
use std::str::FromStr;

/// The architecture of the guest's Linux kernel, which fixes the numeric values
/// of the open flags it sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestArch {
    /// x86_64, which uses the generic Linux values.
    X86_64,
    /// aarch64 (arm64).
    Aarch64,
}

impl GuestArch {
    /// The host's own architecture: the default, and the only possibility for a
    /// guest under hardware virtualization.
    ///
    /// A host that is neither aarch64 nor x86_64 is given `X86_64`, whose values
    /// are the generic ones. On a Linux host that guest's flags then pass through
    /// unchanged, which is the behaviour a native guest needs.
    #[cfg(target_arch = "aarch64")]
    pub const HOST: GuestArch = GuestArch::Aarch64;
    /// The host's own architecture: the default, and the only possibility for a
    /// guest under hardware virtualization.
    #[cfg(not(target_arch = "aarch64"))]
    pub const HOST: GuestArch = GuestArch::X86_64;

    /// The values of the four open flags that differ between architectures.
    fn flags(self) -> ArchOpenFlags {
        match self {
            GuestArch::X86_64 => ArchOpenFlags {
                direct: 0o40000,
                largefile: 0o100000,
                directory: 0o200000,
                nofollow: 0o400000,
            },
            GuestArch::Aarch64 => ArchOpenFlags {
                direct: 0o200000,
                largefile: 0o400000,
                directory: 0o40000,
                nofollow: 0o100000,
            },
        }
    }
}

impl Default for GuestArch {
    fn default() -> Self {
        GuestArch::HOST
    }
}

impl FromStr for GuestArch {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "x86_64" | "amd64" => Ok(GuestArch::X86_64),
            "aarch64" | "arm64" => Ok(GuestArch::Aarch64),
            _ => Err("invalid guest-arch value (expected x86_64 or aarch64)"),
        }
    }
}

impl fmt::Display for GuestArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GuestArch::X86_64 => "x86_64",
            GuestArch::Aarch64 => "aarch64",
        })
    }
}

/// The four Linux open flags whose values depend on the architecture.
#[derive(Clone, Copy)]
struct ArchOpenFlags {
    direct: i32,
    largefile: i32,
    directory: i32,
    nofollow: i32,
}

impl ArchOpenFlags {
    /// Every bit any of the four occupies. The architectures permute the same
    /// four bits, so this is the same mask for each.
    fn mask(self) -> i32 {
        self.direct | self.largefile | self.directory | self.nofollow
    }
}

/// The Linux open flags that have the same value on every architecture this
/// module knows (`include/uapi/asm-generic/fcntl.h`).
pub(crate) mod linux {
    pub const O_ACCMODE: i32 = 0o3;
    pub const O_RDONLY: i32 = 0o0;
    pub const O_WRONLY: i32 = 0o1;
    pub const O_RDWR: i32 = 0o2;
    pub const O_CREAT: i32 = 0o100;
    pub const O_EXCL: i32 = 0o200;
    pub const O_NOCTTY: i32 = 0o400;
    pub const O_TRUNC: i32 = 0o1000;
    pub const O_APPEND: i32 = 0o2000;
    pub const O_NONBLOCK: i32 = 0o4000;
    pub const O_DSYNC: i32 = 0o10000;
    pub const O_CLOEXEC: i32 = 0o2000000;
    /// `__O_SYNC | O_DSYNC`: two bits, of which `O_DSYNC` alone is one.
    pub const O_SYNC: i32 = 0o4010000;
    pub const O_PATH: i32 = 0o10000000;
    /// One of `O_TMPFILE`'s two bits. The other is `O_DIRECTORY`, whose value
    /// depends on the architecture.
    pub const __O_TMPFILE: i32 = 0o20000000;
}

/// Darwin's open(2) flag values (`<sys/fcntl.h>`).
///
/// They are spelled out rather than taken from `libc` so that the translation
/// is a pure function, testable on any host. A macOS-only test pins each one to
/// `libc`'s.
pub mod darwin {
    pub const O_RDONLY: i32 = 0x0000;
    pub const O_WRONLY: i32 = 0x0001;
    pub const O_RDWR: i32 = 0x0002;
    pub const O_NONBLOCK: i32 = 0x0004;
    pub const O_APPEND: i32 = 0x0008;
    pub const O_SYNC: i32 = 0x0080;
    pub const O_NOFOLLOW: i32 = 0x0100;
    pub const O_CREAT: i32 = 0x0200;
    pub const O_TRUNC: i32 = 0x0400;
    pub const O_EXCL: i32 = 0x0800;
    pub const O_NOCTTY: i32 = 0x0002_0000;
    pub const O_DIRECTORY: i32 = 0x0010_0000;
    pub const O_DSYNC: i32 = 0x0040_0000;
    pub const O_CLOEXEC: i32 = 0x0100_0000;
}

/// A guest's open flags, translated for the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostOpenFlags {
    /// The flags to pass to the host's open(2).
    pub flags: i32,
    /// The guest asked for `O_DIRECT`, which the host's open(2) cannot express.
    /// The caller turns the page cache off on the new descriptor instead
    /// (`F_NOCACHE` on macOS). Always `false` on Linux, where `O_DIRECT` stays
    /// in `flags`.
    pub nocache: bool,
}

/// Translate a Linux guest's open flags into Darwin's.
///
/// `O_DIRECT` has no Darwin open flag and is reported in `nocache`. `O_NOATIME`
/// and `O_LARGEFILE` have no Darwin meaning and are dropped, as is any other bit
/// this table does not name.
pub fn linux_to_darwin_open_flags(linux_flags: i32, guest: GuestArch) -> HostOpenFlags {
    let arch = guest.flags();

    let mut flags = match linux_flags & linux::O_ACCMODE {
        linux::O_RDONLY => darwin::O_RDONLY,
        linux::O_WRONLY => darwin::O_WRONLY,
        linux::O_RDWR => darwin::O_RDWR,
        // The fourth access mode is not one open(2) accepts; read-only is the
        // conservative reading.
        _ => darwin::O_RDONLY,
    };

    let table = [
        (linux::O_CREAT, darwin::O_CREAT),
        (linux::O_EXCL, darwin::O_EXCL),
        (linux::O_NOCTTY, darwin::O_NOCTTY),
        (linux::O_TRUNC, darwin::O_TRUNC),
        (linux::O_APPEND, darwin::O_APPEND),
        (linux::O_NONBLOCK, darwin::O_NONBLOCK),
        (linux::O_DSYNC, darwin::O_DSYNC),
        (linux::O_CLOEXEC, darwin::O_CLOEXEC),
        (arch.directory, darwin::O_DIRECTORY),
        (arch.nofollow, darwin::O_NOFOLLOW),
    ];
    for (linux_flag, darwin_flag) in table {
        if linux_flags & linux_flag == linux_flag {
            flags |= darwin_flag;
        }
    }
    // O_SYNC is two bits, one of which is O_DSYNC, so it must match whole.
    if linux_flags & linux::O_SYNC == linux::O_SYNC {
        flags |= darwin::O_SYNC;
    }

    HostOpenFlags {
        flags,
        nocache: linux_flags & arch.direct != 0,
    }
}

/// Translate a Linux guest's open flags into a Linux host's.
///
/// Only the four architecture-dependent flags can differ. When the guest's
/// architecture is the host's the flags pass through unchanged, bit for bit,
/// including any this module does not name.
pub fn linux_to_linux_open_flags(linux_flags: i32, guest: GuestArch, host: GuestArch) -> i32 {
    if guest == host {
        return linux_flags;
    }
    let (from, to) = (guest.flags(), host.flags());
    let mut flags = linux_flags & !from.mask();
    let pairs = [
        (from.direct, to.direct),
        (from.largefile, to.largefile),
        (from.directory, to.directory),
        (from.nofollow, to.nofollow),
    ];
    for (from_flag, to_flag) in pairs {
        if linux_flags & from_flag != 0 {
            flags |= to_flag;
        }
    }
    flags
}

/// Translate a guest's open flags for this host.
#[cfg(target_os = "macos")]
pub fn translate_linux_open_flags(linux_flags: i32, guest: GuestArch) -> HostOpenFlags {
    linux_to_darwin_open_flags(linux_flags, guest)
}

/// Translate a guest's open flags for this host.
#[cfg(target_os = "linux")]
pub fn translate_linux_open_flags(linux_flags: i32, guest: GuestArch) -> HostOpenFlags {
    HostOpenFlags {
        flags: linux_to_linux_open_flags(linux_flags, guest, GuestArch::HOST),
        nocache: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An arm64 guest's values, from arch/arm64/include/uapi/asm/fcntl.h.
    const ARM64_O_DIRECTORY: i32 = 0o40000;
    const ARM64_O_NOFOLLOW: i32 = 0o100000;
    const ARM64_O_DIRECT: i32 = 0o200000;
    const ARM64_O_LARGEFILE: i32 = 0o400000;

    // An x86_64 guest's values, from include/uapi/asm-generic/fcntl.h.
    const X86_64_O_DIRECT: i32 = 0o40000;
    const X86_64_O_LARGEFILE: i32 = 0o100000;
    const X86_64_O_DIRECTORY: i32 = 0o200000;
    const X86_64_O_NOFOLLOW: i32 = 0o400000;

    /// The open `xfs_repair` makes, which an arm64 guest on an Apple Silicon
    /// host saw fail with `ENOTDIR`: `O_RDONLY | O_DIRECT`, plus the
    /// `O_LARGEFILE` a 64-bit kernel adds to every open.
    #[test]
    fn arm64_o_direct_is_not_o_directory() {
        let host =
            linux_to_darwin_open_flags(ARM64_O_DIRECT | ARM64_O_LARGEFILE, GuestArch::Aarch64);
        assert_eq!(host.flags & darwin::O_DIRECTORY, 0, "{host:?}");
        assert_eq!(host.flags & darwin::O_NOFOLLOW, 0, "{host:?}");
        assert_eq!(
            host,
            HostOpenFlags {
                flags: darwin::O_RDONLY,
                nocache: true
            }
        );
    }

    #[test]
    fn arm64_directory_and_nofollow_are_decoded() {
        let host = linux_to_darwin_open_flags(ARM64_O_DIRECTORY, GuestArch::Aarch64);
        assert_eq!(host.flags, darwin::O_DIRECTORY);
        assert!(!host.nocache);

        let host = linux_to_darwin_open_flags(ARM64_O_NOFOLLOW, GuestArch::Aarch64);
        assert_eq!(host.flags, darwin::O_NOFOLLOW);
        assert!(!host.nocache);
    }

    #[test]
    fn x86_64_values_are_decoded() {
        let decode = |f| linux_to_darwin_open_flags(f, GuestArch::X86_64);
        assert_eq!(
            decode(X86_64_O_DIRECT),
            HostOpenFlags {
                flags: darwin::O_RDONLY,
                nocache: true
            }
        );
        assert_eq!(decode(X86_64_O_LARGEFILE).flags, darwin::O_RDONLY);
        assert_eq!(decode(X86_64_O_DIRECTORY).flags, darwin::O_DIRECTORY);
        assert_eq!(decode(X86_64_O_NOFOLLOW).flags, darwin::O_NOFOLLOW);
    }

    #[test]
    fn flags_common_to_every_arch_are_decoded_for_each() {
        let common = [
            (linux::O_WRONLY, darwin::O_WRONLY),
            (linux::O_RDWR, darwin::O_RDWR),
            (linux::O_CREAT, darwin::O_CREAT),
            (linux::O_EXCL, darwin::O_EXCL),
            (linux::O_NOCTTY, darwin::O_NOCTTY),
            (linux::O_TRUNC, darwin::O_TRUNC),
            (linux::O_APPEND, darwin::O_APPEND),
            (linux::O_NONBLOCK, darwin::O_NONBLOCK),
            (linux::O_DSYNC, darwin::O_DSYNC),
            (linux::O_CLOEXEC, darwin::O_CLOEXEC),
            (linux::O_SYNC, darwin::O_SYNC | darwin::O_DSYNC),
        ];
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            for (linux_flag, darwin_flag) in common {
                let host = linux_to_darwin_open_flags(linux_flag, arch);
                assert_eq!(host.flags, darwin_flag, "{arch}: linux {linux_flag:#o}");
                assert!(!host.nocache, "{}: linux {:#o}", arch, linux_flag);
            }
        }
    }

    /// `O_SYNC` contains the `O_DSYNC` bit, so testing it with a non-zero `&`
    /// turned every `O_DSYNC` open into an `O_SYNC` one.
    #[test]
    fn o_dsync_alone_is_not_o_sync() {
        let host = linux_to_darwin_open_flags(linux::O_DSYNC, GuestArch::HOST);
        assert_eq!(host.flags, darwin::O_DSYNC);
    }

    #[test]
    fn a_linux_host_passes_its_own_arch_through_unchanged() {
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            for flags in [0, -1, 0o7777777, ARM64_O_DIRECT, X86_64_O_DIRECTORY] {
                assert_eq!(linux_to_linux_open_flags(flags, arch, arch), flags);
            }
        }
    }

    #[test]
    fn a_linux_host_remaps_another_arch() {
        let rw = linux::O_RDWR | linux::O_CLOEXEC;
        let pairs = [
            (ARM64_O_DIRECT, X86_64_O_DIRECT),
            (ARM64_O_LARGEFILE, X86_64_O_LARGEFILE),
            (ARM64_O_DIRECTORY, X86_64_O_DIRECTORY),
            (ARM64_O_NOFOLLOW, X86_64_O_NOFOLLOW),
        ];
        for (arm64, x86_64) in pairs {
            assert_eq!(
                linux_to_linux_open_flags(rw | arm64, GuestArch::Aarch64, GuestArch::X86_64),
                rw | x86_64
            );
            assert_eq!(
                linux_to_linux_open_flags(rw | x86_64, GuestArch::X86_64, GuestArch::Aarch64),
                rw | arm64
            );
        }
    }

    #[test]
    fn guest_arch_parses_and_prints() {
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            assert_eq!(arch.to_string().parse::<GuestArch>(), Ok(arch));
        }
        assert_eq!("arm64".parse::<GuestArch>(), Ok(GuestArch::Aarch64));
        assert_eq!("amd64".parse::<GuestArch>(), Ok(GuestArch::X86_64));
        assert!("riscv64".parse::<GuestArch>().is_err());
        assert_eq!(GuestArch::default(), GuestArch::HOST);
    }

    /// The tables checked against something other than themselves: on a Linux
    /// host, `libc` gives the host architecture's own values, and a guest of the
    /// host's architecture must decode them as the flags they name. CI runs this
    /// on x86_64 and aarch64 Linux, which covers both tables.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_tables_agree_with_libc() {
        let decode = |f| linux_to_darwin_open_flags(f, GuestArch::HOST);
        assert_eq!(
            decode(libc::O_DIRECT),
            HostOpenFlags {
                flags: darwin::O_RDONLY,
                nocache: true
            }
        );
        assert_eq!(decode(libc::O_DIRECTORY).flags, darwin::O_DIRECTORY);
        assert_eq!(decode(libc::O_NOFOLLOW).flags, darwin::O_NOFOLLOW);
        let common = [
            (libc::O_CREAT, darwin::O_CREAT),
            (libc::O_EXCL, darwin::O_EXCL),
            (libc::O_NOCTTY, darwin::O_NOCTTY),
            (libc::O_TRUNC, darwin::O_TRUNC),
            (libc::O_APPEND, darwin::O_APPEND),
            (libc::O_NONBLOCK, darwin::O_NONBLOCK),
            (libc::O_DSYNC, darwin::O_DSYNC),
            (libc::O_CLOEXEC, darwin::O_CLOEXEC),
            (libc::O_SYNC, darwin::O_SYNC | darwin::O_DSYNC),
        ];
        for (linux_flag, darwin_flag) in common {
            assert_eq!(decode(linux_flag).flags, darwin_flag, "{linux_flag:#o}");
        }
    }

    /// The Darwin values are written out by hand; pin each to the SDK's.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_darwin_values_agree_with_libc() {
        assert_eq!(darwin::O_RDONLY, libc::O_RDONLY);
        assert_eq!(darwin::O_WRONLY, libc::O_WRONLY);
        assert_eq!(darwin::O_RDWR, libc::O_RDWR);
        assert_eq!(darwin::O_NONBLOCK, libc::O_NONBLOCK);
        assert_eq!(darwin::O_APPEND, libc::O_APPEND);
        assert_eq!(darwin::O_SYNC, libc::O_SYNC);
        assert_eq!(darwin::O_NOFOLLOW, libc::O_NOFOLLOW);
        assert_eq!(darwin::O_CREAT, libc::O_CREAT);
        assert_eq!(darwin::O_TRUNC, libc::O_TRUNC);
        assert_eq!(darwin::O_EXCL, libc::O_EXCL);
        assert_eq!(darwin::O_NOCTTY, libc::O_NOCTTY);
        assert_eq!(darwin::O_DIRECTORY, libc::O_DIRECTORY);
        assert_eq!(darwin::O_DSYNC, libc::O_DSYNC);
        assert_eq!(darwin::O_CLOEXEC, libc::O_CLOEXEC);
    }
}
