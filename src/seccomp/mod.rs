// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Platform-neutral seccomp abstraction.
//!
//! On Linux, applies a seccomp-bpf filter to restrict syscalls.
//! On macOS, seccomp is not available; this module provides no-op stubs.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

// ── Shared types ────────────────────────────────────────────────────────────

use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    /// Error allowing a syscall
    AllowSeccompSyscall(i32),

    /// Cannot load seccomp filter
    LoadSeccompFilter,

    /// Cannot initialize seccomp context
    InitSeccompContext,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtiofsd_seccomp_error: {self:?}")
    }
}

#[derive(Copy, Clone, Debug)]
pub enum SeccompAction {
    Allow,
    Kill,
    Log,
    Trap,
}

// ── Platform re-exports ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub use linux::enable_seccomp;

#[cfg(target_os = "macos")]
pub use macos::enable_seccomp;
