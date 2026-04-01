// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! macOS no-op seccomp implementation.
//!
//! macOS does not support seccomp-bpf. This module provides a no-op
//! `enable_seccomp()` that always succeeds.

use super::{Error, SeccompAction};

/// No-op seccomp on macOS. Always succeeds.
///
/// # Errors
///
/// This function never returns an error on macOS.
pub fn enable_seccomp(_action: SeccompAction, _allow_remote_logging: bool) -> Result<(), Error> {
    // TODO(macos): Consider using macOS sandbox_init(3) or App Sandbox
    // for similar process isolation, if needed.
    Ok(())
}
