// Copyright 2020 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! macOS sandbox implementation.
//!
//! macOS does not support Linux namespaces or pivot_root.
//! This module provides a basic chroot-based sandbox and a no-op mode.

use super::{Error, SandboxMode};
use crate::idmap::{GidMap, UidMap};
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::io::FromRawFd;
use vhost::vhost_user::Listener;

/// A helper for creating a sandbox for isolating the service.
pub struct Sandbox {
    shared_dir: String,
    proc_self_fd: Option<File>,
    mountinfo_fd: Option<File>,
    sandbox_mode: SandboxMode,
    _uid_map: Vec<UidMap>,
    _gid_map: Vec<GidMap>,
}

impl Sandbox {
    pub fn new(
        shared_dir: String,
        sandbox_mode: SandboxMode,
        uid_map: Vec<UidMap>,
        gid_map: Vec<GidMap>,
    ) -> Self {
        Sandbox {
            shared_dir,
            proc_self_fd: None,
            mountinfo_fd: None,
            sandbox_mode,
            _uid_map: uid_map,
            _gid_map: gid_map,
        }
    }

    /// Enter a chroot-based sandbox.
    /// On macOS there is no /proc/self/fd, so proc_self_fd is left as None.
    fn enter_chroot(&mut self) -> Result<(), Error> {
        // TODO(macos): There is no /proc on macOS. The proc_self_fd mechanism
        // needs to be replaced with fcntl(F_GETPATH) based fd path resolution.
        // For now, leave proc_self_fd and mountinfo_fd as None.

        let c_shared_dir = CString::new(self.shared_dir.clone()).unwrap();
        let ret = unsafe { libc::chroot(c_shared_dir.as_ptr()) };
        if ret != 0 {
            return Err(Error::Chroot(std::io::Error::last_os_error()));
        }

        let c_root_dir = CString::new("/").unwrap();
        let ret = unsafe { libc::chdir(c_root_dir.as_ptr()) };
        if ret != 0 {
            return Err(Error::ChrootChdir(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Set up sandbox.
    ///
    /// On macOS:
    /// - `Namespace` mode falls back to `Chroot` with a warning, since macOS
    ///   does not support Linux namespaces.
    /// - `Chroot` mode uses a basic chroot.
    /// - `None` mode does nothing.
    pub fn enter(&mut self, listener: Listener) -> Result<Listener, Error> {
        match self.sandbox_mode {
            SandboxMode::Namespace => {
                // TODO(macos): macOS has no namespace support. Fall back to chroot.
                warn!("Namespace sandbox mode is not supported on macOS, falling back to chroot");
                self.enter_chroot().and(Ok(listener))
            }
            SandboxMode::Chroot => self.enter_chroot().and(Ok(listener)),
            SandboxMode::None => Ok(listener),
        }
    }

    pub fn get_proc_self_fd(&mut self) -> Option<File> {
        self.proc_self_fd.take()
    }

    pub fn get_mountinfo_fd(&mut self) -> Option<File> {
        self.mountinfo_fd.take()
    }

    pub fn get_root_dir(&self) -> String {
        match self.sandbox_mode {
            SandboxMode::Namespace | SandboxMode::Chroot => "/".to_string(),
            SandboxMode::None => self.shared_dir.clone(),
        }
    }

    /// Return the prefix to strip from mountinfo entries.
    /// On macOS there is no /proc/self/mountinfo, so this always returns None
    /// unless in chroot mode where we try to provide the prefix.
    pub fn get_mountinfo_prefix(&self) -> io::Result<Option<String>> {
        match self.sandbox_mode {
            SandboxMode::Namespace | SandboxMode::None => Ok(None),
            SandboxMode::Chroot => {
                let prefix = fs::canonicalize(&self.shared_dir)?
                    .into_os_string()
                    .into_string()
                    .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
                Ok(Some(prefix))
            }
        }
    }
}
