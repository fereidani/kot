//! `mount_setattr(2)`, which sets mount flags and id mappings in one call.
//!
//! This replaces the older pattern of remounting to change flags, and it is
//! the only interface that can apply an id mapping to a mount.

use core::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::sys::{
    error::Result,
    path,
    raw::{arg_fd, arg_ref, nr, ret_unit, syscall5},
};

/// Mount is read only.
pub const ATTR_RDONLY: u64 = 0x0000_0001;
/// Set-user-id and set-group-id bits are ignored.
pub const ATTR_NOSUID: u64 = 0x0000_0002;
/// Device nodes cannot be opened.
pub const ATTR_NODEV: u64 = 0x0000_0004;
/// Programs cannot be executed.
pub const ATTR_NOEXEC: u64 = 0x0000_0008;
/// Mask covering the three access-time settings.
pub const ATTR_ATIME_MASK: u64 = 0x0000_0070;
/// Update access time only when older than modify time.
pub const ATTR_RELATIME: u64 = 0x0000_0000;
/// Never update access time.
pub const ATTR_NOATIME: u64 = 0x0000_0010;
/// Always update access time.
pub const ATTR_STRICTATIME: u64 = 0x0000_0020;
/// Never update directory access time.
pub const ATTR_NODIRATIME: u64 = 0x0000_0080;
/// Apply the id mapping named by `userns_fd`.
pub const ATTR_IDMAP: u64 = 0x0010_0000;
/// Symbolic links on this mount are not followed.
pub const ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

/// Apply to the whole subtree rather than the single mount.
pub const AT_RECURSIVE: u32 = 0x8000;
/// Operate on the descriptor itself, with an empty path.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// The kernel's `struct mount_attr`.
#[repr(C, align(8))]
#[derive(Default, Clone, Copy)]
pub struct MountAttr {
    /// Flags to turn on.
    pub attr_set: u64,
    /// Flags to turn off.
    pub attr_clr: u64,
    /// New propagation type, or zero to leave it alone.
    pub propagation: u64,
    /// User namespace supplying the id mapping, when `ATTR_IDMAP` is set.
    pub userns_fd: u64,
}

impl MountAttr {
    /// Turns `flags` on.
    #[must_use]
    pub const fn set(mut self, flags: u64) -> Self {
        self.attr_set |= flags;
        self
    }

    /// Turns `flags` off.
    #[must_use]
    pub const fn clear(mut self, flags: u64) -> Self {
        self.attr_clr |= flags;
        self
    }

    /// Applies the id mapping of the user namespace that `fd` refers to.
    #[must_use]
    pub fn idmap(mut self, fd: BorrowedFd<'_>) -> Self {
        self.attr_set |= ATTR_IDMAP;
        self.userns_fd = u64::from(fd.as_raw_fd().unsigned_abs());
        self
    }

    /// True when the request would change nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.attr_set == 0 && self.attr_clr == 0 && self.propagation == 0
    }
}

/// Applies `attr` to the mount at `path` relative to `dirfd`.
pub fn mount_setattr(
    dirfd: BorrowedFd<'_>,
    path: &CStr,
    flags: u32,
    attr: &MountAttr,
) -> Result<()> {
    // SAFETY: `path` is NUL terminated and outlives the call, `attr` is a
    // correctly shaped `struct mount_attr` of the declared size, and `dirfd`
    // is valid for the duration.
    let r = unsafe {
        syscall5(
            nr::MOUNT_SETATTR,
            arg_fd(dirfd),
            path.as_ptr() as usize,
            flags as usize,
            arg_ref(attr),
            core::mem::size_of::<MountAttr>(),
        )
    };
    ret_unit(r, "mount_setattr")
}

/// Applies `attr` to the mount that `fd` itself refers to.
pub fn mount_setattr_fd(
    fd: BorrowedFd<'_>,
    recursive: bool,
    attr: &MountAttr,
) -> Result<()> {
    let mut flags = AT_EMPTY_PATH;
    if recursive {
        flags |= AT_RECURSIVE;
    }
    mount_setattr(fd, path::EMPTY, flags, attr)
}
