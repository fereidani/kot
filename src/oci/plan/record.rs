//! The fixed-size records a plan is built from.
//!
//! Every record encodes to the same number of bytes, so a section is a plain
//! array and the executor reaches record `n` without scanning. Variable-length
//! data lives in the string section and is referenced by [`Str`].

use crate::{
    oci::plan::{
        codec::{Reader, Str, Writer},
        layout::{I32Pad4, U8Pad3, U32Pad4},
    },
    sys::error::Result,
};

/// How a mount is established.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountKind {
    /// A new superblock of the named filesystem type.
    Filesystem,
    /// A bind of an existing path or of a prepared detached mount.
    Bind,
    /// A bind that carries the source's whole subtree.
    RecursiveBind,
    /// `/dev/null` placed over a file to hide it.
    MaskFile,
    /// An empty read-only directory placed over a directory to hide it.
    MaskDirectory,
}

impl MountKind {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Filesystem => 0,
            Self::Bind => 1,
            Self::RecursiveBind => 2,
            Self::MaskFile => 3,
            Self::MaskDirectory => 4,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Filesystem),
            1 => Some(Self::Bind),
            2 => Some(Self::RecursiveBind),
            3 => Some(Self::MaskFile),
            4 => Some(Self::MaskDirectory),
            _ => None,
        }
    }
}

/// Extra behaviours a mount option can ask for beyond kernel flags.
pub mod mount_flag {
    /// Copy the shadowed contents up into a new tmpfs.
    pub const TMPCOPYUP: u32 = 1 << 0;
    /// Recreate a symbolic link source rather than resolving it.
    pub const COPY_SYMLINK: u32 = 1 << 1;
    /// Mount onto a symbolic link destination rather than its target.
    pub const DEST_NOFOLLOW: u32 = 1 << 2;
    /// Use a symbolic link source itself rather than its target.
    pub const SRC_NOFOLLOW: u32 = 1 << 3;
    /// Apply the attribute changes to the whole subtree.
    pub const RECURSIVE: u32 = 1 << 4;
    /// The destination is expected to be a file, not a directory.
    pub const DEST_IS_FILE: u32 = 1 << 5;
    /// Do not fail when the source does not exist.
    pub const OPTIONAL: u32 = 1 << 7;
}

record! {
    /// One mount, fully resolved.
    pub struct MountOp {
        /// Source path, for binds and for filesystems that take one.
        source: Str,
        /// Destination inside the container, always absolute.
        target: Str,
        /// Filesystem type.
        fstype: Str,
        /// Filesystem-specific option string.
        data: Str,
        /// `SELinux` context this mount is given, or empty for none.
        ///
        /// Kept apart from `data` because a label carries commas of its own
        /// and the executor splits `data` on them.
        context: Str,
        /// Legacy `MS_*` flags, for the fallback path.
        flags: u64,
        /// `MOUNT_ATTR_*` bits to set.
        attr_set: u64,
        /// `MOUNT_ATTR_*` bits to clear.
        attr_clr: u64,
        /// Propagation mode to apply after the mount, or zero for none.
        propagation: u64,
        /// How the mount is established.
        kind: U8Pad3,
        /// Index of a user namespace descriptor for an id mapping, or minus
        /// one.
        idmap_fd: i32,
        /// A mask of [`mount_flag`] values.
        extra: u32,
    }
}

impl MountOp {
    /// How this mount is established, or `None` when the byte is not one the
    /// runtime knows, which means the plan came from a different build.
    #[must_use]
    pub const fn mount_kind(&self) -> Option<MountKind> {
        MountKind::from_u8(self.kind)
    }

    /// Sets how this mount is established.
    pub const fn set_kind(&mut self, kind: MountKind) {
        self.kind = kind.to_u8();
    }
}

record! {
    /// One device node to create.
    pub struct DeviceOp {
        /// Path inside the container.
        path: Str,
        /// `c`, `b`, `u` or `p`, as its ASCII byte.
        kind: U8Pad3,
        /// Major number.
        major: u32,
        /// Minor number.
        minor: u32,
        /// Permission bits.
        mode: u32,
        /// Owning user, in the container's id space.
        uid: u32,
        /// Owning group, in the container's id space.
        gid: u32,
    }
}

/// What to do with a path the configuration restricts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathAction {
    /// Hide the path entirely.
    Mask,
    /// Allow reads but not writes.
    ReadOnly,
}

impl PathAction {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Mask => 0,
            Self::ReadOnly => 1,
        }
    }

    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Mask),
            1 => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

record! {
    /// One masked or read-only path.
    pub struct PathOp {
        /// The path, inside the container.
        path: Str,
        /// What to do with it.
        action: U8Pad3,
    }
}

impl PathOp {
    /// A record restricting `path`.
    #[must_use]
    pub const fn new(path: Str, action: PathAction) -> Self {
        Self {
            path,
            action: action.to_u8(),
        }
    }

    /// What to do with the path.
    #[must_use]
    pub const fn path_action(&self) -> Option<PathAction> {
        PathAction::from_u8(self.action)
    }
}

record! {
    /// One key and value to write, used for both sysctls and cgroup files.
    pub struct WriteOp {
        /// File to write, relative to a base the executor supplies.
        key: Str,
        /// Bytes to write, already rendered.
        value: Str,
    }
}

record! {
    /// One resource limit.
    pub struct RlimitOp {
        /// `RLIMIT_*` number.
        resource: U32Pad4,
        /// Soft limit.
        soft: u64,
        /// Hard limit.
        hard: u64,
    }
}

record! {
    /// One range of an id mapping.
    pub struct IdRange {
        /// First id inside the container.
        container_id: u32,
        /// First id outside it.
        host_id: u32,
        /// How many ids the range covers.
        size: u32,
    }
}

record! {
    /// One namespace the container enters or creates.
    pub struct NamespaceOp {
        /// The `CLONE_NEW*` bit for this namespace.
        clone_flag: u64,
        /// Index of an inherited descriptor to join, or minus one to create a
        /// new namespace.
        fd_index: I32Pad4,
    }
}
