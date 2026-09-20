//! Name to number tables used while lowering.
//!
//! Mount options, resource limits, namespaces and propagation modes all arrive
//! as strings and all have to become numbers before the container init process
//! sees them. Doing that here, once, leaves init free of parsing.

use crate::{
    oci::plan::record::mount_flag,
    sys::{
        clone::{
            CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
            CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS,
        },
        mountattr,
    },
};

/// Legacy `MS_*` mount flags, for the fallback path on kernels without the
/// mount API.
pub mod ms {
    /// Read only.
    pub const RDONLY: u64 = 1;
    /// Ignore set-user-id and set-group-id bits.
    pub const NOSUID: u64 = 2;
    /// Disallow access to device special files.
    pub const NODEV: u64 = 4;
    /// Disallow program execution.
    pub const NOEXEC: u64 = 8;
    /// Writes are synchronous.
    pub const SYNCHRONOUS: u64 = 16;
    /// Change an existing mount.
    pub const REMOUNT: u64 = 32;
    /// Allow mandatory locks.
    pub const MANDLOCK: u64 = 64;
    /// Directory changes are synchronous.
    pub const DIRSYNC: u64 = 128;
    /// Do not follow symbolic links.
    pub const NOSYMFOLLOW: u64 = 256;
    /// Do not update directory access times.
    pub const NODIRATIME: u64 = 2048;
    /// Create a bind mount.
    pub const BIND: u64 = 4096;
    /// Apply recursively.
    pub const REC: u64 = 16384;
    /// Suppress kernel messages.
    pub const SILENT: u64 = 32768;
    /// Honour POSIX access control lists.
    pub const POSIXACL: u64 = 1 << 16;
    /// The mount cannot be bind mounted elsewhere.
    pub const UNBINDABLE: u64 = 1 << 17;
    /// No propagation.
    pub const PRIVATE: u64 = 1 << 18;
    /// Receive propagation but do not send it.
    pub const SLAVE: u64 = 1 << 19;
    /// Propagate in both directions.
    pub const SHARED: u64 = 1 << 20;
    /// Track inode versions.
    pub const I_VERSION: u64 = 1 << 23;
    /// Defer timestamp writes.
    pub const LAZYTIME: u64 = 1 << 25;
}

/// What a mount option does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Sets and clears kernel flags and mount attributes.
    Flag {
        /// `MS_*` bits to set.
        ms_set: u64,
        /// `MS_*` bits to clear.
        ms_clear: u64,
        /// `MOUNT_ATTR_*` bits to set.
        attr_set: u64,
        /// `MOUNT_ATTR_*` bits to clear.
        attr_clear: u64,
        /// Apply to the whole subtree.
        recursive: bool,
    },
    /// Changes the propagation mode.
    Propagation {
        /// `MS_*` propagation bit.
        mode: u64,
        /// Apply to the whole subtree.
        recursive: bool,
    },
    /// Chooses the access-time mode.
    ///
    /// The kernel treats these as one setting rather than as independent
    /// flags: it wants every access-time bit cleared and exactly one set, and
    /// rejects a request that does anything else.
    Atime(u64),
    /// Makes the mount a bind.
    Bind {
        /// Carry the source's whole subtree.
        recursive: bool,
    },
    /// Sets one of the runtime's own behaviours.
    Extra(u32),
    /// Recognised but does nothing.
    Ignore,
    /// Not a flag: pass through to the filesystem as option data.
    Data,
}

/// A flag option that only sets bits.
const fn set(ms: u64, attr: u64) -> Effect {
    Effect::Flag {
        ms_set: ms,
        ms_clear: 0,
        attr_set: attr,
        attr_clear: 0,
        recursive: false,
    }
}

/// A flag option that only clears bits.
const fn clear(ms: u64, attr: u64) -> Effect {
    Effect::Flag {
        ms_set: 0,
        ms_clear: ms,
        attr_set: 0,
        attr_clear: attr,
        recursive: false,
    }
}

/// An option that selects a propagation mode.
const fn propagation_mode(mode: u64, recursive: bool) -> Effect {
    Effect::Propagation { mode, recursive }
}

/// Marks an effect as applying to the whole subtree.
const fn recursive(effect: Effect) -> Effect {
    match effect {
        Effect::Flag {
            ms_set,
            ms_clear,
            attr_set,
            attr_clear,
            ..
        } => Effect::Flag {
            ms_set,
            ms_clear,
            attr_set,
            attr_clear,
            recursive: true,
        },
        Effect::Propagation { mode, .. } => Effect::Propagation {
            mode,
            recursive: true,
        },
        // The recursive form of an access-time mode still names one mode; it
        // is the application that is recursive, which the caller records
        // separately.
        other => other,
    }
}

/// Resolves a mount option.
///
/// The `r` prefixed family comes from crun and applies the same change to
/// every mount below the destination, which real bundles use for read-only
/// volume trees. Anything not recognised here is filesystem option data, which
/// is how `mode=755` and `context=...` reach the filesystem unchanged.
#[must_use]
pub fn mount_option(name: &str) -> Effect {
    match plain_mount_option(name) {
        // The recursive family from crun sets an attribute on every mount
        // below the destination rather than only on the top one. Each of its
        // names is the plain one with an `r` in front, so the plain table is
        // consulted first and only a name it does not know is retried without
        // the prefix. That order matters: `ro` and `relatime` start with `r`
        // without being recursive anything.
        Effect::Data => match name.strip_prefix('r') {
            Some(rest) => match plain_mount_option(rest) {
                Effect::Data => Effect::Data,
                effect => recursive(effect),
            },
            None => Effect::Data,
        },
        effect => effect,
    }
}

/// The effect of one option, ignoring the recursive family.
///
/// Long because the kernel's option set is long, and kept as one table so
/// that a reviewer can see the whole vocabulary at once.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
fn plain_mount_option(name: &str) -> Effect {
    use mountattr as attr;
    match name {
        "defaults" => Effect::Ignore,
        "ro" => set(ms::RDONLY, attr::ATTR_RDONLY),
        "rw" => clear(ms::RDONLY, attr::ATTR_RDONLY),
        "suid" => clear(ms::NOSUID, attr::ATTR_NOSUID),
        "nosuid" => set(ms::NOSUID, attr::ATTR_NOSUID),
        "dev" => clear(ms::NODEV, attr::ATTR_NODEV),
        "nodev" => set(ms::NODEV, attr::ATTR_NODEV),
        "exec" => clear(ms::NOEXEC, attr::ATTR_NOEXEC),
        "noexec" => set(ms::NOEXEC, attr::ATTR_NOEXEC),
        "sync" => set(ms::SYNCHRONOUS, 0),
        "async" => clear(ms::SYNCHRONOUS, 0),
        "dirsync" => set(ms::DIRSYNC, 0),
        "remount" => set(ms::REMOUNT, 0),
        "mand" => set(ms::MANDLOCK, 0),
        "nomand" => clear(ms::MANDLOCK, 0),
        "atime" => Effect::Atime(attr::ATTR_RELATIME),
        "noatime" => Effect::Atime(attr::ATTR_NOATIME),
        "diratime" => clear(ms::NODIRATIME, attr::ATTR_NODIRATIME),
        "nodiratime" => set(ms::NODIRATIME, attr::ATTR_NODIRATIME),
        "relatime" => Effect::Atime(attr::ATTR_RELATIME),
        "norelatime" => Effect::Atime(attr::ATTR_STRICTATIME),
        "strictatime" => Effect::Atime(attr::ATTR_STRICTATIME),
        "nostrictatime" => Effect::Atime(attr::ATTR_RELATIME),
        "lazytime" => set(ms::LAZYTIME, 0),
        "nolazytime" => clear(ms::LAZYTIME, 0),
        "symfollow" => clear(ms::NOSYMFOLLOW, attr::ATTR_NOSYMFOLLOW),
        "nosymfollow" => set(ms::NOSYMFOLLOW, attr::ATTR_NOSYMFOLLOW),
        "silent" => set(ms::SILENT, 0),
        "loud" => clear(ms::SILENT, 0),
        "iversion" => set(ms::I_VERSION, 0),
        "noiversion" => clear(ms::I_VERSION, 0),
        "acl" => set(ms::POSIXACL, 0),
        "noacl" => clear(ms::POSIXACL, 0),
        "nofail" => Effect::Extra(mount_flag::OPTIONAL),

        _ => structural_mount_option(name),
    }
}

/// Options that change what kind of mount is made rather than one of its
/// flags: binds, propagation modes, and the markers the plan carries through
/// to the code that does the mounting.
fn structural_mount_option(name: &str) -> Effect {
    match name {
        "bind" => Effect::Bind { recursive: false },
        "rbind" => Effect::Bind { recursive: true },

        "private" => propagation_mode(ms::PRIVATE, false),
        "rprivate" => propagation_mode(ms::PRIVATE, true),
        "slave" => propagation_mode(ms::SLAVE, false),
        "rslave" => propagation_mode(ms::SLAVE, true),
        "shared" => propagation_mode(ms::SHARED, false),
        "rshared" => propagation_mode(ms::SHARED, true),
        "unbindable" => propagation_mode(ms::UNBINDABLE, false),
        "runbindable" => propagation_mode(ms::UNBINDABLE, true),

        "tmpcopyup" => Effect::Extra(mount_flag::TMPCOPYUP),
        "copy-symlink" => Effect::Extra(mount_flag::COPY_SYMLINK),
        "dest-nofollow" => Effect::Extra(mount_flag::DEST_NOFOLLOW),
        "src-nofollow" => Effect::Extra(mount_flag::SRC_NOFOLLOW),
        // The mapping itself is carried by the mount's own `uidMappings` and
        // `gidMappings`, so the option is only a marker.
        "idmap" => Effect::Ignore,
        _ => Effect::Data,
    }
}

/// Resolves a propagation mode named by `rootfsPropagation`.
#[must_use]
pub fn propagation(name: &str) -> Option<u64> {
    match name {
        "private" | "rprivate" => Some(ms::PRIVATE),
        "slave" | "rslave" => Some(ms::SLAVE),
        "shared" | "rshared" => Some(ms::SHARED),
        "unbindable" | "runbindable" => Some(ms::UNBINDABLE),
        _ => None,
    }
}

/// Resolves a namespace type to its `CLONE_NEW*` bit.
#[must_use]
pub fn namespace(name: &str) -> Option<u64> {
    match name {
        "mount" => Some(CLONE_NEWNS),
        "cgroup" => Some(CLONE_NEWCGROUP),
        "uts" => Some(CLONE_NEWUTS),
        "ipc" => Some(CLONE_NEWIPC),
        "user" => Some(CLONE_NEWUSER),
        "pid" => Some(CLONE_NEWPID),
        "network" => Some(CLONE_NEWNET),
        "time" => Some(CLONE_NEWTIME),
        _ => None,
    }
}

/// Resolves a resource limit name to its `RLIMIT_*` number.
#[must_use]
pub fn rlimit(name: &str) -> Option<u32> {
    let value = match name {
        "RLIMIT_CPU" => 0,
        "RLIMIT_FSIZE" => 1,
        "RLIMIT_DATA" => 2,
        "RLIMIT_STACK" => 3,
        "RLIMIT_CORE" => 4,
        "RLIMIT_RSS" => 5,
        "RLIMIT_NPROC" => 6,
        "RLIMIT_NOFILE" => 7,
        "RLIMIT_MEMLOCK" => 8,
        "RLIMIT_AS" => 9,
        "RLIMIT_LOCKS" => 10,
        "RLIMIT_SIGPENDING" => 11,
        "RLIMIT_MSGQUEUE" => 12,
        "RLIMIT_NICE" => 13,
        "RLIMIT_RTPRIO" => 14,
        "RLIMIT_RTTIME" => 15,
        _ => return None,
    };
    Some(value)
}

/// Resolves a scheduling policy name.
#[must_use]
pub fn scheduler_policy(name: &str) -> Option<u32> {
    use crate::sys::process as p;
    match name {
        "SCHED_OTHER" => Some(p::SCHED_OTHER),
        "SCHED_FIFO" => Some(p::SCHED_FIFO),
        "SCHED_RR" => Some(p::SCHED_RR),
        "SCHED_BATCH" => Some(p::SCHED_BATCH),
        "SCHED_IDLE" => Some(p::SCHED_IDLE),
        "SCHED_DEADLINE" => Some(p::SCHED_DEADLINE),
        _ => None,
    }
}

/// Resolves a scheduling flag name.
#[must_use]
pub fn scheduler_flag(name: &str) -> Option<u64> {
    use crate::sys::process as p;
    match name {
        "SCHED_FLAG_RESET_ON_FORK" => Some(p::SCHED_FLAG_RESET_ON_FORK),
        "SCHED_FLAG_RECLAIM" => Some(p::SCHED_FLAG_RECLAIM),
        "SCHED_FLAG_DL_OVERRUN" => Some(p::SCHED_FLAG_DL_OVERRUN),
        "SCHED_FLAG_KEEP_POLICY" => Some(p::SCHED_FLAG_KEEP_POLICY),
        _ => None,
    }
}

/// Resolves an I/O priority class name.
#[must_use]
pub fn ioprio_class(name: &str) -> Option<u32> {
    use crate::sys::process as p;
    match name {
        "IOPRIO_CLASS_RT" => Some(p::IOPRIO_CLASS_RT),
        "IOPRIO_CLASS_BE" => Some(p::IOPRIO_CLASS_BE),
        "IOPRIO_CLASS_IDLE" => Some(p::IOPRIO_CLASS_IDLE),
        _ => None,
    }
}

/// Resolves a NUMA memory policy mode.
#[must_use]
pub fn mempolicy_mode(name: &str) -> Option<u32> {
    use crate::sys::process as p;
    match name {
        "MPOL_DEFAULT" => Some(p::MPOL_DEFAULT),
        "MPOL_BIND" => Some(p::MPOL_BIND),
        "MPOL_INTERLEAVE" => Some(p::MPOL_INTERLEAVE),
        "MPOL_WEIGHTED_INTERLEAVE" => Some(p::MPOL_WEIGHTED_INTERLEAVE),
        "MPOL_PREFERRED" => Some(p::MPOL_PREFERRED),
        "MPOL_PREFERRED_MANY" => Some(p::MPOL_PREFERRED_MANY),
        "MPOL_LOCAL" => Some(p::MPOL_LOCAL),
        _ => None,
    }
}

/// Resolves a NUMA memory policy flag.
#[must_use]
pub fn mempolicy_flag(name: &str) -> Option<u32> {
    use crate::sys::process as p;
    match name {
        "MPOL_F_NUMA_BALANCING" => Some(p::MPOL_F_NUMA_BALANCING),
        "MPOL_F_RELATIVE_NODES" => Some(p::MPOL_F_RELATIVE_NODES),
        "MPOL_F_STATIC_NODES" => Some(p::MPOL_F_STATIC_NODES),
        _ => None,
    }
}

/// Resolves an execution domain name.
#[must_use]
pub fn personality(name: &str) -> Option<u64> {
    match name {
        "LINUX" => Some(crate::sys::process::PER_LINUX),
        "LINUX32" => Some(crate::sys::process::PER_LINUX32),
        _ => None,
    }
}

/// True when the kernel labels a filesystem's inodes from the policy it has
/// loaded rather than from what the mount was given.
///
/// These refuse an explicit `context=` outright, so a container-wide mount
/// label has to leave them alone. Their contents are already labelled, by the
/// host's policy, which is the answer the label was asking for anyway.
#[must_use]
pub fn labels_from_policy(fstype: &str) -> bool {
    matches!(
        fstype,
        "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "mqueue"
            | "bpf"
            | "tracefs"
            | "debugfs"
            | "securityfs"
            | "selinuxfs"
            | "pstore"
            | "configfs"
            | "binfmt_misc"
            | "fusectl"
            | "nsfs"
    )
}

/// Resolves an execution domain flag.
///
/// Only one is defined by anything a container can ask for. An unknown name is
/// refused rather than dropped: a container that asked for a deterministic
/// address space and quietly did not get one is the kind of difference that
/// shows up much later as a test that only fails sometimes.
#[must_use]
pub fn personality_flag(name: &str) -> Option<u64> {
    match name {
        "ADDR_NO_RANDOMIZE" => Some(crate::sys::process::ADDR_NO_RANDOMIZE),
        _ => None,
    }
}

/// The device nodes every container gets whether or not it asks.
///
/// The specification requires these to exist, and a container without them
/// fails in confusing ways long before anyone suspects the runtime.
pub const DEFAULT_DEVICES: [(&str, u8, u32, u32, u32); 6] = [
    ("/dev/null", b'c', 1, 3, 0o666),
    ("/dev/zero", b'c', 1, 5, 0o666),
    ("/dev/full", b'c', 1, 7, 0o666),
    ("/dev/random", b'c', 1, 8, 0o666),
    ("/dev/urandom", b'c', 1, 9, 0o666),
    ("/dev/tty", b'c', 5, 0, 0o666),
];
