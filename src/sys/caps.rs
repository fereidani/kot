//! Capability sets, as bitmasks rather than as the list-of-strings the OCI
//! configuration uses.
//!
//! Lowering converts names to bits once, so the container init process only
//! ever handles the five `u64` masks below.

use crate::sys::{
    error::{EINVAL, Result},
    prctl,
    raw::{arg_ref, nr, ret_unit, syscall2},
};

/// Highest capability the runtime knows about.
pub const LAST_CAP: u32 = 40;

/// Every capability this build recognises, indexed by capability number.
pub const NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Resolves a capability name to its number.
///
/// Accepts both the `CAP_` prefixed spelling the OCI configuration uses and
/// the bare name, case insensitively, because real configurations contain
/// both.
#[must_use]
pub fn by_name(name: &str) -> Option<u32> {
    let index = NAMES.iter().position(|&full| {
        let bare = full.get(4..).unwrap_or(full);
        full.eq_ignore_ascii_case(name) || bare.eq_ignore_ascii_case(name)
    })?;
    u32::try_from(index).ok()
}

/// The four capability sets the kernel tracks per thread, plus the bounding
/// set, each as a bitmask over capability numbers.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CapSets {
    /// Capabilities currently in force.
    pub effective: u64,
    /// Capabilities that may be moved into the effective set.
    pub permitted: u64,
    /// Capabilities preserved across `execve` into a file with no file
    /// capabilities.
    pub inheritable: u64,
    /// Upper bound on what may ever be gained.
    pub bounding: u64,
    /// Capabilities that survive `execve` for an unprivileged program.
    pub ambient: u64,
}

impl CapSets {
    /// True when `cap` is present in `mask`.
    #[must_use]
    pub const fn has(mask: u64, cap: u32) -> bool {
        cap <= LAST_CAP && (mask & (1u64 << cap)) != 0
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// `_LINUX_CAPABILITY_VERSION_3` for the calling thread, which is the only
/// header shape either wrapper below uses.
const HEADER: CapHeader = CapHeader {
    version: 0x2008_0522,
    pid: 0,
};

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Applies `sets` to the calling thread.
///
/// The order matters and is not negotiable:
///
/// 1. The ambient set is cleared, because raising a capability requires it to
///    be in both the permitted and inheritable sets, which may not yet be true.
/// 2. The bounding set is narrowed, which is irreversible and requires
///    `CAP_SETPCAP`, so it happens while that is still held.
/// 3. The effective, permitted and inheritable sets are installed together.
/// 4. The ambient set is raised, which requires step 3 to have happened.
///
/// Getting this order wrong produces a container that silently holds more
/// privilege than its configuration asked for, which is why it lives here
/// rather than being open coded by callers.
pub fn apply(sets: &CapSets) -> Result<()> {
    prctl::clear_ambient_caps()?;

    for cap in 0..=LAST_CAP {
        if CapSets::has(sets.bounding, cap) {
            continue;
        }
        // A capability the kernel does not implement cannot be in the
        // bounding set either, so a refusal with EINVAL is harmless.
        match prctl::drop_bounding_cap(cap) {
            Ok(()) => {}
            Err(e) if e.errno() == EINVAL => {}
            Err(e) => return Err(e),
        }
    }

    set_caps(sets.effective, sets.permitted, sets.inheritable)?;

    for cap in 0..=LAST_CAP {
        if CapSets::has(sets.ambient, cap) {
            prctl::raise_ambient_cap(cap)?;
        }
    }
    Ok(())
}

/// Installs the effective, permitted and inheritable sets.
pub fn set_caps(
    effective: u64,
    permitted: u64,
    inheritable: u64,
) -> Result<()> {
    #[allow(clippy::cast_possible_truncation)]
    let data = [
        CapData {
            effective: effective as u32,
            permitted: permitted as u32,
            inheritable: inheritable as u32,
        },
        CapData {
            effective: (effective >> 32) as u32,
            permitted: (permitted >> 32) as u32,
            inheritable: (inheritable >> 32) as u32,
        },
    ];
    // SAFETY: `HEADER` declares version 3, which makes the kernel read exactly
    // two `CapData` entries, and `data` provides them. Both outlive the call.
    let r = unsafe {
        syscall2(nr::CAPSET, arg_ref(&HEADER), data.as_ptr() as usize)
    };
    ret_unit(r, "capset")
}
