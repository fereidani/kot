//! Capability sets, as bitmasks rather than as the list-of-strings the OCI
//! configuration uses.
//!
//! Lowering converts names to bits once, so the container init process only
//! ever handles the five `u64` masks below.

use crate::sys::{
    error::{EINVAL, EPERM, Result},
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

/// Narrows the bounding set to `bounding`, and empties the ambient set.
///
/// Runs before the user changes, and that is the whole point of its being
/// separate. Giving up a bounding capability is checked against the effective
/// set, and a change of user empties the effective set even when the caller
/// has asked the kernel to keep the permitted one. Afterwards there is
/// nothing left to give it up with, so a container asked to run as somebody
/// else would keep every bounding capability its configuration meant to take
/// away.
///
/// The ambient set goes first because raising a capability into it later
/// needs that capability in both the permitted and the inheritable set, which
/// is not yet true.
pub fn narrow(bounding: u64) -> Result<()> {
    prctl::clear_ambient_caps()?;

    for cap in 0..=LAST_CAP {
        if CapSets::has(bounding, cap) {
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
    Ok(())
}

/// Installs the sets the payload runs with, after [`narrow`].
///
/// The effective, permitted and inheritable sets go in together, and only
/// then can the ambient set be raised, since a capability reaches the ambient
/// set through the permitted and inheritable ones.
///
/// Getting this order wrong produces a container that silently holds more
/// privilege than its configuration asked for, which is why it lives here
/// rather than being open coded by callers.
pub fn apply(sets: &CapSets) -> Result<()> {
    set_caps(sets.effective, sets.permitted, sets.inheritable)?;

    for cap in 0..=LAST_CAP {
        if !CapSets::has(sets.ambient, cap) {
            continue;
        }
        match prctl::raise_ambient_cap(cap) {
            Ok(()) => {}
            // The kernel admits a capability to the ambient set only from
            // the permitted and the inheritable set together. Engines that
            // copy `ambient` from `permitted` alone ask for one that is in
            // neither, and refusing would reject their default bundle;
            // granting it is not on offer, so the container runs with the
            // privilege its other sets describe.
            Err(e) if matches!(e.errno(), EPERM | EINVAL) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Carries this thread's capabilities through an `execve`.
///
/// The kernel keeps the permitted set across an execution only for a
/// process whose effective id is root in its own user namespace, which a
/// container init in a fresh one usually is not. The ambient set survives
/// whatever the id is, and init replaces all of it with what the
/// configuration asked for before the payload runs.
pub fn preserve_across_exec() -> Result<()> {
    let held = get_caps()?;
    // A capability reaches the ambient set only from the permitted and the
    // inheritable set together, so the inheritable one is widened first.
    set_caps(held.effective, held.permitted, held.permitted)?;
    for cap in 0..=LAST_CAP {
        if !CapSets::has(held.permitted, cap) {
            continue;
        }
        match prctl::raise_ambient_cap(cap) {
            Ok(()) => {}
            // A capability this build knows and the kernel does not cannot be
            // held either, so there is nothing to carry over.
            Err(e) if e.errno() == EINVAL => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads the calling thread's capability sets.
///
/// Three of the five: the bounding and ambient sets are read through
/// `prctl` one capability at a time, and nothing here needs them, so they
/// come back as zero.
pub fn get_caps() -> Result<CapSets> {
    let mut data = [CapData::default(); 2];
    // SAFETY: `HEADER` declares version 3, which makes the kernel write
    // exactly two `CapData` entries, and `data` provides them. Both outlive
    // the call.
    let r = unsafe {
        syscall2(nr::CAPGET, arg_ref(&HEADER), data.as_mut_ptr() as usize)
    };
    ret_unit(r, "capget")?;
    let join = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
    Ok(CapSets {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
        bounding: 0,
        ambient: 0,
    })
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
