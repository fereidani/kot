//! `seccomp(2)` and the classic-BPF instruction layout it consumes.

use std::os::fd::OwnedFd;

use crate::sys::{
    error::{Error, Result},
    raw::{arg_ref, nr, ret_fd, ret_unit, syscall3},
};

/// Install a classic-BPF filter for the calling thread.
pub const SET_MODE_FILTER: u32 = 1;
/// Query whether the kernel knows an action.
pub const GET_ACTION_AVAIL: u32 = 2;

/// Apply the filter to every thread in the process.
pub const FLAG_TSYNC: u32 = 1;
/// Log actions other than `ALLOW`.
pub const FLAG_LOG: u32 = 2;
/// Do not implicitly disable speculative execution mitigations.
pub const FLAG_SPEC_ALLOW: u32 = 4;
/// Return a listener fd for `SECCOMP_RET_USER_NOTIF`.
pub const FLAG_NEW_LISTENER: u32 = 8;
/// Report a `TSYNC` failure through `ESRCH` rather than a thread id.
pub const FLAG_TSYNC_ESRCH: u32 = 16;
/// Make a blocked notify recipient killable.
pub const FLAG_WAIT_KILLABLE_RECV: u32 = 32;

/// The kernel's maximum classic-BPF program length.
pub const MAX_INSNS: usize = 4096;

/// One classic-BPF instruction, matching `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SockFilter {
    /// Opcode, one of the `BPF_*` combinations.
    pub code: u16,
    /// Branch offset taken when the comparison succeeds.
    pub jt: u8,
    /// Branch offset taken when the comparison fails.
    pub jf: u8,
    /// Immediate operand.
    pub k: u32,
}

impl SockFilter {
    /// Builds an instruction.
    #[must_use]
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// `struct sock_fprog`, the header the kernel reads a filter through.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// `struct seccomp_data`, the input a filter is evaluated against.
///
/// Only the field offsets matter to the emitter, and they are fixed by the
/// kernel ABI.
pub mod data {
    /// Offset of the syscall number.
    pub const NR: u32 = 0;
    /// Offset of the `AUDIT_ARCH_*` token.
    pub const ARCH: u32 = 4;
    /// Offset of the first syscall argument.
    pub const ARGS: u32 = 16;

    /// Offset of the low half of argument `index`.
    #[must_use]
    pub const fn arg_low(index: u32) -> u32 {
        ARGS + index * 8
    }

    /// Offset of the high half of argument `index`.
    #[must_use]
    pub const fn arg_high(index: u32) -> u32 {
        ARGS + index * 8 + 4
    }
}

/// Installs `filter` on the calling thread.
///
/// The caller must already have `no_new_privs` set, or hold `CAP_SYS_ADMIN`,
/// or the kernel rejects the call.
pub fn set_mode_filter(filter: &[SockFilter], flags: u32) -> Result<()> {
    install(filter, flags).map(|_| ())
}

/// Installs `filter` and returns the listener descriptor.
///
/// Implies [`FLAG_NEW_LISTENER`]. Fails when the filter contains no
/// `SECCOMP_RET_USER_NOTIF` action.
pub fn set_mode_filter_listener(
    filter: &[SockFilter],
    flags: u32,
) -> Result<OwnedFd> {
    let mut flags = flags | FLAG_NEW_LISTENER;
    // With a listener the call answers with the descriptor, so there is
    // nowhere left to report which thread a `TSYNC` failure came from, and the
    // kernel refuses the pair unless the caller has accepted an errno instead.
    // The listener is the runtime's own addition, made because the profile
    // asks for a notify action, so the runtime adds what keeps the pair legal
    // rather than refusing a profile that asked for nothing contradictory.
    if flags & FLAG_TSYNC != 0 {
        flags |= FLAG_TSYNC_ESRCH;
    }
    let r = install(filter, flags)?;
    ret_fd(r, "seccomp: new listener")
}

fn install(filter: &[SockFilter], flags: u32) -> Result<isize> {
    if filter.is_empty() {
        return Err(Error::msg("seccomp: empty filter"));
    }
    let len = u16::try_from(filter.len())
        .map_err(|_| Error::msg("seccomp: too many instructions"))?;
    let prog = SockFprog {
        len,
        filter: filter.as_ptr(),
    };
    // SAFETY: `prog` describes `filter`, which outlives the call, and `len`
    // is its exact instruction count. The kernel only reads through it.
    let r = unsafe {
        syscall3(
            nr::SECCOMP,
            SET_MODE_FILTER as usize,
            flags as usize,
            arg_ref(&prog),
        )
    };
    if r < 0 {
        return Err(Error::from_ret(r, "seccomp(SET_MODE_FILTER)"));
    }
    Ok(r)
}

/// Reports whether the kernel recognises `flags`.
///
/// Asked with no filter at all, which the kernel reaches only after it has
/// checked the flags: a flag it does not know answers `EINVAL`, while one it
/// knows gets as far as the missing filter and answers something else.
/// Nothing is installed either way.
#[must_use]
pub fn flags_available(flags: u32) -> bool {
    // SAFETY: the filter pointer is null. The kernel reads it only after the
    // flag check this is asking about, so no filter is ever installed.
    let r = unsafe {
        syscall3(nr::SECCOMP, SET_MODE_FILTER as usize, flags as usize, 0)
    };
    Error::from_ret(r, "seccomp").errno() != crate::sys::error::EINVAL
}

/// Reports whether the kernel recognises `action`.
///
/// Used by `kot features` so that the reported action list reflects the
/// running kernel rather than what the build knew about.
#[must_use]
pub fn action_available(action: u32) -> bool {
    // SAFETY: `action` is read as a single `u32` through the pointer, and the
    // local outlives the call.
    let r = unsafe {
        syscall3(nr::SECCOMP, GET_ACTION_AVAIL as usize, 0, arg_ref(&action))
    };
    ret_unit(r, "seccomp").is_ok()
}
