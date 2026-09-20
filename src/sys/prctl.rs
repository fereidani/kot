//! `prctl(2)` operations the runtime needs.

use crate::sys::{
    error::Result,
    raw::{nr, ret_unit, syscall3},
};

const PR_SET_PDEATHSIG: usize = 1;
const PR_SET_KEEPCAPS: usize = 8;
const PR_CAPBSET_DROP: usize = 24;
const PR_SET_NO_NEW_PRIVS: usize = 38;
const PR_CAP_AMBIENT: usize = 47;

const PR_CAP_AMBIENT_RAISE: usize = 2;
const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;

/// Issues a `prctl` operation.
///
/// Nothing the runtime uses needs the last two arguments or the returned
/// value, so both are dropped here.
fn prctl(op: usize, arg2: usize, arg3: usize) -> Result<()> {
    // SAFETY: every operation used here takes scalar arguments only, or a
    // pointer that the specific caller below keeps alive across the call.
    let ret = unsafe { syscall3(nr::PRCTL, op, arg2, arg3) };
    ret_unit(ret, "prctl")
}

/// Refuses any future gain of privilege through `execve`.
///
/// Required before installing a seccomp filter without `CAP_SYS_ADMIN`, and
/// required by the OCI configuration's `noNewPrivileges`.
pub fn set_no_new_privs() -> Result<()> {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0)
}

/// Asks the kernel to deliver `signal` when the parent process dies.
///
/// This is how the container init process learns that the runtime went away
/// without an orderly shutdown.
pub fn set_pdeathsig(signal: i32) -> Result<()> {
    prctl(PR_SET_PDEATHSIG, signal.unsigned_abs() as usize, 0)
}

/// Keeps permitted capabilities across a change of user id.
pub fn set_keep_caps(on: bool) -> Result<()> {
    prctl(PR_SET_KEEPCAPS, usize::from(on), 0)
}

/// Removes `cap` from the bounding set, which cannot be undone.
pub fn drop_bounding_cap(cap: u32) -> Result<()> {
    prctl(PR_CAPBSET_DROP, cap as usize, 0)
}

/// Adds `cap` to the ambient set, so it survives `execve`.
pub fn raise_ambient_cap(cap: u32) -> Result<()> {
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap as usize)
}

/// Empties the ambient set.
pub fn clear_ambient_caps() -> Result<()> {
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0)
}
