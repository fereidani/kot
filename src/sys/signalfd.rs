//! Taking delivery of signals as bytes rather than as interruptions.
//!
//! Noticing a signal the usual way, with a handler, would put the work that
//! follows under the async-signal-safety rules. Blocking the signals and
//! reading them from a descriptor keeps it in ordinary code, and lets one
//! `poll` watch for signals and for the container at once.

use std::os::fd::{BorrowedFd, OwnedFd};

use crate::sys::{
    error::{Context, Result},
    raw::{arg_ref, nr, ret_fd, ret_unit, syscall4},
};

/// `SFD_CLOEXEC`, so the descriptor does not reach the container.
const SFD_CLOEXEC: usize = 0o2_000_000;
/// `SFD_NONBLOCK`, so draining stops at the last pending signal.
const SFD_NONBLOCK: usize = 0o4000;

/// `SIG_BLOCK`.
const SIG_BLOCK: usize = 0;
/// `SIG_SETMASK`.
const SIG_SETMASK: usize = 2;

/// `SIG_IGN`.
const SIG_IGN: usize = 1;

/// Bytes one `signalfd_siginfo` occupies. The kernel's structure is this
/// long by definition, and the signal number is its first word.
pub const SIGINFO_SIZE: usize = 128;

/// Adds `mask` to the calling thread's blocked set and answers with the set
/// that was in force.
///
/// Blocking is what makes the descriptor below the only way these signals
/// arrive; unblocked, most of them end the process instead.
pub fn block(mask: u64) -> Result<u64> {
    let mut previous = 0u64;
    // SAFETY: both pointers refer to a `u64`, which is the size the last
    // argument declares, and both outlive the call.
    let r = unsafe {
        syscall4(
            nr::RT_SIGPROCMASK,
            SIG_BLOCK,
            arg_ref(&mask),
            core::ptr::from_mut(&mut previous) as usize,
            core::mem::size_of::<u64>(),
        )
    };
    ret_unit(r, "rt_sigprocmask").context("signalfd: block")?;
    Ok(previous)
}

/// Puts a blocked set back the way [`block`] found it.
pub fn restore(mask: u64) -> Result<()> {
    // SAFETY: the pointer refers to a `u64`, which is the size the last
    // argument declares, and it outlives the call.
    let r = unsafe {
        syscall4(
            nr::RT_SIGPROCMASK,
            SIG_SETMASK,
            arg_ref(&mask),
            0,
            core::mem::size_of::<u64>(),
        )
    };
    ret_unit(r, "rt_sigprocmask").context("signalfd: restore")
}

/// Opens a descriptor that reads the signals in `mask`.
pub fn open(mask: u64) -> Result<OwnedFd> {
    // SAFETY: the pointer refers to a `u64`, which is the size the third
    // argument declares, and it outlives the call.
    let r = unsafe {
        syscall4(
            nr::SIGNALFD4,
            usize::MAX, // -1: create a descriptor rather than change one
            arg_ref(&mask),
            core::mem::size_of::<u64>(),
            SFD_CLOEXEC | SFD_NONBLOCK,
        )
    };
    ret_fd(r, "signalfd4").context("signalfd: open")
}

/// The signal number one record describes.
#[must_use]
pub fn signal_of(record: &[u8]) -> Option<u32> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(record.get(..4)?);
    // The kernel writes the structure as this machine lays it out.
    Some(u32::from_ne_bytes(bytes))
}

/// The bit a signal occupies in a mask.
#[must_use]
pub const fn bit(signal: u32) -> u64 {
    if signal == 0 || signal > 64 {
        return 0;
    }
    1u64 << (signal - 1)
}

/// Reads whatever signals have arrived, calling `visit` for each.
///
/// The descriptor is non-blocking, so this returns as soon as the queue is
/// empty rather than waiting for the next one.
pub fn drain(fd: BorrowedFd<'_>, mut visit: impl FnMut(u32)) -> Result<()> {
    let mut record = [0u8; SIGINFO_SIZE];
    // Bounded: a longer queue than this is not one a caller sent by hand,
    // and the descriptor stays readable for the caller's next turn.
    for _ in 0..64 {
        match rustix::io::read(fd, &mut record) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                if let Some(signal) = signal_of(&record) {
                    visit(signal);
                }
            }
            Err(e) if e.raw_os_error() == crate::sys::error::EAGAIN => {
                return Ok(());
            }
            Err(e) if e.raw_os_error() == crate::sys::error::EINTR => {}
            Err(e) => {
                return Err(crate::sys::error::Error::from(e)
                    .describe("signalfd: read"));
            }
        }
    }
    Ok(())
}

/// The kernel's `sigaction`, which is not the structure `libc` exposes under
/// that name: the mask is a plain word and the restorer is a field of its
/// own.
#[repr(C)]
struct Action {
    /// `SIG_DFL`, `SIG_IGN`, or a handler, none of which this crate installs.
    handler: usize,
    /// `SA_*` flags.
    flags: usize,
    /// The trampoline a handler returns through, unused without one.
    restorer: usize,
    /// Signals blocked while a handler runs, likewise unused.
    mask: u64,
}

/// Sets a signal's disposition to ignoring it.
pub fn ignore(signal: u32) -> Result<()> {
    let action = Action {
        handler: SIG_IGN,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    // SAFETY: the pointer refers to an `Action` laid out as the kernel's
    // structure and outlives the call, the old disposition is not asked for,
    // and the last argument is the size of the mask above. No handler is
    // installed, so nothing runs in signal context.
    let r = unsafe {
        syscall4(
            nr::RT_SIGACTION,
            signal as usize,
            arg_ref(&action),
            0,
            core::mem::size_of::<u64>(),
        )
    };
    ret_unit(r, "rt_sigaction").context("signalfd: ignore")
}
