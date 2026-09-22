//! Direct Linux syscalls for the interfaces `rustix` does not expose.
//!
//! This is the only module in the crate that issues syscall instructions.
//! Everything above it works through the safe wrappers in the sibling modules.
//!
//! None of these wrappers may be used with `CLONE_VM` or `CLONE_VFORK`: the
//! child would run on the caller's stack, which the inline assembly below is
//! not written to survive.

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::sys::error::{Error, Result};

/// Defines the syscall numbers, which differ per architecture.
///
/// Both numbers for a call sit on one line so that a new entry cannot be
/// added for one architecture and forgotten for the other.
macro_rules! syscall_numbers {
    ($($name:ident = $doc:literal, $x86_64:literal, $aarch64:literal;)*) => {
        /// Syscall numbers for the architecture this build targets.
        pub mod nr {
            $(
                #[doc = $doc]
                #[cfg(target_arch = "x86_64")]
                pub const $name: usize = $x86_64;
                #[doc = $doc]
                #[cfg(target_arch = "aarch64")]
                pub const $name: usize = $aarch64;
            )*
        }
    };
}

syscall_numbers! {
    BPF = "`bpf(2)`", 321, 280;
    CAPGET = "`capget(2)`", 125, 90;
    CAPSET = "`capset(2)`", 126, 91;
    CLONE3 = "`clone3(2)`", 435, 435;
    CLOSE_RANGE = "`close_range(2)`", 436, 436;
    DUP3 = "`dup3(2)`", 292, 24;
    EXECVEAT = "`execveat(2)`", 322, 281;
    EXIT_GROUP = "`exit_group(2)`", 231, 94;
    IOPRIO_SET = "`ioprio_set(2)`", 251, 30;
    IOCTL = "`ioctl(2)`", 16, 29;
    KEYCTL = "`keyctl(2)`", 250, 219;
    MOUNT_SETATTR = "`mount_setattr(2)`", 442, 442;
    PERSONALITY = "`personality(2)`", 135, 92;
    PRCTL = "`prctl(2)`", 157, 167;
    RT_SIGPROCMASK = "`rt_sigprocmask(2)`", 14, 135;
    SCHED_SETAFFINITY = "`sched_setaffinity(2)`", 203, 122;
    SCHED_SETATTR = "`sched_setattr(2)`", 314, 274;
    SECCOMP = "`seccomp(2)`", 317, 277;
    SETNS = "`setns(2)`", 308, 268;
    SIGNALFD4 = "`signalfd4(2)`", 289, 74;
    SET_MEMPOLICY = "`set_mempolicy(2)`", 238, 237;
}

/// Issues a syscall with six arguments, the maximum Linux supports.
///
/// # Safety
///
/// The caller must uphold whatever contract the named syscall imposes,
/// including the lifetime and alignment of any pointer passed in a register.
#[cfg(target_arch = "x86_64")]
#[inline]
#[must_use]
#[allow(clippy::many_single_char_names, clippy::cast_possible_wrap)]
pub unsafe fn syscall6(
    nr: usize,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> isize {
    let ret: isize;
    // SAFETY: this is the x86-64 Linux syscall sequence. `rcx` and `r11` are
    // clobbered by the `syscall` instruction and are declared as such; the
    // kernel preserves every other register. `nostack` holds because the
    // sequence touches no memory through the stack pointer.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            in("r8") e,
            in("r9") f,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Issues a syscall with six arguments, the maximum Linux supports.
///
/// # Safety
///
/// The caller must uphold whatever contract the named syscall imposes,
/// including the lifetime and alignment of any pointer passed in a register.
#[cfg(target_arch = "aarch64")]
#[inline]
#[must_use]
#[allow(clippy::many_single_char_names)]
pub unsafe fn syscall6(
    nr: usize,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    e: usize,
    f: usize,
) -> isize {
    let ret: isize;
    // SAFETY: this is the aarch64 Linux syscall sequence. The kernel preserves
    // every register except `x0`, which carries the result. `nostack` holds
    // because the sequence touches no memory through the stack pointer.
    unsafe {
        core::arch::asm!(
            "svc 0",
            in("x8") nr,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            in("x4") e,
            in("x5") f,
            options(nostack)
        );
    }
    ret
}

/// Defines the shorter forms, each padding the argument registers it does not
/// use with zero.
///
/// A syscall never reads past the arguments it declares, so the padding is
/// invisible to the kernel.
macro_rules! syscall_arity {
    ($($(#[$doc:meta])+ $name:ident($($arg:ident),+) $(, $pad:literal)*;)*) => {
        $(
            $(#[$doc])+
            ///
            /// # Safety
            ///
            /// The caller must uphold whatever contract the named syscall
            /// imposes, including the lifetime and alignment of any pointer
            /// passed in a register.
            #[inline]
            #[must_use]
            #[allow(clippy::many_single_char_names)]
            pub unsafe fn $name(nr: usize, $($arg: usize),+) -> isize {
                // SAFETY: the caller upholds the named syscall's contract,
                // and the padding registers are ones it does not declare.
                unsafe { syscall6(nr, $($arg,)+ $($pad),*) }
            }
        )*
    };
}

syscall_arity! {
    /// Issues a syscall with one argument.
    syscall1(a), 0, 0, 0, 0, 0;
    /// Issues a syscall with two arguments.
    syscall2(a, b), 0, 0, 0, 0;
    /// Issues a syscall with three arguments.
    syscall3(a, b, c), 0, 0, 0;
    /// Issues a syscall with four arguments.
    syscall4(a, b, c, d), 0, 0;
    /// Issues a syscall with five arguments.
    syscall5(a, b, c, d, e), 0;
}

/// Converts a descriptor into a syscall argument.
///
/// Descriptors are non-negative, and the one negative value the kernel
/// accepts, `AT_FDCWD`, is meant to reach it with its bit pattern intact.
#[inline]
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub fn arg_fd(fd: BorrowedFd<'_>) -> usize {
    fd.as_raw_fd() as usize
}

/// Converts a signed integer into a syscall argument, preserving its bits.
#[inline]
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub const fn arg_i32(value: i32) -> usize {
    value as isize as usize
}

/// Converts a 64-bit flag word into a syscall argument.
///
/// Only meaningful on 64-bit targets, which are the only ones this runtime
/// supports.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn arg_u64(value: u64) -> usize {
    value as usize
}

/// Converts a shared reference into a syscall argument.
#[inline]
#[must_use]
pub fn arg_ref<T>(value: &T) -> usize {
    std::ptr::from_ref(value) as usize
}

/// Converts a raw syscall return value into a `Result`.
#[inline]
pub const fn ret_usize(r: isize, context: &'static str) -> Result<usize> {
    if r < 0 {
        Err(Error::from_ret(r, context))
    } else {
        // Casting a non-negative isize to usize is always exact.
        #[allow(clippy::cast_sign_loss)]
        Ok(r as usize)
    }
}

/// Converts a raw syscall return value into a `Result` discarding the value.
#[inline]
pub const fn ret_unit(r: isize, context: &'static str) -> Result<()> {
    if r < 0 {
        Err(Error::from_ret(r, context))
    } else {
        Ok(())
    }
}

/// Wraps a descriptor the kernel wrote into an output parameter.
pub fn own_fd(raw: i32, context: &'static str) -> Result<OwnedFd> {
    if raw < 0 {
        return Err(Error::msg(context));
    }
    // SAFETY: the kernel just produced `raw` as a fresh descriptor owned by
    // this process, and nothing else holds it.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Converts a raw syscall return value into an owned file descriptor.
#[inline]
pub fn ret_fd(r: isize, context: &'static str) -> Result<OwnedFd> {
    if r < 0 {
        return Err(Error::from_ret(r, context));
    }
    own_fd(i32::try_from(r).map_err(|_| Error::msg(context))?, context)
}
