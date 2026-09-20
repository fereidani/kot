//! `clone3(2)`, which creates the container init process.
//!
//! Also used by `exec`, and a second time by init itself when a pid namespace
//! has to be entered by a child.

use crate::sys::{
    error::{Error, Result},
    raw::{arg_ref, nr, ret_usize, syscall2},
};

/// New mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// New cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
/// New UTS namespace.
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// New IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// New user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// New PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// New network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// New time namespace.
pub const CLONE_NEWTIME: u64 = 0x0000_0080;
/// Place the child directly into the cgroup named by `clone_args.cgroup`.
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Every namespace flag, used to mask a requested set.
pub const CLONE_ALL_NAMESPACES: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME;

/// The kernel's `struct clone_args`, third revision.
#[repr(C, align(8))]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Which side of a `clone3` call the current code is running on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fork {
    /// The calling process, carrying the child's pid.
    Parent(i32),
    /// The newly created process.
    Child,
}

/// Arguments for creating the container init process.
///
/// `CLONE_VM` and `CLONE_VFORK` are deliberately not expressible: the child
/// must get its own address space, both because the raw syscall wrapper
/// assumes it and because sharing one with the driver would defeat the
/// isolation the runtime is built to provide.
#[derive(Clone, Copy, Default)]
pub struct CloneSpec {
    namespaces: u64,
    exit_signal: u64,
    cgroup_fd: Option<i32>,
}

impl CloneSpec {
    /// A clone that creates no namespaces and sends `SIGCHLD` on exit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exit_signal: SIGCHLD,
            ..Self::default()
        }
    }

    /// Sets the namespaces to create, as a mask of `CLONE_NEW*`.
    #[must_use]
    pub const fn namespaces(mut self, mask: u64) -> Self {
        self.namespaces = mask & CLONE_ALL_NAMESPACES;
        self
    }

    /// Places the child directly into the cgroup that `fd` refers to, which
    /// saves a write to `cgroup.procs` and closes the window in which the
    /// child runs outside its limits.
    #[must_use]
    pub const fn into_cgroup(mut self, fd: i32) -> Self {
        self.cgroup_fd = Some(fd);
        self
    }

    /// Creates the child process.
    ///
    /// Returns [`Fork::Parent`] in the caller and [`Fork::Child`] in the new
    /// process.
    ///
    /// # Safety
    ///
    /// The child continues on a copy-on-write image of the caller's address
    /// space. The caller must be single-threaded, or must guarantee that the
    /// child touches nothing another thread could have left inconsistent.
    pub unsafe fn spawn(&self) -> Result<Fork> {
        let mut args = CloneArgs {
            flags: self.namespaces,
            exit_signal: self.exit_signal,
            ..CloneArgs::default()
        };
        if let Some(fd) = self.cgroup_fd {
            args.flags |= CLONE_INTO_CGROUP;
            args.cgroup = u64::from(fd.unsigned_abs());
        }

        let size = core::mem::size_of::<CloneArgs>();
        // SAFETY: `args` is a correctly shaped and aligned `struct
        // clone_args` that outlives the call, `size` is its exact length, and
        // no `CLONE_VM`/`CLONE_VFORK` is set, so the child gets its own stack.
        let r = unsafe { syscall2(nr::CLONE3, arg_ref(&args), size) };
        let pid = ret_usize(r, "clone3")?;
        if pid == 0 {
            return Ok(Fork::Child);
        }

        let pid = i32::try_from(pid)
            .map_err(|_| Error::msg("clone3: pid overflow"))?;
        Ok(Fork::Parent(pid))
    }
}

/// Signal delivered to the parent when a cloned child exits.
pub const SIGCHLD: u64 = 17;
