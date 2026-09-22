//! Process-level syscalls: namespace entry, execution, scheduling, and the
//! smaller knobs the OCI configuration exposes.

use core::ffi::CStr;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use crate::sys::{
    error::{Error, Result},
    path,
    raw::{
        arg_fd, arg_i32, arg_ref, arg_u64, nr, ret_unit, ret_usize, syscall1,
        syscall2, syscall3, syscall5,
    },
};

/// Operate on the descriptor itself, with an empty path.
pub const AT_EMPTY_PATH: usize = 0x1000;

/// Joins the namespace that `fd` refers to.
///
/// When `fd` is a pidfd, `nstype` may be a mask of several `CLONE_NEW*` flags
/// and the kernel joins all of them in one call. When it is a namespace file
/// from `/proc/<pid>/ns/`, `nstype` is either zero or the single matching
/// flag.
pub fn setns(fd: BorrowedFd<'_>, nstype: u64) -> Result<()> {
    // SAFETY: both arguments are scalars and `fd` is valid for the call.
    let r = unsafe { syscall2(nr::SETNS, arg_fd(fd), arg_u64(nstype)) };
    ret_unit(r, "setns")
}

/// Arranges for a command's child to join `namespaces` before it executes.
///
/// The descriptors are opened by the caller, before the fork, because between
/// the fork and the execution a child may only call what is
/// async-signal-safe: it cannot open anything, and it cannot allocate.
///
/// The order is the caller's, and it matters: a user namespace decides what
/// the joins after it may do, and a mount namespace changes what every path
/// means, so those belong at the ends.
pub fn join_before_exec(
    command: &mut std::process::Command,
    namespaces: Vec<OwnedFd>,
    directory: Option<std::ffi::CString>,
    enters_pid_namespace: bool,
) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: the closure runs in the forked child, which has one thread,
    // between the fork and `execve`. Everything it calls is
    // async-signal-safe and allocates nothing: `setns`, `chdir`, and, for a
    // pid namespace, a further `clone`, `waitpid` and `exit_group`. It
    // touches no descriptor it was not already handed.
    unsafe {
        command.pre_exec(move || {
            for fd in &namespaces {
                setns(fd.as_fd(), 0).map_err(|error| {
                    std::io::Error::from_raw_os_error(error.errno())
                })?;
            }
            // After the joins, not before: a working directory set before
            // them names a directory in the namespace left behind, and the
            // program would come up somewhere with no path at all.
            if let Some(directory) = directory.as_deref() {
                rustix::process::chdir(directory).map_err(|error| {
                    std::io::Error::from_raw_os_error(error.raw_os_error())
                })?;
            }
            // `setns` puts a process's children in a pid namespace, never
            // the process itself, so without one more fork the program
            // would run beside the container on the host's process
            // numbers. This process stays behind as a proxy for it.
            if enters_pid_namespace {
                enter_pid_namespace()?;
            }
            Ok(())
        });
    }
}

/// What a proxy that goes away takes its child down with.
const SIGKILL_NUMBER: i32 = 9;

/// Forks so that the caller's program is inside the pid namespace already
/// joined, and turns the caller into a proxy for it.
///
/// Returns only in the child. The proxy waits and exits with what the child
/// did, without unwinding: it is a forked copy of a process that was about
/// to execute something else, and none of that state is its to undo.
fn enter_pid_namespace() -> std::io::Result<()> {
    use crate::sys::clone::{CloneSpec, Fork};

    // SAFETY: this runs between a fork and an execution, in a process with
    // one thread, and the child only ever returns to the caller's execution.
    let side = unsafe { CloneSpec::new().spawn() }
        .map_err(|error| std::io::Error::from_raw_os_error(error.errno()))?;
    let pid = match side {
        Fork::Child => {
            // The runtime holds the proxy, and kills it when a hook
            // outstays its timeout. Without this the hook would survive
            // that, reparented onto the container's init.
            crate::sys::prctl::set_pdeathsig(SIGKILL_NUMBER).map_err(
                |error| std::io::Error::from_raw_os_error(error.errno()),
            )?;
            return Ok(());
        }
        Fork::Parent(pid) => pid,
    };
    // One of the inherited descriptors decides whether the caller ever gets
    // its child back: the standard library learns that an execution
    // succeeded when the socket it handed the child closes, which takes
    // every copy. The copy that means anything is the one held by the
    // process that executes, so this one goes. Nothing below needs a
    // descriptor.
    let _ = close_range(3, u32::MAX, 0);
    let status = wait_for_child(pid);
    exit_group(status)
}

/// Ends this process and every thread in it, without unwinding anything.
#[allow(clippy::cast_sign_loss)]
fn exit_group(status: i32) -> ! {
    // Bounded: the kernel does not return from this, and the loop is only
    // there because the compiler cannot know that.
    loop {
        // SAFETY: the single argument is a scalar, and the call does not
        // return.
        unsafe {
            let _ = syscall1(nr::EXIT_GROUP, status as usize);
        }
    }
}

/// Waits for one child and renders its end as an exit status.
fn wait_for_child(pid: i32) -> i32 {
    use rustix::process::{Pid, WaitOptions, waitpid};

    /// What a shell reports for a program a signal ended.
    const SIGNALLED: i32 = 128;

    let Some(pid) = Pid::from_raw(pid) else {
        return 1;
    };
    // Bounded: only an interrupted wait repeats.
    for _ in 0..1024 {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                if let Some(code) = status.exit_status() {
                    return code;
                }
                if let Some(signal) = status.terminating_signal() {
                    return SIGNALLED + signal;
                }
                return 1;
            }
            Ok(None) => {}
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(_) => return 1,
        }
    }
    1
}

/// Sets the filesystem user id.
///
/// The call reports no failure: an id the current user namespace does not
/// map leaves the old one in place and still looks like success, so the
/// only way to know is to ask again.
pub fn set_fs_uid(uid: u32) -> Result<()> {
    // SAFETY: the single argument is a scalar.
    let previous = unsafe { syscall1(nr::SETFSUID, uid as usize) };
    // The answer is the id that was in force. Finding the one asked for
    // settles it without a second call: nothing changed because nothing
    // had to.
    if u32::try_from(previous).is_ok_and(|current| current == uid) {
        return Ok(());
    }
    // SAFETY: as above. The answer is what the call before it left in
    // place, which is the id now in force.
    let now = unsafe { syscall1(nr::SETFSUID, uid as usize) };
    if u32::try_from(now).is_ok_and(|current| current == uid) {
        return Ok(());
    }
    Err(Error::msg(
        "process: the container's user namespace does not map a root user \
         for the runtime to build its filesystem as",
    ))
}

/// The same for the group, whose failure is reported the same way.
pub fn set_fs_gid(gid: u32) -> Result<()> {
    // SAFETY: the single argument is a scalar.
    let previous = unsafe { syscall1(nr::SETFSGID, gid as usize) };
    if u32::try_from(previous).is_ok_and(|current| current == gid) {
        return Ok(());
    }
    // SAFETY: as above.
    let now = unsafe { syscall1(nr::SETFSGID, gid as usize) };
    if u32::try_from(now).is_ok_and(|current| current == gid) {
        return Ok(());
    }
    Err(Error::msg(
        "process: the container's user namespace does not map a root group \
         for the runtime to build its filesystem as",
    ))
}

/// Translates an id through the contents of a `uid_map` or `gid_map`.
///
/// Each line is a container id, the host id it starts at, and how many ids
/// the range covers. Answers `None` for an id no range holds, and for a map
/// whose arithmetic does not fit the id space, which a kernel does not write
/// but a reader has no way to rule out.
#[must_use]
pub fn translate_id(map: &str, id: u32) -> Option<u32> {
    for line in map.lines() {
        let mut fields = line.split_whitespace();
        let (Some(inside), Some(outside), Some(count)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(inside), Ok(outside), Ok(count)) = (
            inside.parse::<u32>(),
            outside.parse::<u32>(),
            count.parse::<u32>(),
        ) else {
            continue;
        };
        let Some(offset) = id.checked_sub(inside) else {
            continue;
        };
        if offset < count {
            return outside.checked_add(offset);
        }
    }
    None
}

/// Executes the program that `fd` refers to.
///
/// Taking the program as a descriptor rather than a path closes the window
/// between checking a path and executing it, which matters because the
/// container controls the filesystem the path is resolved in.
///
/// # Safety
///
/// `argv` and `envp` must be NUL-terminated arrays of NUL-terminated strings
/// that stay valid for the duration of the call.
#[must_use]
pub unsafe fn fexecve(
    fd: BorrowedFd<'_>,
    argv: *const *const u8,
    envp: *const *const u8,
) -> Error {
    // SAFETY: the caller guarantees the shape and lifetime of `argv` and
    // `envp`; `AT_EMPTY_PATH` makes the kernel ignore the empty path and use
    // the descriptor instead. Like `execveat`, this only returns on failure.
    unsafe { execveat(fd, path::EMPTY, argv, envp, AT_EMPTY_PATH) }
}

/// Executes `path` relative to `dirfd`, returning only on failure.
///
/// # Safety
///
/// As [`fexecve`].
#[must_use]
pub unsafe fn execveat(
    dirfd: BorrowedFd<'_>,
    path: &CStr,
    argv: *const *const u8,
    envp: *const *const u8,
    flags: usize,
) -> Error {
    // SAFETY: the caller guarantees the shape and lifetime of `argv` and
    // `envp`, and `CStr` guarantees `path` is NUL terminated.
    let r = unsafe {
        syscall5(
            nr::EXECVEAT,
            arg_fd(dirfd),
            path.as_ptr() as usize,
            argv as usize,
            envp as usize,
            flags,
        )
    };
    Error::from_ret(r, "execveat")
}

/// Duplicates `old` onto `new`, closing whatever was there.
///
/// Taking raw numbers is deliberate: this renumbers a descriptor table onto
/// fixed slots, where the target is a number rather than something the caller
/// owns.
///
/// # Safety
///
/// `old` must name a descriptor this process owns. Anything currently at `new`
/// is closed, so the caller must not be holding it through a safe wrapper.
pub unsafe fn dup3(old: i32, new: i32, flags: u32) -> Result<()> {
    // SAFETY: all three arguments are scalars; the caller upholds the
    // descriptor ownership contract described above.
    let r = unsafe {
        syscall3(nr::DUP3, arg_i32(old), arg_i32(new), flags as usize)
    };
    ret_unit(r, "dup3")
}

/// Closes every descriptor from `first` to `last`, inclusive.
///
/// Used once, just before the payload runs, to make sure the container starts
/// with exactly the descriptors it was promised and nothing the runtime
/// happened to be holding.
pub fn close_range(first: u32, last: u32, flags: u32) -> Result<()> {
    // SAFETY: all three arguments are scalars. Closing a range the caller has
    // finished with is the operation's whole purpose.
    let r = unsafe {
        syscall3(
            nr::CLOSE_RANGE,
            first as usize,
            last as usize,
            flags as usize,
        )
    };
    ret_unit(r, "close_range")
}

/// Execution domain: native Linux.
pub const PER_LINUX: u64 = 0x0000_0000;
/// Execution domain: report a 32 bit machine from `uname`.
pub const PER_LINUX32: u64 = 0x0000_0008;
/// Execution domain flag: lay the address space out the same way every run.
pub const ADDR_NO_RANDOMIZE: u64 = 0x0004_0000;

/// Sets the execution domain for the calling process.
pub fn personality(persona: u64) -> Result<()> {
    // SAFETY: the single argument is a scalar.
    let r = unsafe { syscall1(nr::PERSONALITY, arg_u64(persona)) };
    ret_unit(r, "personality")
}

/// I/O priority class: real time.
pub const IOPRIO_CLASS_RT: u32 = 1;
/// I/O priority class: best effort.
pub const IOPRIO_CLASS_BE: u32 = 2;
/// I/O priority class: idle.
pub const IOPRIO_CLASS_IDLE: u32 = 3;

const IOPRIO_WHO_PROCESS: usize = 1;
const IOPRIO_CLASS_SHIFT: u32 = 13;

/// Sets the calling process's I/O priority.
pub fn set_ioprio(class: u32, priority: u32) -> Result<()> {
    let value = (class << IOPRIO_CLASS_SHIFT) | (priority & 0x1fff);
    // SAFETY: all three arguments are scalars.
    let r = unsafe {
        syscall3(nr::IOPRIO_SET, IOPRIO_WHO_PROCESS, 0, value as usize)
    };
    ret_unit(r, "ioprio_set")
}

/// Scheduling policy: the default time-sharing policy.
pub const SCHED_OTHER: u32 = 0;
/// Scheduling policy: first in, first out real time.
pub const SCHED_FIFO: u32 = 1;
/// Scheduling policy: round robin real time.
pub const SCHED_RR: u32 = 2;
/// Scheduling policy: batch.
pub const SCHED_BATCH: u32 = 3;
/// Scheduling policy: idle.
pub const SCHED_IDLE: u32 = 5;
/// Scheduling policy: earliest deadline first.
pub const SCHED_DEADLINE: u32 = 6;

/// Scheduling flag: revert to the default policy in children.
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 0x01;
/// Scheduling flag: reclaim unused deadline bandwidth.
pub const SCHED_FLAG_RECLAIM: u64 = 0x02;
/// Scheduling flag: send `SIGXCPU` when a deadline task overruns.
pub const SCHED_FLAG_DL_OVERRUN: u64 = 0x04;
/// Scheduling flag: keep the current policy.
pub const SCHED_FLAG_KEEP_POLICY: u64 = 0x08;

/// The kernel's `struct sched_attr`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SchedAttr {
    size: u32,
    /// One of the `SCHED_*` policies.
    pub policy: u32,
    /// A mask of `SCHED_FLAG_*`.
    pub flags: u64,
    /// Nice value, for the time-sharing policies.
    pub nice: i32,
    /// Static priority, for the real-time policies.
    pub priority: u32,
    /// Deadline policy: runtime budget in nanoseconds.
    pub runtime: u64,
    /// Deadline policy: relative deadline in nanoseconds.
    pub deadline: u64,
    /// Deadline policy: period in nanoseconds.
    pub period: u64,
}

impl SchedAttr {
    /// Builds an attribute block with the size field filled in.
    #[must_use]
    pub fn new(policy: u32) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        Self {
            size: core::mem::size_of::<Self>() as u32,
            policy,
            ..Self::default()
        }
    }
}

/// Applies a scheduling policy to the calling process.
pub fn set_sched_attr(attr: &SchedAttr) -> Result<()> {
    // SAFETY: `attr` is a correctly shaped `struct sched_attr` whose `size`
    // field matches its own length, and it outlives the call.
    let r = unsafe { syscall3(nr::SCHED_SETATTR, 0, arg_ref(attr), 0) };
    ret_unit(r, "sched_setattr")
}

/// `KEYCTL_JOIN_SESSION_KEYRING`
const KEYCTL_JOIN_SESSION_KEYRING: usize = 1;

/// Creates a fresh session keyring named `name`.
///
/// Containers get their own keyring so that keys added inside one are not
/// visible to the host or to other containers.
pub fn join_session_keyring(name: &CStr) -> Result<usize> {
    // SAFETY: `name` is NUL terminated and outlives the call.
    let r = unsafe {
        syscall2(
            nr::KEYCTL,
            KEYCTL_JOIN_SESSION_KEYRING,
            name.as_ptr() as usize,
        )
    };
    ret_usize(r, "keyctl(JOIN_SESSION_KEYRING)")
}

/// Memory policy: system default.
pub const MPOL_DEFAULT: u32 = 0;
/// Memory policy: prefer one node.
pub const MPOL_PREFERRED: u32 = 1;
/// Memory policy: allocate only from the given nodes.
pub const MPOL_BIND: u32 = 2;
/// Memory policy: interleave across the given nodes.
pub const MPOL_INTERLEAVE: u32 = 3;
/// Memory policy: allocate from the local node.
pub const MPOL_LOCAL: u32 = 4;
/// Memory policy: prefer any of the given nodes.
pub const MPOL_PREFERRED_MANY: u32 = 5;
/// Memory policy: interleave with per-node weights.
pub const MPOL_WEIGHTED_INTERLEAVE: u32 = 6;

/// Memory policy flag: node numbers are relative to the allowed set.
pub const MPOL_F_RELATIVE_NODES: u32 = 1 << 14;
/// Memory policy flag: node numbers are absolute.
pub const MPOL_F_STATIC_NODES: u32 = 1 << 15;
/// Memory policy flag: enable NUMA balancing for the mapping.
pub const MPOL_F_NUMA_BALANCING: u32 = 1 << 13;

/// Sets the calling process's NUMA memory policy.
///
/// `nodes` is a bitmask of node numbers, and `max_node` is one past the
/// highest node the mask covers.
///
/// The kernel takes one more than that: `get_nodes` decrements what it is
/// given before counting words, so the count on the wire is the number of bits
/// plus one. libnuma sends the same, and sending `max_node` itself would leave
/// the highest node out of the mask.
pub fn set_mempolicy(mode: u32, nodes: &[u64], max_node: u64) -> Result<()> {
    let ptr = if nodes.is_empty() {
        0
    } else {
        nodes.as_ptr() as usize
    };
    // SAFETY: `nodes` outlives the call, and `max_node` bounds how much of it
    // the kernel reads.
    let r = unsafe {
        syscall3(
            nr::SET_MEMPOLICY,
            mode as usize,
            ptr,
            arg_u64(max_node.saturating_add(1)),
        )
    };
    ret_unit(r, "set_mempolicy")
}

/// The highest CPU number an affinity mask here can name.
///
/// The kernel's own set grows with the machine, but a runtime that has to
/// keep its stack bounded cannot follow it. A thousand and twenty-four is
/// the width the C library has used for decades and more than any host this
/// runtime targets; a configuration naming a higher CPU is refused rather
/// than silently confined to the ones that fit.
pub const MAX_CPUS: usize = 1024;

/// How many words the mask takes.
const AFFINITY_WORDS: usize = MAX_CPUS / 64;

/// A set of CPUs, laid out the way `sched_setaffinity` reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuSet {
    words: [u64; AFFINITY_WORDS],
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            words: [0; AFFINITY_WORDS],
        }
    }

    /// Adds one CPU to the set.
    pub fn add(&mut self, cpu: usize) -> Result<()> {
        let Some(word) = self.words.get_mut(cpu / 64) else {
            return Err(Error::msg("affinity: CPU number out of range"));
        };
        *word |= 1u64 << (cpu % 64);
        Ok(())
    }

    /// Whether the set names `cpu`.
    #[must_use]
    pub fn contains(&self, cpu: usize) -> bool {
        self.words
            .get(cpu / 64)
            .is_some_and(|word| word & (1u64 << (cpu % 64)) != 0)
    }

    /// Whether the set names nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Parses the list form the configuration states, such as `0-3,8`.
    ///
    /// An empty set is refused: a process has to be able to run somewhere,
    /// and the kernel rejects the call anyway, later and less clearly.
    pub fn parse(list: &str) -> Result<Self> {
        let mut set = Self::new();
        // Bounded by the text: each iteration consumes one comma-separated
        // item, and there are fewer of those than there are characters.
        for item in list.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (low, high) = if let Some((low, high)) = item.split_once('-') {
                (parse_cpu(low)?, parse_cpu(high)?)
            } else {
                let only = parse_cpu(item)?;
                (only, only)
            };
            if high < low {
                return Err(Error::msg(
                    "affinity: range ends before it starts",
                ));
            }
            for cpu in low..=high {
                set.add(cpu)?;
            }
        }
        if set.is_empty() {
            return Err(Error::msg("affinity: names no CPU at all"));
        }
        Ok(set)
    }
}

/// Parses one CPU number, refusing anything the mask cannot hold.
fn parse_cpu(text: &str) -> Result<usize> {
    let cpu: usize = text
        .trim()
        .parse()
        .map_err(|_| Error::msg("affinity: expected a CPU number"))?;
    if cpu >= MAX_CPUS {
        return Err(Error::msg("affinity: CPU number out of range"));
    }
    Ok(cpu)
}

/// Confines a process to `set`, or the calling thread when `pid` is zero.
///
/// The set is inherited across `execve`, which is what lets the runtime
/// place a process before handing it the program it was asked to run.
pub fn set_affinity(pid: i32, set: &CpuSet) -> Result<()> {
    // SAFETY: the kernel reads `size` bytes from the mask, and `size` is that
    // array's own length in bytes. The array outlives the call.
    let r = unsafe {
        syscall3(
            nr::SCHED_SETAFFINITY,
            arg_i32(pid),
            core::mem::size_of_val(&set.words),
            arg_ref(&set.words),
        )
    };
    ret_unit(r, "sched_setaffinity")
}
