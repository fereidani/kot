//! Everything applied to the container process just before it runs.
//!
//! The order is the whole content of this module. Each step below depends on
//! the one before it having happened, and a container that applies them in a
//! different order is quietly less constrained than its configuration asked
//! for:
//!
//! 1. Resource limits, while the process still has the privilege to raise a
//!    hard limit if the configuration says so.
//! 2. Scheduling, I/O priority, execution domain and memory policy, which all
//!    need privilege that is about to be given up.
//! 3. Working directory, resolved inside the container.
//! 4. Group and user identity, which is where privilege is dropped.
//! 5. Capabilities, which have to be installed after the identity change
//!    because changing user id clears them.
//! 6. No-new-privileges, which has to precede the seccomp filter for an
//!    unprivileged install to be allowed.
//! 7. The seccomp filter, last, because installing it restricts what the steps
//!    above would have been able to do.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::{
    io::{FdFlags, fcntl_setfd},
    process::Pid,
};

use crate::{
    linux::mount::{Create, create_at},
    oci::plan::{Process, Section, View, codec::Str, process_flag},
    sys::{
        caps::CapSets,
        error::{Context, Error, Result},
        path::PathBuf,
        prctl, process as sys,
        raw::{arg_ref, nr, ret_unit, syscall4},
        seccomp::SockFilter,
    },
};

/// Applies the resource limits.
pub fn apply_rlimits(plan: &View<'_>) -> Result<()> {
    use rustix::process::{Rlimit, setrlimit};
    plan.rlimits(|limit| {
        let resource = resource_of(limit.resource)?;
        let value = Rlimit {
            current: (limit.soft != u64::MAX).then_some(limit.soft),
            maximum: (limit.hard != u64::MAX).then_some(limit.hard),
        };
        setrlimit(resource, value).context("rlimits: set")
    })
}

/// Raises `target`'s hard limits to what the plan asks for.
///
/// Only the part the container cannot do for itself: lowering a limit and
/// raising a soft one to the hard one need no privilege, raising a hard one
/// does. Nothing is lowered here, since the process is still being built and
/// a lower limit could fail a step it has yet to take.
pub fn raise_rlimits(plan: &View<'_>, target: Pid) -> Result<()> {
    use rustix::process::{Rlimit, getrlimit, prlimit};
    plan.rlimits(|limit| {
        let resource = resource_of(limit.resource)?;
        // The plan says no limit with the largest value there is, which is
        // what `None` means to the kernel.
        let wanted = (limit.hard != u64::MAX).then_some(limit.hard);
        let held = getrlimit(resource);
        let raises = match (wanted, held.maximum) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(wanted), Some(held)) => wanted > held,
        };
        if !raises {
            return Ok(());
        }
        let value = Rlimit {
            current: held.current,
            maximum: wanted,
        };
        prlimit(Some(target), resource, value)
            .map(|_| ())
            .context("rlimits: raise")
    })
}

fn resource_of(number: u32) -> Result<rustix::process::Resource> {
    use rustix::process::Resource;
    const RESOURCES: [Resource; 16] = [
        Resource::Cpu,
        Resource::Fsize,
        Resource::Data,
        Resource::Stack,
        Resource::Core,
        Resource::Rss,
        Resource::Nproc,
        Resource::Nofile,
        Resource::Memlock,
        Resource::As,
        Resource::Locks,
        Resource::Sigpending,
        Resource::Msgqueue,
        Resource::Nice,
        Resource::Rtprio,
        Resource::Rttime,
    ];
    RESOURCES
        .get(number as usize)
        .copied()
        .ok_or_else(|| Error::msg("rlimits: unknown limit"))
}

/// Restores every signal's disposition before the payload runs.
///
/// An ignored signal stays ignored across an execution, and the runtime
/// ignores a broken pipe for its own sake, as does anything that may have
/// started it. The payload would inherit that and be unable to be killed
/// with a signal it never chose to ignore.
pub fn reset_signal_dispositions() -> Result<()> {
    /// Highest signal number the kernel has.
    const LAST: u32 = 64;
    /// `SIGKILL` and `SIGSTOP`, neither of which has a disposition to set.
    const FIXED: [u32; 2] = [9, 19];

    for signal in 1..=LAST {
        if FIXED.contains(&signal) {
            continue;
        }
        match crate::sys::signalfd::restore_default(signal) {
            // The two the threading library keeps are refused by number.
            Err(e) if e.errno() == crate::sys::error::EINVAL => {}
            outcome => outcome?,
        }
    }
    Ok(())
}

/// Applies scheduling, I/O priority, execution domain and memory policy.
pub fn apply_scheduling(plan: &View<'_>, process: &Process) -> Result<()> {
    if process.has(process_flag::HAS_SCHEDULER) {
        let mut attr = sys::SchedAttr::new(process.sched_policy);
        attr.flags = process.sched_flags;
        attr.nice = process.sched_nice;
        attr.priority = process.sched_priority;
        attr.runtime = process.sched_runtime;
        attr.deadline = process.sched_deadline;
        attr.period = process.sched_period;
        sys::set_sched_attr(&attr)?;
    }
    if process.has(process_flag::HAS_IOPRIO) {
        sys::set_ioprio(process.ioprio_class, process.ioprio_priority)?;
    }
    if process.has(process_flag::HAS_PERSONALITY) {
        sys::personality(process.personality)?;
    }
    if process.has(process_flag::HAS_OOM_SCORE_ADJ) {
        set_oom_score_adj(process.oom_score_adj)?;
    }
    if process.has(process_flag::HAS_MEMPOLICY) {
        let nodes = parse_nodes(plan.text(process.mempolicy_nodes)?)?;
        let highest = nodes
            .iter()
            .rposition(|word| *word != 0)
            .map_or(0, |index| (index as u64 + 1) * 64);
        sys::set_mempolicy(
            process.mempolicy_mode | process.mempolicy_flags,
            &nodes,
            highest,
        )?;
    }
    Ok(())
}

/// Writes the out-of-memory score adjustment the configuration asked for.
///
/// Written here rather than by the driver because the value belongs to the
/// container's process, and written before privilege is dropped because
/// lowering the score needs a capability the payload may not keep.
fn set_oom_score_adj(value: i32) -> Result<()> {
    use rustix::fs::{Mode, OFlags, open};

    let mut rendered = PathBuf::<16>::new();
    rendered.push_i64(i64::from(value))?;
    let file = open(
        c"/proc/self/oom_score_adj",
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::from(e).describe("process: open oom_score_adj"))?;
    let written = rustix::io::write(&file, rendered.as_bytes())
        .map_err(|e| Error::from(e).describe("process: set oom_score_adj"))?;
    if written == rendered.as_bytes().len() {
        Ok(())
    } else {
        Err(Error::msg("process: short oom_score_adj write"))
    }
}

/// Words in a NUMA node mask, which caps the node number the plan may name.
const NODE_WORDS: usize = 16;

/// Parses a NUMA node list such as `0-3,7` into a bitmask.
fn parse_nodes(text: &str) -> Result<[u64; NODE_WORDS]> {
    let mut mask = [0u64; NODE_WORDS];
    if text.is_empty() {
        return Ok(mask);
    }
    for part in text.split(',') {
        let (first, last) = match part.split_once('-') {
            Some((a, b)) => (a, b),
            None => (part, part),
        };
        let parse = |value: &str| -> Result<usize> {
            value
                .trim()
                .parse()
                .map_err(|_| Error::msg("memoryPolicy: bad node list"))
        };
        let (first, last) = (parse(first)?, parse(last)?);
        if last < first || last >= NODE_WORDS * 64 {
            return Err(Error::msg("memoryPolicy: node out of range"));
        }
        for node in first..=last {
            if let Some(word) = mask.get_mut(node / 64) {
                *word |= 1u64 << (node % 64);
            }
        }
    }
    Ok(mask)
}

/// Changes to the container's working directory.
///
/// The directory is created when missing, as every other runtime does,
/// because images with a `WORKDIR` that no layer created depend on it.
pub fn enter_working_directory(
    plan: &View<'_>,
    process: &Process,
) -> Result<()> {
    use rustix::{
        fs::{Mode, OFlags, ResolveFlags, openat2},
        process::fchdir,
    };

    let cwd = plan.c_str(process.cwd)?;
    let open = || {
        openat2(
            rustix::fs::CWD,
            cwd,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
    };
    let directory =
        open().context("process: chdir to the working directory")?;
    fchdir(directory.as_fd()).context("process: chdir")
}

/// Takes the identity of the container's root, for the files the runtime
/// makes inside it.
///
/// Device nodes, the directories a mount lands on, a working directory the
/// image does not ship: all of them belong to the container. Made under the
/// runtime's own identity they belong to a user the container cannot name,
/// and on a filesystem its user namespace owns the kernel refuses them with
/// `EOVERFLOW` rather than record an owner it cannot express.
///
/// Only the filesystem identity changes, so no capability is given up and
/// the effective id stays what it was. A no-op outside a user namespace.
pub fn adopt_container_root() -> Result<()> {
    /// Root, as the namespace this process is in names it.
    const ROOT: u32 = 0;

    sys::set_fs_gid(ROOT)?;
    sys::set_fs_uid(ROOT)
}

/// Puts this process in a process group of its own.
///
/// A process group is named by a process id, and the group inherited from
/// outside a pid namespace has no name inside it: `getpgrp` answers zero and
/// nothing can signal the group. Starting one here gives it a name.
///
/// Not for a process that goes on to lead a session: `setsid` refuses a
/// process that already leads a group, and makes a group of its own anyway.
pub fn start_process_group() -> Result<()> {
    rustix::process::setpgid(None, None)
        .context("process: start a process group")
}

/// Creates the working directory when the image does not ship it.
///
/// Separate from entering it, and earlier, because it writes to the
/// container's filesystem: by the time the payload's settings are applied
/// the root may already be read only.
pub fn create_working_directory(
    plan: &View<'_>,
    process: &Process,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    let cwd = plan.c_str(process.cwd)?;
    let found = openat2(
        rustix::fs::CWD,
        cwd,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
    );
    match found {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == crate::sys::error::ENOENT => {
            create_directories(plan.raw(process.cwd)?)
        }
        Err(e) => Err(Error::from(e).describe("process: working directory")),
    }
}

/// Creates every missing component of a path inside the container.
fn create_directories(path: &[u8]) -> Result<()> {
    use crate::sys::path::Path;

    let mut partial = Path::new();
    partial.push_bytes(b"/")?;
    for component in crate::sys::path::components(path) {
        partial.join(component)?;
        create_at(
            rustix::fs::CWD,
            partial.as_c_str(),
            Create::Directories,
            "process: create directory",
        )?;
    }
    Ok(())
}

/// Gives the container's user the streams it was handed.
///
/// The payload inherits its streams from whoever started the runtime and
/// runs as whatever user the configuration names. Those are usually
/// different users, and a stream the payload cannot write to is a container
/// that looks like it produced nothing.
///
/// Devices are left alone: they are shared with the whole machine, and a
/// terminal the container gets is made for it with the right owner already.
/// A refusal is not an error, since the stream may belong to a user this
/// runtime cannot give away.
pub fn adopt_standard_streams(process: &Process) {
    use rustix::fs::{FileType, Gid, Uid, fchown, fstat};

    /// The mode bit that says anyone may write to the file.
    const OTHER_WRITE: u32 = 0o002;

    for number in 0..=2 {
        // SAFETY: the three standard descriptors are open for the life of
        // the process, and the borrow does not outlive this turn.
        let stream = unsafe { BorrowedFd::borrow_raw(number) };
        let Ok(stat) = fstat(stream) else { continue };
        let kind = FileType::from_raw_mode(stat.st_mode);
        if matches!(kind, FileType::CharacterDevice | FileType::BlockDevice) {
            continue;
        }
        if stat.st_uid == process.uid && stat.st_gid == process.gid {
            continue;
        }
        // A stream anyone may already write to needs no handing over, and
        // leaving it alone spares a host file an ownership change that
        // would have bought the container nothing.
        if stat.st_mode & OTHER_WRITE != 0 {
            continue;
        }
        let _ = fchown(
            stream,
            Some(Uid::from_raw(process.uid)),
            Some(Gid::from_raw(process.gid)),
        );
    }
}

/// Drops to the container's user and group.
///
/// Keeping capabilities across the change leaves the capability sets to be
/// installed afterwards; without it the kernel clears the permitted set the
/// moment the user id stops being zero.
pub fn drop_privileges(plan: &View<'_>, process: &Process) -> Result<()> {
    use rustix::{
        process::{Gid, Uid},
        thread::{set_thread_gid, set_thread_groups, set_thread_uid},
    };

    if process.has(process_flag::HAS_CAPS) {
        prctl::set_keep_caps(true)?;
    }

    if !process.has(process_flag::KEEP_ORIGINAL_GROUPS) {
        let mut gids = Vec::new();
        plan.additional_gids(&mut gids)?;
        let groups: Vec<Gid> = gids.into_iter().map(Gid::from_raw).collect();
        match set_thread_groups(&groups) {
            Ok(()) => {}
            // A user namespace whose gid map had to be written with
            // `setgroups` denied refuses the call outright. Where the
            // configuration named no groups that changes nothing, and
            // failing would stop every rootless container for a call it
            // never needed to make.
            Err(e)
                if groups.is_empty()
                    && matches!(
                        e.raw_os_error(),
                        crate::sys::error::EPERM | crate::sys::error::EINVAL
                    ) => {}
            // Where it did name groups, they are access the container was
            // meant to have. Carrying on would start it with an identity
            // the configuration did not describe and nothing to say so.
            Err(e) => {
                return Err(Error::from(e).describe("process: set groups"));
            }
        }
    }

    set_thread_gid(Gid::from_raw(process.gid))
        .context("process: set group id")?;
    set_thread_uid(Uid::from_raw(process.uid))
        .context("process: set user id")?;

    if process.has(process_flag::HAS_UMASK) {
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(process.umask));
    }
    Ok(())
}

/// Narrows the bounding set, before the user changes.
///
/// Separate from [`apply_capabilities`] because giving up a bounding
/// capability needs one the change of user takes away.
pub fn narrow_capabilities(process: &Process) -> Result<()> {
    if !process.has(process_flag::HAS_CAPS) {
        return Ok(());
    }
    crate::sys::caps::narrow(process.cap_bounding)
}

/// Installs the capability sets.
pub fn apply_capabilities(process: &Process) -> Result<()> {
    if !process.has(process_flag::HAS_CAPS) {
        return Ok(());
    }
    let sets = CapSets {
        effective: process.cap_effective,
        permitted: process.cap_permitted,
        inheritable: process.cap_inheritable,
        bounding: process.cap_bounding,
        ambient: process.cap_ambient,
    };
    crate::sys::caps::apply(&sets)
}

/// The magic number `statfs` reports for the kernel's process filesystem.
const PROC_SUPER_MAGIC: rustix::fs::FsWord = 0x0000_9fa0;

/// Applies the mandatory access control labels.
///
/// Both are written through `/proc/self`, and both only take effect at the
/// next `execve`, which is why they go last among the privilege steps.
pub fn apply_labels(plan: &View<'_>, process: &Process) -> Result<()> {
    write_label(
        plan,
        process.selinux,
        c"/proc/thread-self/attr/exec",
        "",
        "process: set selinux label",
    )?;
    // AppArmor wants a verb before the profile name; SELinux wants the label
    // alone. Getting this wrong silently leaves the process unconfined.
    write_label(
        plan,
        process.apparmor,
        c"/proc/self/attr/apparmor/exec",
        "exec ",
        "process: set apparmor profile",
    )
}

fn write_label(
    plan: &View<'_>,
    label: Str,
    path: &core::ffi::CStr,
    prefix: &str,
    failure: &'static str,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, open};

    if label.is_empty() {
        return Ok(());
    }
    let value = plan.raw(label)?;
    let file = open(
        path,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context(failure)?;

    // The label is written to a file in `/proc`, and by this point the
    // container's own mounts are in place. A configuration can mount
    // anything anywhere, including a writable filesystem of its own over
    // the path below: the write would then succeed against an ordinary
    // file, the runtime would report the label applied, and the payload
    // would run with no confinement at all. Only the kernel's own
    // filesystem can carry these attributes, so anything else is refused.
    let kind = rustix::fs::fstatfs(&file).context(failure)?;
    if kind.f_type != PROC_SUPER_MAGIC {
        return Err(Error::msg(
            "process: the label attribute is not on the kernel's own \
             filesystem",
        ));
    }

    let mut buffer = PathBuf::<512>::new();
    buffer.push_str(prefix)?;
    buffer.push_bytes(value)?;
    let written =
        rustix::io::write(&file, buffer.as_bytes()).context(failure)?;
    if written == buffer.as_bytes().len() {
        Ok(())
    } else {
        Err(Error::msg("process: short label write"))
    }
}

/// Installs the seccomp filter.
///
/// Returns the listener descriptor when the filter uses the notify action, so
/// the caller can hand it to whatever is supervising the container.
pub fn apply_seccomp(
    plan: &View<'_>,
    process: &Process,
    scratch: &mut Vec<SockFilter>,
) -> Result<Option<OwnedFd>> {
    if !process.has(process_flag::HAS_SECCOMP) {
        return Ok(None);
    }
    let bytes = plan.seccomp()?;
    if bytes.is_empty() {
        return Ok(None);
    }
    crate::oci::lower::seccomp::decode_program(bytes, scratch)?;

    let wants_listener = !plan.text(process.seccomp_listener)?.is_empty();
    if wants_listener {
        let listener = crate::sys::seccomp::set_mode_filter_listener(
            scratch,
            process.seccomp_flags,
        )?;
        return Ok(Some(listener));
    }
    crate::sys::seccomp::set_mode_filter(scratch, process.seccomp_flags)?;
    Ok(None)
}

/// Refuses any later gain of privilege.
pub fn apply_no_new_privs(process: &Process) -> Result<()> {
    if process.has(process_flag::NO_NEW_PRIVS) {
        prctl::set_no_new_privs()?;
    }
    Ok(())
}

/// The payload's arguments and environment, as the pointers `execve` takes.
///
/// Both borrow the plan's string section, which already stores every string
/// with a terminator, so nothing is copied.
pub struct Command {
    argv: Vec<*const u8>,
    envp: Vec<*const u8>,
    /// Variables the runtime adds, kept alive for as long as `envp` points
    /// into them.
    added: Vec<std::ffi::CString>,
}

impl Command {
    /// Collects the payload's arguments and environment from the plan.
    pub fn new(plan: &View<'_>) -> Result<Self> {
        let mut argv = Vec::new();
        let mut envp = Vec::new();
        let mut entries = Vec::new();

        Self::pointers(plan, Section::Args, &mut entries, &mut argv)?;
        Self::pointers(plan, Section::Env, &mut entries, &mut envp)?;

        if argv.len() < 2 {
            return Err(Error::msg("process: args is empty"));
        }
        Ok(Self {
            argv,
            envp,
            added: Vec::new(),
        })
    }

    /// Adds a variable the configuration did not set.
    ///
    /// The string is owned here, because unlike the rest of the environment
    /// it is not in the plan.
    fn add(&mut self, name: &str, value: &[u8]) -> Result<()> {
        let mut entry = Vec::with_capacity(name.len() + value.len() + 2);
        entry.extend_from_slice(name.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(value);
        let entry = std::ffi::CString::new(entry)
            .map_err(|_| Error::msg("process: the value has a nul in it"))?;
        let pointer = entry.as_ptr().cast::<u8>();
        self.added.push(entry);
        // The list ends with a null, and the new entry goes before it.
        let last = self.envp.len().saturating_sub(1);
        self.envp.insert(last, pointer);
        Ok(())
    }

    /// Gives the payload a home directory when the configuration named none.
    ///
    /// A program that finds no home writes wherever it falls back to, which
    /// for a shell is the working directory. The container's own passwd
    /// file decides, and the root directory is the answer when it says
    /// nothing about this user.
    ///
    /// Runs after the root has changed, so the file read is the container's.
    pub fn ensure_home(&mut self, uid: u32) -> Result<()> {
        if self.env("HOME").is_some() {
            return Ok(());
        }
        let mut passwd = Vec::new();
        let path = std::path::Path::new("/etc/passwd");
        let home = match crate::file::read_capped(path, PASSWD_MAX, &mut passwd)
        {
            Ok(()) => home_of(&passwd, uid).unwrap_or(b"/").to_vec(),
            Err(_) => b"/".to_vec(),
        };
        self.add("HOME", &home)
    }

    /// Tells the payload which process the sockets it was handed belong to.
    ///
    /// A service manager sets `LISTEN_FDS` and leaves `LISTEN_PID` to
    /// whoever starts the process, since only it knows the number. Inside a
    /// pid namespace that number is one, and a payload comparing its own id
    /// with the runtime's would ignore the sockets it was given.
    pub fn set_listen_pid(&mut self, pid: i32) -> Result<()> {
        if self.env("LISTEN_FDS").is_none() {
            return Ok(());
        }
        let mut text = crate::sys::path::Path::new();
        text.push_u64(u64::try_from(pid).unwrap_or(0))?;
        // Whoever started the runtime may have set one of its own, and a
        // payload reading the environment takes the first of two.
        self.remove("LISTEN_PID");
        self.add("LISTEN_PID", text.as_bytes())
    }

    /// Drops every entry naming `name` from the environment.
    fn remove(&mut self, name: &str) {
        self.envp.retain(|&entry| {
            if entry.is_null() {
                return true;
            }
            // SAFETY: as `program`.
            let text = unsafe { core::ffi::CStr::from_ptr(entry.cast()) };
            text.to_bytes()
                .strip_prefix(name.as_bytes())
                .is_none_or(|rest| rest.first() != Some(&b'='))
        });
    }

    /// Collects one string section as the pointers `execve` takes.
    fn pointers(
        plan: &View<'_>,
        section: Section,
        entries: &mut Vec<Str>,
        out: &mut Vec<*const u8>,
    ) -> Result<()> {
        plan.string_list(section, entries)?;
        for entry in &*entries {
            out.push(plan.c_str(*entry)?.as_ptr().cast::<u8>());
        }
        out.push(core::ptr::null());
        Ok(())
    }

    /// The program name, as the first argument.
    pub fn program(&self) -> Result<&core::ffi::CStr> {
        let Some(&first) = self.argv.first() else {
            return Err(Error::msg("process: args is empty"));
        };
        if first.is_null() {
            return Err(Error::msg("process: args is empty"));
        }
        // SAFETY: the pointer came from a `CStr` in the plan's string section,
        // which stays mapped for the life of the process.
        Ok(unsafe { core::ffi::CStr::from_ptr(first.cast()) })
    }

    /// The value of an environment variable, when it is set.
    #[must_use]
    pub fn env(&self, name: &str) -> Option<&str> {
        for &entry in &self.envp {
            if entry.is_null() {
                break;
            }
            // SAFETY: as `program`.
            let text = unsafe { core::ffi::CStr::from_ptr(entry.cast()) };
            let text = text.to_str().ok()?;
            if let Some(value) = text
                .strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
            {
                return Some(value);
            }
        }
        None
    }

    /// Replaces this process with the payload.
    ///
    /// Only returns on failure, which is why the return type is an error
    /// rather than a result.
    #[must_use]
    pub fn exec(&self, program: BorrowedFd<'_>) -> Error {
        // SAFETY: both arrays are NUL terminated and point into the mapped
        // plan, which outlives the call because the call does not return.
        let error = unsafe {
            sys::fexecve(program, self.argv.as_ptr(), self.envp.as_ptr())
        };
        if error.errno() != crate::sys::error::ENOENT {
            return error;
        }
        // A script is read by its interpreter through `/dev/fd/<number>`,
        // which the kernel will not arrange for a descriptor that closes on
        // the execution, and it says so with the errno of a program that is
        // not there. Keeping it open is what an interpreted payload needs;
        // a missing one fails the same way twice.
        if fcntl_setfd(program, FdFlags::empty()).is_err() {
            return error;
        }
        // SAFETY: as above.
        unsafe { sys::fexecve(program, self.argv.as_ptr(), self.envp.as_ptr()) }
    }
}

/// Most of a passwd file this reads looking for a home directory. A file
/// larger than this is not one a container's own accounts fill.
const PASSWD_MAX: usize = 1 << 20;

/// The home directory a passwd file gives `uid`.
///
/// Seven colon separated fields per line, the third the user id and the
/// sixth the home directory. A shorter line is skipped: the file belongs to
/// the image, and one malformed account is no reason to refuse to start.
fn home_of(passwd: &[u8], uid: u32) -> Option<&[u8]> {
    for line in passwd.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b':');
        let (Some(_name), Some(_password), Some(id)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let matches = core::str::from_utf8(id)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
            == Some(uid);
        if !matches {
            continue;
        }
        let (Some(_gid), Some(_comment), Some(home)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !home.is_empty() {
            return Some(home);
        }
    }
    None
}

/// True when a descriptor names a regular file.
///
/// Opened with `O_PATH`, so this is the only way to tell what was resolved.
fn is_regular_file(fd: BorrowedFd<'_>) -> bool {
    use rustix::fs::{FileType, fstat};
    fstat(fd).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
    })
}

/// True when a descriptor names something that can be executed.
///
/// The answer covers the mount as well as the file, so a program on a mount
/// the configuration asked to be `noexec` is refused here rather than by the
/// execution itself, where there is nobody left to report it to.
fn is_executable(fd: BorrowedFd<'_>) -> bool {
    /// `X_OK`.
    const X_OK: usize = 1;
    /// `AT_EMPTY_PATH`.
    const AT_EMPTY_PATH: usize = 0x1000;

    // SAFETY: the path is an empty NUL terminated string, which
    // `AT_EMPTY_PATH` makes the kernel ignore in favour of the descriptor.
    let r = unsafe {
        syscall4(
            nr::FACCESSAT2,
            fd.as_raw_fd().unsigned_abs() as usize,
            arg_ref(&0u8),
            X_OK,
            AT_EMPTY_PATH,
        )
    };
    ret_unit(r, "process: check the payload").is_ok()
}

/// Resolves the payload inside the container.
///
/// A name with no separator is looked up along `PATH`, which the specification
/// requires and which images rely on. Every candidate is opened with the
/// kernel confining the resolution, and it is the descriptor that gets
/// executed, so there is no window in which the container could swap the file.
pub fn resolve_program(command: &Command) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    use crate::sys::path::Path;

    let program = command.program()?;
    let bytes = program.to_bytes();

    // `RESOLVE_IN_ROOT` makes the directory it resolves from the root of
    // the resolution, so an absolute path has to start at the container's
    // root: otherwise `/init` would mean `/init` under `process.cwd`.
    let root = rustix::fs::open(
        c"/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("process: open the container root")?;

    let open = |path: &core::ffi::CStr| {
        let (at, path) = match path.to_bytes().strip_prefix(b"/") {
            // Every component past the first separator, which the root
            // descriptor now stands for. A path of just separators names the
            // root itself, which is not a program.
            Some(rest) => (root.as_fd(), Path::from(rest)?),
            None => (rustix::fs::CWD, Path::from(path.to_bytes())?),
        };
        let fd = openat2(
            at,
            path.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            // Confinement and the refusal to follow a magic link are both the
            // kernel's job here. The second keeps an entrypoint that is a link
            // to `/proc/self/exe` from resolving to the runtime.
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(Error::from)
        .context("process: open payload")?;
        // A directory or a device is not a program. Refusing it here names
        // the configuration rather than the syscall, and lets the search
        // along `PATH` pass over a directory of the program's name.
        if !is_regular_file(fd.as_fd()) {
            return Err(Error::new(
                crate::sys::error::EPERM,
                "process: the payload is not a regular file",
            ));
        }
        if !is_executable(fd.as_fd()) {
            return Err(Error::new(
                crate::sys::error::EACCES,
                "process: the payload cannot be executed",
            ));
        }
        Ok(fd)
    };

    if bytes.contains(&b'/') {
        return open(program);
    }

    let path = command.env("PATH").unwrap_or(
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    for directory in path.split(':') {
        let mut candidate = Path::new();
        if directory.is_empty() {
            candidate.push_bytes(b".")?;
        } else {
            candidate.push_str(directory)?;
        }
        candidate.join(bytes)?;
        if let Ok(fd) = open(candidate.as_c_str()) {
            return Ok(fd);
        }
    }
    Err(Error::new(
        crate::sys::error::ENOENT,
        "process: payload not found in PATH",
    ))
}
