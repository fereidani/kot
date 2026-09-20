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

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::{
    linux::mount::{Create, create_at},
    oci::plan::{Process, Section, View, codec::Str, process_flag},
    sys::{
        caps::CapSets,
        error::{Context, Error, Result},
        path::PathBuf,
        prctl, process as sys,
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
    let directory = match open() {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == crate::sys::error::ENOENT => {
            create_directories(plan.raw(process.cwd)?)?;
            open().context("process: open working directory")?
        }
        Err(e) => {
            return Err(Error::from(e).describe("process: working directory"));
        }
    };
    fchdir(directory.as_fd()).context("process: enter working directory")
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
            // An unprivileged user namespace refuses `setgroups` outright, and
            // the driver already wrote `deny` to say so. Failing here would
            // stop every rootless container.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    crate::sys::error::EPERM | crate::sys::error::EINVAL
                ) => {}
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
    let file = open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .context(failure)?;

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
        Ok(Self { argv, envp })
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
        unsafe { sys::fexecve(program, self.argv.as_ptr(), self.envp.as_ptr()) }
    }
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
    if bytes.is_empty() {
        return Err(Error::msg("process: args[0] is empty"));
    }

    let open = |path: &core::ffi::CStr| {
        openat2(
            rustix::fs::CWD,
            path,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            // Confinement and the refusal to follow a magic link are both the
            // kernel's job here. The second keeps an entrypoint that is a link
            // to `/proc/self/exe` from resolving to the runtime.
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        )
    };

    if bytes.contains(&b'/') {
        return open(program).context("process: open payload");
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
