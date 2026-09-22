//! Checking a configuration before any of it is applied.
//!
//! Everything here answers a question that would otherwise be answered halfway
//! through building a container, when undoing the answer is expensive and the
//! error message is poor. Refusing a configuration is also the only correct
//! response to one the runtime cannot honour: quietly applying less than was
//! asked for is a security failure, not a compatibility feature.

use anyhow::{Result, bail, ensure};

use crate::{
    oci::{Spec, spec},
    seccomp::Action,
};

/// The range of specification versions this build implements.
pub const OCI_VERSION_MIN: &str = "1.0.0";
/// The newest specification version this build implements.
pub const OCI_VERSION_MAX: &str = "1.3.0";

/// Checks a configuration.
pub fn spec(spec: &Spec<'_>) -> Result<()> {
    ensure!(!spec.version.is_empty(), "config.json has no ociVersion");
    check_version(spec.version)?;

    if let Some(platform) = spec.foreign_platforms.first() {
        bail!(
            "config.json has a {platform} section, which this runtime does \
             not implement; refusing rather than ignoring it"
        );
    }

    let Some(root) = spec.root.as_ref() else {
        bail!("config.json has no root");
    };
    ensure!(!root.path.is_empty(), "config.json has an empty root path");

    if let Some(process) = spec.process.as_ref() {
        check_process(process)?;
    }

    // A key with no name cannot be looked up, and the state document this
    // runtime prints would carry it as an empty string.
    for (key, _) in &spec.annotations {
        ensure!(!key.is_empty(), "an annotation key must not be empty");
    }

    for mount in &spec.mounts {
        ensure!(
            mount.destination.starts_with('/'),
            "mount destination {} must be absolute",
            mount.destination
        );
    }

    check_mount_namespace(spec.linux.as_ref())?;
    check_uts_namespace(spec)?;

    let Some(linux) = spec.linux.as_ref() else {
        return Ok(());
    };
    check_namespaces(linux)?;
    check_time_offsets(linux)?;
    check_unimplemented(linux)?;
    check_id_maps(linux)?;
    check_seccomp(linux)?;
    check_sysctls(spec, linux)?;
    Ok(())
}

/// Refuses a parameter the container would set on the host, or set twice.
///
/// A kernel parameter belongs to a namespace, so writing one from a
/// container that shares that namespace with the host changes the host's,
/// and the write succeeds while it does it.
///
/// The container's name is the other half: it has a field of its own, and a
/// configuration that also names it as a parameter, differently, asks for
/// two things at once with no order between them.
fn check_sysctls(spec: &Spec<'_>, linux: &spec::Linux<'_>) -> Result<()> {
    if linux.sysctl.is_empty() {
        return Ok(());
    }
    let creates = |kind: &str| {
        linux
            .namespaces
            .iter()
            .any(|n| n.kind == kind && n.path.is_none())
    };
    // A namespace the configuration joins is somebody else's, and its
    // parameters are that owner's business. One this runtime is already in
    // is not somebody else's: it is the host's, reached the long way round.
    let joins_another = |kind: &str| {
        linux.namespaces.iter().any(|n| {
            n.kind == kind
                && n.path.is_some_and(|path| !is_our_namespace(kind, path))
        })
    };
    let own = |kind: &str| creates(kind) || joins_another(kind);

    for &(key, value) in &linux.sysctl {
        ensure!(
            key != "kernel.hostname",
            "linux.sysctl names kernel.hostname; the container's name is \
             the `hostname` field, and this parameter would rename the \
             whole UTS namespace it is set in"
        );
        // Both spellings may name the same domain: the outcome is the one
        // the configuration describes either way. Two different names
        // leave the result to whichever is applied last.
        if key == "kernel.domainname" {
            let named = spec.domainname.unwrap_or_default();
            ensure!(
                named.is_empty() || named == value,
                "config.json sets the domain name to `{named}` and the \
                 linux.sysctl kernel.domainname to `{value}`"
            );
        }
        if let Some(kind) = namespace_of(key) {
            ensure!(
                own(kind),
                "linux.sysctl names {key}, which belongs to the {kind} \
                 namespace; this container shares the host's, so setting \
                 it would change the host"
            );
        }
    }
    Ok(())
}

/// Whether `path` names the namespace this runtime is already in.
///
/// Two paths naming one namespace share a device and inode. A path that
/// cannot be looked at is treated as somebody else's, since the join itself
/// fails later with a better answer than a refusal here would give.
fn is_our_namespace(kind: &str, path: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    // The specification's names for two of these are not the kernel's.
    let file = match kind {
        "network" => "net",
        "mount" => "mnt",
        other => other,
    };
    let (Ok(theirs), Ok(ours)) = (
        std::fs::metadata(path),
        std::fs::metadata(format!("/proc/self/ns/{file}")),
    ) else {
        return false;
    };
    (theirs.dev(), theirs.ino()) == (ours.dev(), ours.ino())
}

/// The namespace a kernel parameter belongs to, when it belongs to one.
///
/// These are the parameters the kernel keeps per namespace. Anything else is
/// the machine's, and writing one is refused for a different reason: it is
/// not the container's to set at all, which the read-only `/proc/sys` a
/// stock bundle asks for already prevents.
fn namespace_of(key: &str) -> Option<&'static str> {
    const IPC: [&str; 13] = [
        "kernel.msgmax",
        "kernel.msgmnb",
        "kernel.msgmni",
        "kernel.sem",
        "kernel.shmall",
        "kernel.shmmax",
        "kernel.shmmni",
        "kernel.shm_rmid_forced",
        "kernel.mq_msg_default",
        "kernel.mq_msgsize_default",
        "kernel.msg_next_id",
        "kernel.sem_next_id",
        "kernel.shm_next_id",
    ];

    if key.starts_with("net.") {
        return Some("network");
    }
    if key.starts_with("fs.mqueue.") || IPC.contains(&key) {
        return Some("ipc");
    }
    if key == "kernel.domainname" {
        return Some("uts");
    }
    None
}

/// Refuses a filter that asks for a supervisor it does not name.
///
/// The notify action hands the syscall to a user-space supervisor, which the
/// runtime reaches over the socket `listenerPath` names. Without one there is
/// nobody to answer, and the kernel fails every syscall the rule covers with
/// `ENOSYS` instead. That looks to the container like a kernel too old to
/// have the call at all, which is the least diagnosable failure available.
fn check_seccomp(linux: &spec::Linux<'_>) -> Result<()> {
    let Some(seccomp) = linux.seccomp.as_ref() else {
        return Ok(());
    };
    if !seccomp.listener_path.unwrap_or_default().is_empty() {
        return Ok(());
    }
    // Resolved the way the emitter resolves it, which accepts the name with
    // or without its prefix and in any case. Matching on the text here
    // instead would let a spelling the filter honours past the check.
    let notifies =
        |action: &str| Action::by_name(action, None) == Some(Action::Notify);
    ensure!(
        !notifies(seccomp.default_action)
            && !seccomp.syscalls.iter().any(|rule| notifies(rule.action)),
        "seccomp: SCMP_ACT_NOTIFY needs linux.seccomp.listenerPath"
    );
    Ok(())
}

/// Checks the section describing the program the container runs.
///
/// Every answer here is one the runtime would otherwise reach much later,
/// inside the container, where reporting it well is no longer possible.
fn check_process(process: &spec::Process<'_>) -> Result<()> {
    ensure!(
        process.command_line.is_none(),
        "process.commandLine is a Windows field and has no meaning here"
    );
    ensure!(
        !process.args.is_empty(),
        "process.args needs at least one entry, which is the program to run"
    );
    ensure!(
        process.cwd.starts_with('/'),
        "process.cwd {} must be an absolute path",
        process.cwd
    );
    // Only the first entry has to say something: it names the program, and
    // an empty name cannot be resolved. The rest are the program's own
    // arguments, and an empty one is a value like any other.
    ensure!(
        process
            .args
            .first()
            .is_none_or(|program| !program.is_empty()),
        "process.args[0] names the program to run and must not be empty"
    );

    // Two limits of the same kind describe the same file, and the one that
    // happened to be written last would decide it.
    let mut seen: Vec<&str> = Vec::with_capacity(process.rlimits.len());
    for limit in &process.rlimits {
        ensure!(
            !seen.contains(&limit.kind),
            "process.rlimits names {} more than once",
            limit.kind
        );
        seen.push(limit.kind);
    }
    if let Some(scheduler) = process.scheduler.as_ref() {
        check_deadline(scheduler)?;
    }
    Ok(())
}

/// Checks the three figures the deadline policy is described by.
///
/// The kernel answers an inconsistent set with `EINVAL`, from a call made
/// inside the container after everything else has been built. The rules are
/// simple enough to state here, where the answer can name the field.
fn check_deadline(scheduler: &spec::Scheduler<'_>) -> Result<()> {
    if !scheduler.policy.eq_ignore_ascii_case("SCHED_DEADLINE") {
        return Ok(());
    }
    ensure!(
        scheduler.runtime > 0,
        "process.scheduler: SCHED_DEADLINE needs a runtime above zero"
    );
    ensure!(
        scheduler.deadline > 0,
        "process.scheduler: SCHED_DEADLINE needs a deadline above zero"
    );
    // A period of zero means the deadline is the period, which is the
    // kernel's own default and a configuration this accepts.
    let period = if scheduler.period == 0 {
        scheduler.deadline
    } else {
        scheduler.period
    };
    ensure!(
        scheduler.runtime <= scheduler.deadline,
        "process.scheduler: the SCHED_DEADLINE runtime {} is longer than \
         its deadline {}, so the task could never finish in time",
        scheduler.runtime,
        scheduler.deadline
    );
    ensure!(
        scheduler.deadline <= period,
        "process.scheduler: the SCHED_DEADLINE deadline {} is longer than \
         its period {}, so one instance would still be due when the next \
         begins",
        scheduler.deadline,
        period
    );
    Ok(())
}

/// Rejects a bundle claiming a version this build does not implement.
fn check_version(version: &str) -> Result<()> {
    // Both numbers have to be there: a version missing its minor is
    // malformed, even though only the major decides what is implemented.
    let mut parts = version.split('.');
    let major = parts.next().and_then(|text| text.parse::<u32>().ok());
    let minor = parts.next().and_then(|text| text.parse::<u32>().ok());
    let (Some(major), Some(_)) = (major, minor) else {
        bail!("config.json has a malformed ociVersion: {version}");
    };
    // The specification promises compatibility within a major version, so a
    // newer minor is accepted and a newer major is not.
    ensure!(
        major == 1,
        "config.json asks for specification version {version}, and this \
         runtime implements {OCI_VERSION_MIN} to {OCI_VERSION_MAX}"
    );
    Ok(())
}

/// Refuses a configuration that builds a root filesystem with no mount
/// namespace to build it in.
///
/// The runtime installs the configured mounts and then changes the root, both
/// in whatever mount namespace it was handed. Without a private one that is
/// the caller's own: the mounts, their propagation and the detached old root
/// all land outside the container, and processes that never asked to be in a
/// container see them. A configuration that joins an existing mount namespace
/// by path has said where the work belongs, so only the absent case is
/// refused.
fn check_mount_namespace(linux: Option<&spec::Linux<'_>>) -> Result<()> {
    let present = linux.is_some_and(|linux| {
        linux.namespaces.iter().any(|n| n.kind == "mount")
    });
    ensure!(
        present,
        "config.json asks for no mount namespace; the configured mounts and \
         the change of root would be made in the caller's own namespace"
    );
    Ok(())
}

/// Refuses a name for a machine the container does not have.
///
/// `hostname` and `domainname` are set with `sethostname` and
/// `setdomainname`, which act on the UTS namespace the process is in. Without
/// a private one that is the caller's, so a container asking to be called
/// something would rename the host, and every process on it would see the new
/// name. There is no way to honour the field for this container alone, and
/// renaming the host is not what was asked for.
fn check_uts_namespace(spec: &Spec<'_>) -> Result<()> {
    let named = spec.hostname.is_some_and(|name| !name.is_empty())
        || spec.domainname.is_some_and(|name| !name.is_empty());
    if !named {
        return Ok(());
    }
    let present = spec
        .linux
        .as_ref()
        .is_some_and(|linux| linux.namespaces.iter().any(|n| n.kind == "uts"));
    ensure!(
        present,
        "config.json names the container but asks for no UTS namespace; \
         setting it would rename the host instead"
    );
    Ok(())
}

fn check_namespaces(linux: &spec::Linux<'_>) -> Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(linux.namespaces.len());
    for namespace in &linux.namespaces {
        ensure!(!namespace.kind.is_empty(), "a namespace entry has no type");
        ensure!(
            !seen.contains(&namespace.kind),
            "namespace {} appears more than once",
            namespace.kind
        );
        seen.push(namespace.kind);
    }
    Ok(())
}

/// Refuses a section this build does not carry.
///
/// `features` reports these as unavailable, and a caller that checked will
/// not send them. One that did not send them anyway, and a container that
/// started regardless would run without the interface it was supposed to be
/// given: the payload would bind to whatever interface it found instead,
/// which is the host's. Refusing is what the report already promises.
fn check_unimplemented(linux: &spec::Linux<'_>) -> Result<()> {
    ensure!(
        linux.net_devices.is_empty(),
        "linux.netDevices moves host interfaces into the container, which \
         this runtime does not implement; `kot features` reports it as \
         unavailable"
    );
    Ok(())
}

/// Refuses clock offsets with nowhere to apply them.
///
/// The offsets are set on a time namespace while it still holds the single
/// process that was put there, so they need one this runtime created. Joining
/// somebody else's is too late: it already has processes reading its clocks,
/// and the kernel refuses the write.
///
/// The file names two clocks and no others, so a third is a configuration
/// error worth reporting here rather than as a rejected write halfway through
/// building the container.
fn check_time_offsets(linux: &spec::Linux<'_>) -> Result<()> {
    if linux.time_offsets.is_empty() {
        return Ok(());
    }
    let created = linux
        .namespaces
        .iter()
        .any(|n| n.kind == "time" && n.path.is_none());
    ensure!(
        created,
        "linux.timeOffsets needs a time namespace of this container's own"
    );
    for (clock, _) in &linux.time_offsets {
        ensure!(
            matches!(*clock, "monotonic" | "boottime"),
            "linux.timeOffsets names {clock}, which is not a clock the \
             kernel offsets"
        );
    }
    Ok(())
}

fn check_id_maps(linux: &spec::Linux<'_>) -> Result<()> {
    let creates_userns = linux
        .namespaces
        .iter()
        .any(|n| n.kind == "user" && n.path.is_none());
    if !creates_userns {
        return Ok(());
    }
    // A configuration that names no mapping is not refused: the lowering
    // derives the caller's own identity, which is what such a bundle asks for.
    // A mapping that is stated, though, has to be usable.
    for mapping in linux.uid_mappings.iter().chain(&linux.gid_mappings) {
        ensure!(mapping.size > 0, "an id mapping range has a size of zero");
    }
    Ok(())
}
