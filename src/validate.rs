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

    let Some(linux) = spec.linux.as_ref() else {
        return Ok(());
    };
    check_namespaces(linux)?;
    check_id_maps(linux)?;
    check_seccomp(linux)?;
    Ok(())
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
    ensure!(
        !process.args.iter().any(|argument| argument.is_empty()),
        "process.args must not contain an empty entry"
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

fn check_id_maps(linux: &spec::Linux<'_>) -> Result<()> {
    let creates_userns = linux
        .namespaces
        .iter()
        .any(|n| n.kind == "user" && n.path.is_none());
    if !creates_userns {
        return Ok(());
    }
    ensure!(
        !linux.uid_mappings.is_empty(),
        "a user namespace needs linux.uidMappings"
    );
    ensure!(
        !linux.gid_mappings.is_empty(),
        "a user namespace needs linux.gidMappings"
    );
    for mapping in linux.uid_mappings.iter().chain(&linux.gid_mappings) {
        ensure!(mapping.size > 0, "an id mapping range has a size of zero");
    }
    Ok(())
}
