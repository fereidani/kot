//! Running another process inside a container that already exists.
//!
//! This is the command Kubernetes calls most often, through liveness and
//! readiness probes, so it is worth keeping short. It reuses everything the
//! create path built: the process is described as a plan, handed to the same
//! sealed image, and applied by the same executor. What differs is that the
//! plan says to join the container's namespaces rather than create any, and to
//! skip the filesystem entirely, because the container already has one.

use std::os::fd::{AsFd, OwnedFd};

use anyhow::{Context as _, Result, bail};
use bumpalo::Bump;

use crate::{
    cgroup::Manager,
    cli::Exec,
    driver::{self, ProcessRequest, Spawned},
    linux::sync::{self, Kind, Message},
    oci::{
        Spec,
        lower::{self, Settings},
        parse,
        plan::View,
    },
    state::{self, Record, Status, Store},
};

/// The namespaces an `exec` joins, in the order they have to be entered.
///
/// The user namespace decides what everything after it is allowed to do, and
/// the mount namespace changes what every path means, so those bracket the
/// rest.
const NAMESPACES: [(&str, &str); 7] = [
    ("user", "user"),
    ("ipc", "ipc"),
    ("uts", "uts"),
    ("net", "network"),
    ("pid", "pid"),
    ("cgroup", "cgroup"),
    ("mnt", "mount"),
];

/// Runs a process inside a container.
pub fn run(store: &Store, options: &Exec) -> Result<i32> {
    let record = store.load(&options.id)?;
    // A created container is a legitimate target: its namespaces and cgroup
    // already exist, and only its payload is still waiting.
    let status = state::observe(&record);
    match status {
        Status::Running | Status::Created => {}
        Status::Creating => {
            bail!("container {} is still being created", options.id)
        }
        Status::Paused | Status::Stopped => {
            bail!("container {} is not running", options.id)
        }
    }
    // A process entering a frozen cgroup freezes with it, so this would hang
    // rather than fail. Refusing says so instead.
    if !options.ignore_paused
        && crate::refine_status(&record, status) == Status::Paused
    {
        bail!(
            "container {} is paused; pass --ignore-paused to enter it anyway",
            options.id
        );
    }

    let bundle = std::path::Path::new(&record.bundle);
    let mut config = Vec::new();
    crate::file::read(&bundle.join("config.json"), &mut config)
        .with_context(|| format!("reading {}/config.json", bundle.display()))?;
    let arena = Bump::new();
    let mut spec =
        parse::spec(&config, &arena).context("parsing config.json")?;

    apply_overrides(&mut spec, options, &arena)?;
    // Joining an existing container means creating nothing, so the namespace
    // list is replaced with the container's own.
    let joins = namespace_paths(&record);
    replace_namespaces(&mut spec, &joins, &arena);

    let settings = Settings {
        rootfs: String::new(),
        join_only: true,
        ..Settings::default()
    };
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings)
        .context("preparing the process")?;
    // Checked here rather than in the child, where a malformed plan could
    // only be reported as an exit code.
    View::new(&lowered.arena)?;

    // The affinity the specification states for an exec process, read here
    // where the configuration is still in scope. The two halves are applied
    // on either side of the cgroup placement, the only thing separating
    // them.
    let affinity = spec
        .process
        .as_ref()
        .and_then(|process| process.exec_cpu_affinity.as_ref())
        .map(|affinity| Affinity {
            initial: affinity.initial.map(str::to_owned),
            final_set: affinity.final_set.map(str::to_owned),
        })
        .unwrap_or_default();

    spawn(store, options, &record, &lowered, &affinity)
}

/// What the configuration says an exec process may run on.
///
/// Owned rather than borrowed because it outlives the arena the
/// configuration was parsed into.
#[derive(Default)]
struct Affinity {
    /// Applied before the process is placed in the container's cgroup.
    initial: Option<String>,
    /// Applied after it, and inherited by the program it runs.
    final_set: Option<String>,
}

/// Replaces the configuration's process section with what `exec` was given.
fn apply_overrides<'a>(
    spec: &mut Spec<'a>,
    options: &Exec,
    arena: &'a Bump,
) -> Result<()> {
    if let Some(path) = options.process.as_deref() {
        let text = std::fs::read(path)
            .with_context(|| format!("reading the process file {path}"))?;
        let stored = arena.alloc_slice_copy(&text);
        let mut parser = crate::oci::json::Parser::new(stored, arena);
        spec.process = Some(
            parse::process(&mut parser).context("parsing the process file")?,
        );
        return Ok(());
    }

    let process = spec.process.get_or_insert_with(Default::default);
    process.args.clear();
    for argument in &options.args {
        process.args.push(arena.alloc_str(argument));
    }
    process.terminal = options.tty;
    if let Some(cwd) = options.cwd.as_deref() {
        process.cwd = arena.alloc_str(cwd);
    }
    // A variable named on the command line replaces the container's own:
    // with two entries under one name the program reads the first, which
    // is the container's, and the caller's would do nothing.
    for entry in &options.env {
        let name = entry.split('=').next().unwrap_or(entry);
        process.env.retain(|existing| {
            existing.split('=').next().unwrap_or(existing) != name
        });
        process.env.push(arena.alloc_str(entry));
    }
    // An `exec` process is described by what the caller asked for, not by
    // what the payload was given. Inheriting this one would leave no way
    // to ask for the other answer.
    process.no_new_privileges = options.no_new_privs;
    if let Some(profile) = options.apparmor.as_deref() {
        process.apparmor_profile = Some(arena.alloc_str(profile));
    }
    if let Some(label) = options.process_label.as_deref() {
        process.selinux_label = Some(arena.alloc_str(label));
    }
    if let Some(user) = options.user.as_deref() {
        let (uid, gid) = parse_user(user)?;
        process.user.uid = uid;
        if let Some(gid) = gid {
            process.user.gid = gid;
        }
    }
    if !options.additional_gids.is_empty() {
        process
            .user
            .additional_gids
            .clone_from(&options.additional_gids);
    }
    if !options.caps.is_empty() {
        let capabilities =
            process.capabilities.get_or_insert_with(Default::default);
        for name in &options.caps {
            capabilities.grant(arena.alloc_str(name));
        }
    }
    Ok(())
}

/// Splits a `user[:group]` argument.
fn parse_user(value: &str) -> Result<(u32, Option<u32>)> {
    let (user, group) = match value.split_once(':') {
        Some((user, group)) => (user, Some(group)),
        None => (value, None),
    };
    let uid = user
        .parse()
        .with_context(|| format!("--user expects a numeric id, got {user}"))?;
    let gid = group
        .map(|g| {
            g.parse::<u32>().with_context(|| {
                format!("--user expects a numeric group id, got {g}")
            })
        })
        .transpose()?;
    Ok((uid, gid))
}

/// The namespace files of a running container, minus the ones we are in
/// already.
///
/// A namespace the runtime already shares cannot be entered: the kernel
/// refuses `setns` into the caller's own user namespace outright, and joining
/// the rest would be a no-op that costs a syscall. Comparing the namespace
/// files by identity is how to tell, and it is why `exec` works for a
/// container that shares the host's network or user namespace.
fn namespace_paths(record: &Record) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(NAMESPACES.len());
    for (file, kind) in NAMESPACES {
        let theirs = format!("/proc/{}/ns/{file}", record.pid);
        let ours = format!("/proc/self/ns/{file}");
        let Ok(target) = std::fs::metadata(&theirs) else {
            continue;
        };
        if let Ok(current) = std::fs::metadata(&ours) {
            use std::os::unix::fs::MetadataExt as _;
            if current.ino() == target.ino() && current.dev() == target.dev() {
                continue;
            }
        }
        out.push((kind, theirs));
    }
    out
}

/// Points the configuration's namespace list at the container's own.
fn replace_namespaces<'a>(
    spec: &mut Spec<'a>,
    joins: &[(&'static str, String)],
    arena: &'a Bump,
) {
    let Some(linux) = spec.linux.as_mut() else {
        return;
    };
    linux.namespaces.clear();
    for (kind, path) in joins {
        linux.namespaces.push(crate::oci::spec::Namespace {
            kind,
            path: Some(arena.alloc_str(path)),
        });
    }
}

/// Creates the process and waits for it, unless the caller detached.
fn spawn(
    store: &Store,
    options: &Exec,
    record: &Record,
    lowered: &lower::Lowered,
    affinity: &Affinity,
) -> Result<i32> {
    // A process run inside a container belongs in the container's cgroup, or
    // it escapes every limit the container has. The cgroup is opened before
    // the clone so the process can be born in it rather than moved there,
    // sparing it the wait a migration costs. A manager the container was
    // created without has no directory to offer, and the process is then
    // placed afterwards, which for that manager means not at all.
    let mut manager =
        crate::cgroup_for(record).context("opening the container's cgroup")?;
    let sub = options.cgroup.as_deref().unwrap_or_default();
    let below = if sub.is_empty() {
        None
    } else {
        manager
            .sub_directory(sub)
            .context("opening the process's cgroup")?
    };
    let placement = below
        .as_ref()
        .map(AsFd::as_fd)
        .or_else(|| manager.directory());

    let process = ProcessRequest {
        lowered,
        preserved: options.preserve_fds,
        detached: options.detach,
        clone_flags: None,
        cgroup: placement,
        scratch: store.root(),
        opening: "opening the container's namespaces",
        creating: "creating the process",
    };
    let prepare = || {
        let console_socket = options
            .console_socket
            .as_deref()
            .map(crate::terminal::connect)
            .transpose()?;
        Ok((None, console_socket, ()))
    };
    let Spawned {
        socket,
        pid,
        prepared: (),
        in_cgroup,
        idmaps: _,
    } = driver::spawn_sealed(&process, prepare)?;
    supervise(options, &mut manager, socket, pid, in_cgroup, affinity)
}

/// Drives the handshake and waits for the process.
#[allow(clippy::needless_pass_by_value)]
fn supervise(
    options: &Exec,
    manager: &mut Manager,
    socket: OwnedFd,
    pid: i32,
    in_cgroup: bool,
    affinity: &Affinity,
) -> Result<i32> {
    // As in `create`: the id the process reports is the one it sees inside
    // the container, so what the runtime acts on is the clone's own answer.
    driver::await_init(socket.as_fd(), Kind::Ready, "waiting for the process")?;
    driver::await_init(
        socket.as_fd(),
        Kind::Prepared,
        "waiting for the process to be prepared",
    )?;

    // Everything below names the process that will run the caller's
    // program, which is not the one the clone returned when init had to
    // fork into the container's pid namespace.
    let payload = driver::payload_process(pid);

    // The affinity the process starts under, before it is placed: the
    // specification states these two separately because placement itself
    // can change what a process may run on, through a cpuset.
    driver::apply_affinity(affinity.initial.as_deref(), payload)
        .context("applying the initial CPU affinity")?;

    // Only a process the clone could not place needs moving. The only way to
    // reach the error is a placement that was asked for and did not happen.
    if !in_cgroup {
        let sub = options.cgroup.as_deref().unwrap_or_default();
        manager
            .add_process_in(payload, sub)
            .context("placing the process in the container's cgroup")?;
    }

    // And the affinity it runs the caller's program under, which the
    // program inherits through `execve`.
    driver::apply_affinity(affinity.final_set.as_deref(), payload)
        .context("applying the CPU affinity for the process")?;

    sync::send(socket.as_fd(), &Message::new(Kind::Proceed))?;

    // Applying the process settings is the last thing the new process does
    // that its configuration can make fail, so the answer is waited for even
    // when the caller detaches. Returning before it arrives closes this end
    // of the socket under a process still reporting on it, which it then
    // dies of, and the caller is told the exec succeeded.
    driver::await_init(
        socket.as_fd(),
        Kind::Configured,
        "applying the process configuration",
    )?;

    if let Some(path) = options.pid_file.as_deref() {
        std::fs::write(path, format!("{pid}\n"))
            .with_context(|| format!("writing the pid file {path}"))?;
    }
    if options.detach {
        return Ok(0);
    }
    crate::wait_for_process(pid)
}
