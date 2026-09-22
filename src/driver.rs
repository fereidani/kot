//! Creating a container.
//!
//! The order below is chosen so that the two things that take real time,
//! systemd creating a cgroup and init building a filesystem, happen at the
//! same time as each other instead of one after the other:
//!
//! ```text
//!   lower the configuration into a plan
//!   cgroupfs: make the cgroup              <- so the clone can land in it
//!   clone the init process                  <- produces the pid systemd needs
//!   systemd: send StartTransientUnit        <- 0.02 ms to send, ~11 ms to land
//!     |                                    init: join namespaces, mount, pivot
//!   wait for the cgroup directory to appear
//!   move the process in if it was not born there, apply the limits
//!   run the hooks
//!   release init
//! ```
//!
//! Sending the systemd request before waiting for anything turns an 11 ms
//! round trip into background work. Other runtimes wait for it before starting
//! the filesystem, and pay for both in series.
//!
//! On the cgroupfs path the cgroup exists before the clone, and the clone
//! places init in it directly. Moving a process into a cgroup after the fact
//! waits out a read-copy-update grace period inside the kernel, several
//! milliseconds during which init would sit idle before touching the
//! filesystem; a process born in its cgroup never pays that.

use std::{
    os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd},
    path::Path,
};

use anyhow::{Context as _, Result, bail};
use bumpalo::Bump;

use crate::{
    cgroup::{self, Manager},
    cli::{Global, Start},
    hooks, image,
    linux::{
        handoff::{self, Handoff, InitArgs},
        namespace,
        sync::{self, Kind, Message},
    },
    oci::{
        Spec,
        lower::{self, Settings},
        parse,
        plan::View,
        spec::Resources,
    },
    state::{LaterHooks, Record, Store},
    sys::clone::{CloneSpec, Fork},
};

/// What a successful creation produced.
pub struct Created {
    /// The runtime's end of the terminal, when it is relaying one itself.
    pub terminal: Option<OwnedFd>,
    /// The container's init process.
    pub pid: i32,
    /// The state record, already written.
    pub record: Record,
    /// The cgroup manager, so the caller can tear it down.
    pub manager: Manager,
}

/// Everything the creation stages read, gathered so they can hand the whole of
/// it along instead of eight arguments that always travel together.
struct Request<'a> {
    global: &'a Global,
    store: &'a Store,
    options: &'a Start,
    /// True when the payload waits on the fifo instead of running at once.
    awaiting_start: bool,
    spec: &'a Spec<'a>,
    lowered: &'a lower::Lowered,
    plan: &'a View<'a>,
    bundle: &'a Path,
}

/// Builds a container and leaves it waiting to be started.
pub fn create(
    global: &Global,
    store: &Store,
    options: &Start,
    awaiting_start: bool,
) -> Result<Created> {
    let bundle = std::fs::canonicalize(&options.bundle).with_context(|| {
        format!("resolving the bundle directory {}", options.bundle)
    })?;
    let mut config = Vec::new();
    // A caller may keep several configurations in one bundle and name the
    // one it wants, which is how a single rootfs serves more than one
    // container.
    let name = options.config.as_deref().unwrap_or("config.json");
    crate::file::read(&bundle.join(name), &mut config)
        .with_context(|| format!("reading {}/{name}", bundle.display()))?;

    let arena = Bump::new();
    let spec = parse::spec(&config, &arena).context("parsing config.json")?;
    crate::validate::spec(&spec).context("validating config.json")?;

    let rootfs = resolve_rootfs(&bundle, &spec)?;
    let settings = Settings {
        rootfs,
        no_pivot: options.no_pivot,
        no_new_keyring: options.no_new_keyring,
        seccomp_fail_unknown_syscall: annotation_is_set(
            &spec,
            "run.oci.seccomp_fail_unknown_syscall",
        ),
        keep_original_groups: annotation_is_set(
            &spec,
            "run.oci.keep_original_groups",
        ),
        join_only: false,
        cgroup_v2: crate::cgroup::Layout::detect()
            .is_ok_and(crate::cgroup::Layout::has_unified),
    };

    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings)
        .context("lowering config.json")?;
    let plan = View::new(&lowered.arena)?;
    let container = plan.container()?;

    // The state directory has to exist before anything that writes into it,
    // and its creation doubles as the check that rejects a duplicate
    // identifier.
    let directory = store.create(&options.id)?;
    let request = Request {
        global,
        store,
        options,
        awaiting_start,
        spec: &spec,
        lowered: &lowered,
        plan: &plan,
        bundle: bundle.as_path(),
    };
    let outcome = start_container(&request, container.clone_flags);
    if outcome.is_err() {
        // A container that failed to start leaves nothing behind. Removing the
        // directory here, instead of leaving it for `delete`, keeps a failed
        // create from blocking the next attempt on the same id.
        let _ = std::fs::remove_dir_all(&directory);
    }
    outcome
}

/// Makes the cgroup, seals the plan, clones the init process and hands it to
/// `supervise`.
fn start_container(request: &Request<'_>, clone_flags: u64) -> Result<Created> {
    let &Request {
        options,
        awaiting_start,
        spec,
        ..
    } = request;
    let cgroups_path = spec.linux.as_ref().and_then(|linux| linux.cgroups_path);
    let mut manager =
        Manager::new(request.global.cgroup_manager, cgroups_path, &options.id)?;
    // Made before the clone so that init can be born in it rather than moved
    // into it, which is the difference described at the top of this file.
    let placement = manager
        .precreate(resources(spec))
        .context("creating the container's cgroup")?;

    let process = ProcessRequest {
        lowered: request.lowered,
        preserved: options.preserve_fds,
        detached: awaiting_start || options.detach,
        clone_flags: Some(clone_flags),
        cgroup: placement,
        scratch: request.store.root(),
        opening: "opening the namespaces to join",
        creating: "creating the container process",
    };
    let prepare = || {
        let start_fifo = if awaiting_start {
            Some(request.store.create_fifo(&options.id)?)
        } else {
            None
        };
        let (console_socket, relay_end) =
            terminal_ends(options, request.spec, awaiting_start)?;
        Ok((start_fifo, console_socket, relay_end))
    };
    let spawned = match spawn_sealed(&process, prepare) {
        Ok(spawned) => spawned,
        Err(error) => {
            // Nothing is in the cgroup yet, so it goes as easily as it came.
            let _ = manager.destroy();
            return Err(error);
        }
    };
    let Spawned {
        socket,
        pid,
        prepared: relay_end,
        in_cgroup,
    } = spawned;
    let mut created = supervise(request, manager, socket, pid, in_cgroup)?;
    created.terminal = relay_end
        .map(|socket| crate::terminal::receive(socket.as_fd()))
        .transpose()?;
    Ok(created)
}

/// What distinguishes one sealed-image process from another.
pub(crate) struct ProcessRequest<'a> {
    pub(crate) lowered: &'a lower::Lowered,
    pub(crate) preserved: usize,
    pub(crate) detached: bool,
    pub(crate) clone_flags: Option<u64>,
    /// The cgroup to create the process in, when one exists already.
    pub(crate) cgroup: Option<BorrowedFd<'a>>,
    /// A directory the runtime owns, which the sealed image is built over.
    pub(crate) scratch: &'a Path,
    pub(crate) opening: &'static str,
    pub(crate) creating: &'static str,
}

type Prepared<T> = (Option<OwnedFd>, Option<OwnedFd>, T);

/// What a clone into the sealed image left the driver holding.
pub(crate) struct Spawned<T> {
    /// The driver's end of the sync socket.
    pub(crate) socket: OwnedFd,
    /// The child, as the driver's own pid namespace numbers it.
    pub(crate) pid: i32,
    /// Whatever `prepare` handed back.
    pub(crate) prepared: T,
    /// True when the child was created inside the cgroup it was asked for,
    /// so nothing has to move it there.
    pub(crate) in_cgroup: bool,
}

/// Clones a process and re-executes it from the sealed runtime image.
///
/// Container creation and `exec` differ only in what they hand over and
/// whether the clone makes namespaces. Keeping the fork and re-execution in
/// one place keeps the descriptor protocol in one place too. `prepare` runs
/// after the namespaces are open and before anything is handed to the child.
pub(crate) fn spawn_sealed<T>(
    request: &ProcessRequest<'_>,
    prepare: impl FnOnce() -> Result<Prepared<T>>,
) -> Result<Spawned<T>> {
    let lowered = request.lowered;
    let (opening, creating) = (request.opening, request.creating);
    let (socket, init_side) = sync::pair()?;
    let plan_fd = image::seal_plan(&lowered.arena)?;
    let sealed = image::sealed(request.scratch)?;

    let join_paths: Vec<String> =
        lowered.joins.iter().map(|join| join.path.clone()).collect();
    let namespaces = namespace::open_joins(&join_paths).context(opening)?;
    // A mount with its own id mapping takes it from a user namespace, which
    // only the driver can build: the mapping files have to be written from
    // outside the namespace they describe.
    let idmaps = lowered
        .idmaps
        .iter()
        .map(|request| {
            namespace::id_mapped(&request.uid_ranges, &request.gid_ranges)
        })
        .collect::<crate::sys::error::Result<Vec<_>>>()
        .context("building the id mapping for a mount")?;
    let (start_fifo, console_socket, prepared) = prepare()?;
    let args = InitArgs {
        namespaces: namespaces.len(),
        idmaps: idmaps.len(),
        preserved: request.preserved,
        has_console_socket: console_socket.is_some(),
        has_start_fifo: start_fifo.is_some(),
        detached: request.detached,
    };

    let handoff = Handoff {
        sync: Some(init_side),
        plan: Some(plan_fd),
        start_fifo,
        console_socket,
        namespaces,
        idmaps,
    };
    // Checked before the fork, and not in the child that uses it: the child
    // renumbers its descriptors before it reaches the slot, so a count that
    // overlaps the runtime's block would have replaced one of the caller's
    // descriptors by the time the error was reported.
    handoff::program_slot(request.preserved)?;

    let mut spawn = CloneSpec::new();
    if let Some(clone_flags) = request.clone_flags {
        spawn = spawn.namespaces(clone_flags);
    }

    // SAFETY: both callers are single-threaded. Neither has spawned a
    // thread, so the child cannot inherit a lock another thread was holding.
    let (side, in_cgroup) =
        unsafe { spawn_placed(spawn, request.cgroup) }.context(creating)?;

    match side {
        Fork::Child => {
            // Anything that goes wrong here cannot be reported: the socket is
            // about to be renumbered and the process is about to be replaced.
            // Exiting with a distinctive code is all that is left.
            let code = enter_sealed_image(&handoff, &args, sealed.as_fd());
            std::process::exit(code);
        }
        Fork::Parent(pid) => {
            drop(handoff);
            Ok(Spawned {
                socket,
                pid,
                prepared,
                in_cgroup,
            })
        }
    }
}

/// Clones the process, into `cgroup` when there is one to be born in.
///
/// A clone the kernel refuses with the cgroup named is made again without it.
/// An older kernel, a hierarchy that is not the unified one, and a cgroup that
/// has since gone away all come to that refusal, and in each case the process
/// is created the old way and moved afterwards. The refused call created
/// nothing, so the second starts from the same state as the first. The flag
/// says which happened.
///
/// # Safety
///
/// As [`CloneSpec::spawn`].
unsafe fn spawn_placed(
    spawn: CloneSpec,
    cgroup: Option<BorrowedFd<'_>>,
) -> crate::sys::error::Result<(Fork, bool)> {
    if let Some(cgroup) = cgroup {
        let placed = spawn.into_cgroup(cgroup.as_raw_fd());
        // SAFETY: the caller's guarantee covers this call as well.
        if let Ok(side) = unsafe { placed.spawn() } {
            return Ok((side, true));
        }
    }
    // SAFETY: the caller's guarantee covers this call as well.
    let side = unsafe { spawn.spawn() }?;
    Ok((side, false))
}

/// The child half of the clone: renumber descriptors and re-execute.
///
/// Shared with `exec`, which does exactly the same thing with a plan that says
/// to join a container rather than build one.
#[allow(clippy::similar_names)]
pub fn enter_sealed_image(
    handoff: &Handoff,
    args: &InitArgs,
    sealed: std::os::fd::BorrowedFd<'_>,
) -> i32 {
    /// Exit code for a child that could not even reach the sealed image.
    const HANDOFF_FAILED: i32 = 125;

    if handoff.install().is_err() {
        return HANDOFF_FAILED;
    }
    let highest = handoff.highest();
    if crate::linux::handoff::close_above(highest).is_err() {
        return HANDOFF_FAILED;
    }

    let encoded = args.encode();
    let Ok(argument) = std::ffi::CString::new(encoded) else {
        return HANDOFF_FAILED;
    };
    let name = c"kot";
    let subcommand = c"__init";
    let argv = [
        name.as_ptr().cast::<u8>(),
        subcommand.as_ptr().cast::<u8>(),
        argument.as_ptr().cast::<u8>(),
        core::ptr::null(),
    ];
    let envp = [core::ptr::null::<u8>()];

    // SAFETY: both arrays are NUL terminated and live until the call, which
    // does not return on success.
    let _ = unsafe {
        crate::sys::process::fexecve(sealed, argv.as_ptr(), envp.as_ptr())
    };
    HANDOFF_FAILED
}

/// The driver half: finish the cgroup, run the hooks, release init.
#[allow(clippy::similar_names, clippy::needless_pass_by_value)]
fn supervise(
    request: &Request<'_>,
    mut manager: Manager,
    socket: OwnedFd,
    pid: i32,
    in_cgroup: bool,
) -> Result<Created> {
    let &Request { spec, .. } = request;

    // On the systemd path this is the request, sent and not waited on:
    // everything between here and `wait_ready` below happens while systemd
    // is still working. On the cgroupfs path the cgroup was made before the
    // clone and there is nothing left to do.
    manager
        .begin_create(pid, resources(spec))
        .context("creating the container's cgroup")?;

    let mut guard = Reaper { pid, armed: true };
    let record = match configure(
        request,
        socket.as_fd(),
        pid,
        &mut manager,
        in_cgroup,
    ) {
        Ok(record) => record,
        Err(error) => {
            // The container was not created, so nothing it would have used
            // may outlive the attempt. The process goes first: a cgroup with
            // anything left in it cannot be removed.
            drop(guard);
            let _ = manager.destroy();
            return Err(error);
        }
    };
    guard.armed = false;
    Ok(Created {
        terminal: None,
        pid,
        record,
        manager,
    })
}

/// Everything between the container's cgroup existing and its process being
/// ready to run, which is the part a failure has to undo.
fn configure(
    request: &Request<'_>,
    socket: BorrowedFd<'_>,
    pid: i32,
    manager: &mut Manager,
    in_cgroup: bool,
) -> Result<Record> {
    let &Request {
        options,
        spec,
        lowered,
        ..
    } = request;

    // The process id init reports is the one it sees, which inside a new pid
    // namespace is one. What the runtime needs, for waiting on it, for writing
    // its id maps, and for the state record, is the id in the runtime's own
    // namespace, which the clone returned.
    let ready =
        await_init(socket, Kind::Ready, "waiting for the container process")?;
    crate::log::debug(&format!(
        "container process is {pid} here, {} inside",
        ready.pid
    ));

    if lowered.creates_userns {
        namespace::write_id_maps(
            request.plan,
            pid,
            request.plan.container()?.deny_setgroups,
        )
        .context("writing the id mappings")?;
        sync::send(socket, &Message::new(Kind::IdMapsWritten))?;
    }

    settle_cgroup(manager, spec, lowered, socket, pid, in_cgroup)?;

    // Cache and bandwidth partitioning is a filesystem of its own rather
    // than part of the cgroup, so it is applied here beside the limits and
    // remembered so that `delete` can undo exactly what this made.
    let rdt = apply_rdt(spec, &request.options.id, pid)?;

    let record = build_record(request, manager, pid, &rdt);
    // The process is this one's child and is waiting on the socket, so its
    // state is known without a look at `/proc`: what remains open is only
    // whether the payload runs at once or waits for `start`.
    let status = if request.awaiting_start {
        crate::state::Status::Created
    } else {
        crate::state::Status::Running
    };

    // These run in the runtime's own namespaces, after the container's exist,
    // which is the specification's `createRuntime` point.
    let state = crate::state::render_public(&record, status);
    if let Some(hooks) = spec.hooks.as_ref() {
        hooks::run(&hooks.prestart, &state)?;
        hooks::run(&hooks.create_runtime, &state)?;
    }

    // Init stops once the container's filesystem exists and before its root
    // changes, which is where `createContainer` belongs: the hooks run in the
    // container's namespaces, and their own paths still resolve on the host.
    await_init(
        socket,
        Kind::Mounted,
        "waiting for the container's filesystem",
    )?;
    if let Some(hooks) = spec.hooks.as_ref() {
        hooks::run_in_container(pid, &hooks.create_container, &state)?;
    }
    sync::send(socket, &Message::new(Kind::HooksRun))?;

    await_init(
        socket,
        Kind::Prepared,
        "waiting for the container to be prepared",
    )?;

    sync::send(socket, &Message::new(Kind::Proceed))?;

    // A profile with a notify action suspends every matching syscall until an
    // agent answers, so the descriptor has to reach the agent before the
    // payload runs. Init sends it back once the filter is installed, which is
    // the last thing it does before executing.
    deliver_seccomp_listener(request.plan, &record, socket)?;

    // Applying the process settings is the last thing init does that the
    // configuration can make fail, and it happens after the handshake above.
    // Waiting for it here turns a container that could not be built into a
    // failed `create`, rather than a successful one holding a dead process.
    await_init(
        socket,
        Kind::Configured,
        "applying the process configuration",
    )?;

    // A container that is not waiting to be started has no `start` operation
    // to carry its `startContainer` hooks, so they run here, in the last
    // moment before the payload replaces init.
    if !request.awaiting_start {
        if let Some(hooks) = spec.hooks.as_ref() {
            hooks::run_in_container(pid, &hooks.start_container, &state)?;
        }
    }
    sync::send(socket, &Message::new(Kind::HooksRun))?;

    request.store.save(&record, status)?;

    if let Some(path) = options.pid_file.as_deref() {
        std::fs::write(path, format!("{pid}\n"))
            .with_context(|| format!("writing the pid file {path}"))?;
    }

    Ok(record)
}

/// Waits for one message from init, keeping what it said when it failed.
///
/// A failure crosses the socket as a description and an errno, which the error
/// type at the syscall boundary cannot carry together: its description has to
/// be a static string, and this one arrived as bytes. Rebuilding the two here,
/// where allocation is allowed, puts one failure on the caller's terminal as a
/// single line rather than a summary and a fragment.
pub(crate) fn await_init(
    socket: BorrowedFd<'_>,
    want: Kind,
    doing: &'static str,
) -> Result<Message> {
    let message = sync::receive(socket)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context(doing)?;
    if message.kind == want {
        return Ok(message);
    }
    if message.kind != Kind::Failed {
        bail!("{doing}: the container sent an unexpected message");
    }
    let reason = crate::sys::error::strerror(message.errno);
    let context = message.context();
    if context.is_empty() {
        bail!("{doing}: the container failed: {reason}");
    }
    bail!("{doing}: {context}: {reason}")
}

/// Decides where the container's terminal goes, if it asks for one.
///
/// The caller usually names a socket. When it does not, and the container is
/// in the foreground, the runtime becomes the other end itself and keeps the
/// second half of the pair to copy through.
fn terminal_ends(
    options: &Start,
    spec: &Spec<'_>,
    awaiting_start: bool,
) -> Result<(Option<OwnedFd>, Option<OwnedFd>)> {
    let wants_terminal = spec
        .process
        .as_ref()
        .is_some_and(|process| process.terminal);
    match options.console_socket.as_deref() {
        Some(path) => Ok((Some(crate::terminal::connect(path)?), None)),
        None if wants_terminal && !awaiting_start && !options.detach => {
            let pair = crate::terminal::pair()?;
            Ok((Some(pair.container), Some(pair.runtime)))
        }
        None if wants_terminal => bail!(
            "the container asks for a terminal, so it needs \
             --console-socket or a foreground run"
        ),
        None => Ok((None, None)),
    }
}

/// The resource limits a configuration asked for, if it asked for any.
fn resources<'a, 'b>(spec: &'a Spec<'b>) -> Option<&'a Resources<'b>> {
    spec.linux
        .as_ref()
        .and_then(|linux| linux.resources.as_ref())
}

/// Finishes the cgroup once the container's process exists.
///
/// Everything here had to wait for a real process id, which is why it is on
/// this side of the readiness exchange instead of beside `begin_create`.
fn settle_cgroup(
    manager: &mut Manager,
    spec: &Spec<'_>,
    lowered: &lower::Lowered,
    socket: BorrowedFd<'_>,
    pid: i32,
    in_cgroup: bool,
) -> Result<()> {
    let resources = resources(spec);
    manager
        .wait_ready()
        .context("waiting for the container's cgroup")?;
    if in_cgroup {
        // Born in place, so a cgroup namespace made from here on is rooted
        // right already. Saying so now instead of after the limits below lets
        // init build the filesystem while they are written.
        release_cgroupns(lowered, socket)?;
    } else {
        manager
            .add_process(pid)
            .context("moving the container into its cgroup")?;
    }
    manager
        .apply(resources)
        .context("applying the container's resource limits")?;
    if let Some(linux) = spec.linux.as_ref() {
        crate::devices::configure(manager, linux.resources.as_ref())?;
    }
    if !in_cgroup {
        release_cgroupns(lowered, socket)?;
    }
    Ok(())
}

/// Tells init it is in its cgroup, if it is waiting to hear so.
///
/// A cgroup namespace is rooted where its maker sits, so init makes one only
/// once it is told. Only a container that asked for one is waiting; sending
/// to a container that is not would leave a message in the socket for the
/// next exchange to misread.
fn release_cgroupns(
    lowered: &lower::Lowered,
    socket: BorrowedFd<'_>,
) -> Result<()> {
    if !lowered.creates_cgroupns {
        return Ok(());
    }
    sync::send(socket, &Message::new(Kind::CgroupJoined))
        .context("releasing the container's cgroup namespace")
}

/// Assembles what the runtime remembers about a container between commands.
fn build_record(
    request: &Request<'_>,
    manager: &Manager,
    pid: i32,
    rdt: &crate::rdt::Created,
) -> Record {
    let spec = request.spec;
    let hooks = spec.hooks.as_ref();
    Record {
        hooks: LaterHooks {
            start_container: hooks
                .is_some_and(|hooks| !hooks.start_container.is_empty()),
            poststart: hooks.is_some_and(|hooks| !hooks.poststart.is_empty()),
            poststop: hooks.is_some_and(|hooks| !hooks.poststop.is_empty()),
        },
        id: request.options.id.clone(),
        oci_version: spec.version.to_owned(),
        bundle: request.bundle.display().to_string(),
        pid,
        start_time: crate::state::process_start_time(pid).unwrap_or(0),
        created: crate::now(),
        cgroup_path: manager.path().to_string(),
        systemd_unit: manager.unit().unwrap_or("").to_owned(),
        cgroup_manager: manager_name(request.global.cgroup_manager).to_owned(),
        owner: crate::owner(),
        awaiting_start: request.awaiting_start,
        rdt_class: render_path(&rdt.class),
        rdt_owned: rdt.owned,
        rdt_monitor: rdt
            .monitor
            .as_deref()
            .map(render_path)
            .unwrap_or_default(),
        annotations: spec
            .annotations
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// Passes the seccomp notify descriptor on, when the profile asked for one.
fn deliver_seccomp_listener(
    plan: &View<'_>,
    record: &Record,
    socket: BorrowedFd<'_>,
) -> Result<()> {
    // Read from the plan rather than from the configuration a second time.
    // The plan is what init acted on, and taking half the answer from one
    // and half from the other is how the two drift apart.
    let process = plan.process()?;
    let path = plan.text(process.seccomp_listener)?;
    if path.is_empty() {
        return Ok(());
    }
    let metadata = plan.text(process.seccomp_metadata)?;

    let (message, listener) = sync::receive_fd(socket)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("waiting for the seccomp listener")?;
    if message.kind != Kind::SeccompListener {
        bail!("the container did not send a seccomp listener");
    }
    let Some(listener) = listener else {
        bail!("the container sent no descriptor with its seccomp listener");
    };
    crate::seccomp_agent::deliver(path, metadata, record, listener.as_fd())?;
    sync::send(socket, &Message::new(Kind::Proceed))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Kills the container process when creation fails partway through.
///
/// Without this, a failure after the clone would leave a process blocked on
/// the sync socket forever, holding whatever namespaces it had entered.
struct Reaper {
    pid: i32,
    armed: bool,
}

impl Drop for Reaper {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(pid) = rustix::process::Pid::from_raw(self.pid) {
            let _ = rustix::process::kill_process(
                pid,
                rustix::process::Signal::KILL,
            );
            let _ = rustix::process::waitpid(
                Some(pid),
                rustix::process::WaitOptions::empty(),
            );
        }
    }
}

/// Resolves the root filesystem against the bundle.
fn resolve_rootfs(bundle: &Path, spec: &Spec<'_>) -> Result<String> {
    let Some(root) = spec.root.as_ref() else {
        bail!("config.json has no root");
    };
    let path = Path::new(root.path);
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        bundle.join(path)
    };
    Ok(absolute.display().to_string())
}

fn annotation_is_set(spec: &Spec<'_>, name: &str) -> bool {
    spec.annotations
        .iter()
        .any(|(key, value)| *key == name && !value.is_empty() && *value != "0")
}

const fn manager_name(kind: cgroup::Kind) -> &'static str {
    match kind {
        cgroup::Kind::Cgroupfs => "cgroupfs",
        cgroup::Kind::Systemd => "systemd",
        cgroup::Kind::Disabled => "disabled",
    }
}

/// Confines a process to the CPUs a list names.
///
/// The specification states two of these for an exec process: one for
/// before it is placed in the container's cgroup and one for after, since
/// the placement itself can change what it may run on. Both are set on the
/// same process, at the two moments that separate them, and the second is
/// inherited by the program it goes on to execute.
pub(crate) fn apply_affinity(list: Option<&str>, pid: i32) -> Result<()> {
    let Some(list) = list.filter(|list| !list.is_empty()) else {
        return Ok(());
    };
    let set = crate::sys::process::CpuSet::parse(list)?;
    crate::sys::process::set_affinity(pid, &set)?;
    Ok(())
}

/// Puts the container in the cache and bandwidth class it asked for.
///
/// Reports the class the container is in, whether this runtime made it, and
/// any monitoring group it made, so that a later `update` can change the
/// allocation and `delete` can remove exactly what was created.
fn apply_rdt(
    spec: &Spec<'_>,
    id: &str,
    pid: i32,
) -> Result<crate::rdt::Created> {
    let Some(rdt) = spec.linux.as_ref().and_then(|l| l.intel_rdt.as_ref())
    else {
        return Ok(crate::rdt::Created::default());
    };
    crate::rdt::apply(rdt, id, pid)
        .context("applying the cache and bandwidth allocation")
}

/// A path as the state record keeps it.
fn render_path(path: &Path) -> String {
    path.display().to_string()
}
