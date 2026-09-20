//! The commands a caller can invoke.
//!
//! Each one is short, because the work lives in the modules they call. What
//! they own is the lifecycle contract: which states a command is legal in,
//! what it leaves behind, and what it reports.

use std::{io::Write, os::fd::AsFd as _};

use anyhow::{Context as _, Result, bail};
use bumpalo::Bump;

use crate::{
    cli::{Command, Global, Start},
    driver, hooks,
    oci::parse,
    state::{self, Record, Status, Store},
};

/// Runs the command the caller asked for and returns its exit code.
pub fn dispatch(
    global: &Global,
    store: &Store,
    command: &Command,
) -> Result<i32> {
    match command {
        Command::Create(options) => create(global, store, options),
        Command::Run(options) => run(global, store, options),
        Command::Start { id } => start(store, id),
        Command::State { id } => report_state(store, id),
        Command::Kill { id, signal, all } => kill(store, id, signal, *all),
        Command::Delete { id, force } => delete(store, id, *force),
        Command::Exec(options) => crate::exec::run(store, options),
        Command::List { json, quiet } => list(store, *json, *quiet),
        Command::Ps { id, json, args } => ps(store, id, *json, args),
        Command::Pause { id } => freeze(store, id, true),
        Command::Resume { id } => freeze(store, id, false),
        Command::Update(options) => crate::update::run(store, options),
        Command::Spec { bundle, rootless } => spec(bundle, *rootless),
        Command::Features => features(),
        Command::Version => version(),
        Command::Help => {
            print!("{}", crate::cli::USAGE);
            Ok(0)
        }
        Command::Init { .. } => bail!("__init is not callable directly"),
    }
}

/// Builds a container and leaves it waiting.
fn create(global: &Global, store: &Store, options: &Start) -> Result<i32> {
    let created = driver::create(global, store, options, true)?;
    drop(created);
    Ok(0)
}

/// Builds a container and runs it.
fn run(global: &Global, store: &Store, options: &Start) -> Result<i32> {
    let mut created = driver::create(global, store, options, false)?;

    // `run` is `create` and `start` without the wait between them, so the
    // hooks that belong after the payload starts run here.
    run_bundle_hooks(&created.record, HookPoint::PostStart);

    if options.detach {
        return Ok(0);
    }

    // When the runtime is holding the container's terminal it has to keep
    // copying until the container is done, and it has to put the caller's
    // terminal back however that ends.
    let status = match created.terminal.take() {
        Some(terminal) => {
            let _raw = crate::terminal::RawMode::enter()?;
            crate::terminal::relay(terminal.as_fd())?;
            crate::wait_for_process(created.pid)?
        }
        None => crate::wait_for_process(created.pid)?,
    };
    let _ = created.manager.destroy();
    store.remove(&created.record.id)?;
    run_bundle_hooks(&created.record, HookPoint::PostStop);
    Ok(status)
}

/// Runs the payload of a container that was created.
fn start(store: &Store, id: &str) -> Result<i32> {
    let mut record = store.load(id)?;
    match state::observe(&record) {
        Status::Created => {}
        Status::Running | Status::Paused => {
            bail!("container {id} is already running")
        }
        Status::Stopped => bail!("container {id} has stopped"),
        Status::Creating => bail!("container {id} is still being created"),
    }

    // Opening the fifo for reading releases the payload: init has been blocked
    // opening the same fifo for writing since it finished setting up.
    //
    // The byte it then sends has to be read before this end closes, or init
    // gets a broken pipe and the container dies at the moment it was supposed
    // to start. Opening without blocking and then waiting for the byte makes
    // the rendezvous reliable in both directions. The `startContainer` hooks
    // run in the container, before the payload replaces init, so they belong
    // here: init is still blocked on the fifo this is about to open. A hook
    // that fails stops the start.
    start_container_hooks(&record)?;

    let fifo = store.open_fifo(id)?;
    await_readiness(&fifo)
        .with_context(|| format!("starting container {id}"))?;
    drop(fifo);
    store.remove_fifo(id);

    record.awaiting_start = false;
    // The byte that just arrived on the fifo is the payload announcing
    // itself, which is more than a look at `/proc` would tell.
    store.save(&record, Status::Running)?;
    run_bundle_hooks(&record, HookPoint::PostStart);
    Ok(0)
}

/// Waits for the container to report that it is about to run.
fn await_readiness(fifo: &std::os::fd::OwnedFd) -> Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let mut byte = [0u8; 1];
    // Bounded: a container that has not answered after this long is one that
    // is not going to, and blocking forever would be worse than saying so.
    for _ in 0..50 {
        match rustix::io::read(fifo, &mut byte) {
            Ok(0) => bail!("the container closed the start fifo"),
            Ok(_) => return Ok(()),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    crate::sys::error::EAGAIN | crate::sys::error::EINTR
                ) => {}
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context("reading the start fifo")
                );
            }
        }
        let mut fds = [PollFd::from_borrowed_fd(fifo.as_fd(), PollFlags::IN)];
        let spec = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        poll(&mut fds, Some(&spec)).context("waiting on the start fifo")?;
    }
    bail!("the container did not report that it had started")
}

/// Reports a container's state.
fn report_state(store: &Store, id: &str) -> Result<i32> {
    let record = store.load(id)?;
    let status = crate::observed_status(&record);
    write_report(&state::render_public(&record, status), "writing the state")?;
    Ok(0)
}

/// Sends a signal to a container.
fn kill(store: &Store, id: &str, signal: &str, all: bool) -> Result<i32> {
    let record = store.load_running(id)?;
    let number = crate::sys::signal::by_name(signal)
        .ok_or_else(|| anyhow::anyhow!("unknown signal: {signal}"))?;

    if all {
        return kill_all(&record, number);
    }
    send_signal(record.pid, number)?;
    Ok(0)
}

/// Signals every process in the container's cgroup.
///
/// Reading the process list from the cgroup rather than walking `/proc` is
/// both cheaper and correct in the face of a process that exits while the list
/// is being read: a process that has gone simply is not signalled.
fn kill_all(record: &Record, signal: u32) -> Result<i32> {
    let pids = container_processes(record)?;
    for pid in pids {
        let _ = send_signal(pid, signal);
    }
    Ok(0)
}

/// Lists the processes the container's cgroup currently holds.
fn container_processes(record: &Record) -> Result<Vec<i32>> {
    let mut manager = crate::cgroup_for(record)?;
    let mut pids = Vec::new();
    manager
        .processes(&mut pids)
        .context("listing the container's processes")?;
    Ok(pids)
}

fn send_signal(pid: i32, signal: u32) -> Result<()> {
    use rustix::process::{Pid, Signal, kill_process};
    let Some(pid) = Pid::from_raw(pid) else {
        bail!("the container has no process to signal");
    };
    let number = i32::try_from(signal).unwrap_or(0);
    // Every signal number the runtime can produce came from a name table, so
    // it is one the kernel defines.
    let Some(signal) = Signal::from_named_raw(number) else {
        bail!("unknown signal number: {number}");
    };
    kill_process(pid, signal).context("sending the signal")?;
    Ok(())
}

/// Removes a container.
fn delete(store: &Store, id: &str, force: bool) -> Result<i32> {
    let record = match store.load(id) {
        Ok(record) => record,
        // Removing something that is already gone leaves the caller where it
        // asked to be.
        Err(_) if force => return Ok(0),
        Err(e) => return Err(e),
    };

    let status = state::observe(&record);
    let mut manager = crate::cgroup_for(&record)?;
    if status != Status::Stopped {
        if !force {
            bail!("container {id} is not stopped; use --force to remove it");
        }
        // A frozen process never acts on a signal, so killing a paused
        // container without thawing it first leaves the process running while
        // its record and its cgroup are taken away.
        if manager.frozen().unwrap_or(false) {
            if let Err(error) = manager.freeze(false) {
                crate::log::warn(&format!(
                    "thawing {id} before removing it: {error}"
                ));
            }
        }
        let _ = send_signal(record.pid, crate::sys::signal::SIGKILL);
        wait_until_stopped(&record);
    }

    if let Err(error) = manager.destroy() {
        crate::log::warn(&format!("removing the cgroup for {id}: {error}"));
    }
    store.remove(id)?;
    run_bundle_hooks(&record, HookPoint::PostStop);
    Ok(0)
}

/// Waits for a killed container to actually be gone.
fn wait_until_stopped(record: &Record) {
    // Bounded: a process that has been sent `SIGKILL` and is still there after
    // this many checks is one the kernel is not going to release, and blocking
    // forever would be worse than reporting what we found.
    for _ in 0..10_000 {
        if !state::is_alive(record.pid, record.start_time) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
}

/// Lists the containers in the state root.
fn list(store: &Store, json: bool, quiet: bool) -> Result<i32> {
    let records = store.list()?;
    if quiet {
        let mut out = std::io::stdout().lock();
        for record in &records {
            writeln!(out, "{}", record.id).context("writing the list")?;
        }
        return Ok(0);
    }
    if json {
        let mut writer = crate::json::Writer::new();
        writer.array(None);
        for record in &records {
            writer.object(None);
            writer.string(Some("ociVersion"), &record.oci_version);
            writer.string(Some("id"), &record.id);
            writer.number(Some("pid"), i64::from(record.pid));
            writer.string(
                Some("status"),
                crate::observed_status(record).as_str(),
            );
            writer.string(Some("bundle"), &record.bundle);
            writer.string(Some("created"), &record.created);
            writer.string(Some("owner"), &record.owner);
            writer.end_object();
        }
        writer.end_array();
        write_report(&writer.finish(), "writing the list")?;
        return Ok(0);
    }

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<24} {:<8} {:<10} {:<32} {:<26} OWNER",
        "ID", "PID", "STATUS", "BUNDLE", "CREATED"
    )
    .context("writing the list")?;
    for record in &records {
        writeln!(
            out,
            "{:<24} {:<8} {:<10} {:<32} {:<26} {}",
            record.id,
            record.pid,
            crate::observed_status(record).as_str(),
            record.bundle,
            record.created,
            record.owner
        )
        .context("writing the list")?;
    }
    Ok(0)
}

/// Shows the processes in a container.
fn ps(store: &Store, id: &str, json: bool, args: &[String]) -> Result<i32> {
    let record = store.load(id)?;
    let pids = container_processes(&record)?;

    if json {
        let mut writer = crate::json::Writer::new();
        writer.array(None);
        for pid in &pids {
            writer.number(None, i64::from(*pid));
        }
        writer.end_array();
        write_report(&writer.finish(), "writing the process list")?;
        return Ok(0);
    }

    let mut out = std::io::stdout().lock();
    // Without a format the caller gets what `ps` would show, filtered to the
    // container's own processes, so the output is readable rather than a
    // column of numbers.
    let mut command = std::process::Command::new("ps");
    if args.is_empty() {
        command.args(["-ef"]);
    } else {
        command.args(args);
    }
    let output = command.output();
    match output {
        Ok(output) if output.status.success() => {
            write_filtered(&mut out, &output.stdout, &pids)?;
        }
        _ => {
            for pid in &pids {
                writeln!(out, "{pid}").context("writing the process list")?;
            }
        }
    }
    Ok(0)
}

/// Prints the `ps` header plus the lines whose pid is in the container.
fn write_filtered(
    out: &mut impl Write,
    text: &[u8],
    pids: &[i32],
) -> Result<()> {
    let text = String::from_utf8_lossy(text);
    let mut lines = text.lines();
    if let Some(header) = lines.next() {
        writeln!(out, "{header}").context("writing the process list")?;
    }
    for line in lines {
        let matches = line
            .split_whitespace()
            .any(|field| field.parse::<i32>().is_ok_and(|p| pids.contains(&p)));
        if matches {
            writeln!(out, "{line}").context("writing the process list")?;
        }
    }
    Ok(())
}

/// Stops or resumes every process in a container.
fn freeze(store: &Store, id: &str, frozen: bool) -> Result<i32> {
    let record = store.load_running(id)?;
    let mut manager = crate::cgroup_for(&record)?;
    manager.freeze(frozen).context(if frozen {
        "pausing the container"
    } else {
        "resuming the container"
    })?;
    Ok(0)
}

/// Writes a starting configuration.
fn spec(bundle: &str, rootless: bool) -> Result<i32> {
    let path = std::path::Path::new(bundle).join("config.json");
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    std::fs::create_dir_all(bundle)
        .with_context(|| format!("creating the bundle directory {bundle}"))?;
    std::fs::write(&path, crate::template::config(rootless))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(0)
}

/// Reports what this build supports.
fn features() -> Result<i32> {
    write_report(&crate::features::report(), "writing the features report")?;
    Ok(0)
}

/// Writes one complete report to the caller.
fn write_report(report: &str, context: &'static str) -> Result<()> {
    std::io::stdout()
        .lock()
        .write_all(report.as_bytes())
        .context(context)
}

/// Reports the version.
fn version() -> Result<i32> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "kot version {}", env!("CARGO_PKG_VERSION"))
        .context("writing the version")?;
    writeln!(
        out,
        "spec: {} to {}",
        crate::validate::OCI_VERSION_MIN,
        crate::validate::OCI_VERSION_MAX
    )
    .context("writing the version")?;
    Ok(0)
}

/// Which point in the lifecycle a hook list belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HookPoint {
    /// After the payload has started.
    PostStart,
    /// After the container is gone.
    PostStop,
}

/// Runs the hooks that belong inside the container just before it starts.
///
/// Unlike the hooks that run after the container is gone, a failure here
/// stops the lifecycle: the payload has not run yet, and a hook that was
/// meant to prepare something for it did not.
fn start_container_hooks(record: &Record) -> Result<()> {
    if !record.hooks.start_container {
        return Ok(());
    }
    let path = std::path::Path::new(&record.bundle).join("config.json");
    let Ok(config) = std::fs::read(path) else {
        return Ok(());
    };
    let arena = Bump::new();
    let Ok(spec) = parse::spec(&config, &arena) else {
        return Ok(());
    };
    let Some(sections) = spec.hooks.as_ref() else {
        return Ok(());
    };
    if sections.start_container.is_empty() {
        return Ok(());
    }
    let state = state::render_public(record, crate::observed_status(record));
    hooks::run_in_container(record.pid, &sections.start_container, &state)
}

/// Reads the bundle back and runs one of its hook lists.
///
/// Both lists are best effort, as the specification asks: by the time either
/// runs the container is beyond the point where tearing it down would help, so
/// a failed notification is only worth reporting.
///
/// The configuration is read again rather than kept, because these run at
/// points where the runtime may be a different process from the one that
/// created the container. The record says whether the list is empty, which
/// it usually is, and then the bundle is not read at all.
fn run_bundle_hooks(record: &Record, point: HookPoint) {
    let present = match point {
        HookPoint::PostStart => record.hooks.poststart,
        HookPoint::PostStop => record.hooks.poststop,
    };
    if !present {
        return;
    }
    let path = std::path::Path::new(&record.bundle).join("config.json");
    let Ok(config) = std::fs::read(path) else {
        return;
    };
    let arena = Bump::new();
    let Ok(spec) = parse::spec(&config, &arena) else {
        return;
    };
    let Some(sections) = spec.hooks.as_ref() else {
        return;
    };
    let list = match point {
        HookPoint::PostStart => &sections.poststart,
        HookPoint::PostStop => &sections.poststop,
    };
    let state = state::render_public(record, crate::observed_status(record));
    hooks::run_best_effort(list, &state);
}
