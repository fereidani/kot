//! Running the programs a configuration attaches to the lifecycle.
//!
//! Each hook gets the container's state on standard input, which is how it
//! learns which container it is being run for. A hook that fails stops the
//! lifecycle, except after the container is gone, where there is nothing left
//! to stop and a failure is only worth reporting.

use std::{
    io::Write as _,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};

use crate::oci::spec::Hook;

/// Runs a list of hooks in order, stopping at the first failure.
pub fn run(hooks: &[Hook<'_>], state: &str) -> Result<()> {
    for hook in hooks {
        run_one(hook, state)
            .with_context(|| format!("running the hook {}", hook.path))?;
    }
    Ok(())
}

/// Runs a list of hooks, reporting failures without stopping.
///
/// The specification asks for this after the container is gone: a `poststop`
/// hook that fails is a warning, because there is no state left to protect.
pub fn run_best_effort(hooks: &[Hook<'_>], state: &str) {
    for hook in hooks {
        if let Err(error) = run_one(hook, state) {
            crate::log::warn(&format!("hook {} failed: {error:#}", hook.path));
        }
    }
}

/// Runs a list of hooks inside the namespaces of the container's process.
///
/// Two of the hook points the specification defines run in the container
/// rather than beside it: `createContainer`, which runs before the root is
/// changed and so still sees the host's paths, and `startContainer`, which
/// runs after and so sees the container's own.
pub fn run_in_container(
    pid: i32,
    hooks: &[Hook<'_>],
    state: &str,
) -> Result<()> {
    for hook in hooks {
        let namespaces = open_namespaces(pid)?;
        run_one_in(hook, state, namespaces)
            .with_context(|| format!("running the hook {}", hook.path))?;
    }
    Ok(())
}

/// Opens the namespaces of `pid`, in the order they have to be entered.
fn open_namespaces(pid: i32) -> Result<Vec<std::os::fd::OwnedFd>> {
    /// A user namespace decides what the joins after it may do, and a mount
    /// namespace changes what every path means, so they bracket the rest.
    const ORDER: [&str; 7] =
        ["user", "ipc", "uts", "net", "pid", "cgroup", "mnt"];

    let mut paths = Vec::with_capacity(ORDER.len());
    for name in ORDER {
        let path = format!("/proc/{pid}/ns/{name}");
        // Only the namespaces the container actually has of its own. A
        // namespace it shares with the runtime is one the hook is already in,
        // and the kernel refuses a user namespace on those terms rather than
        // treating it as the no-op it would be.
        if shares_namespace(&path) == Some(false) {
            paths.push(path);
        }
    }
    crate::linux::namespace::open_joins(&paths)
        .context("opening the container's namespaces for a hook")
}

/// Whether the runtime is already in the namespace `path` names.
///
/// Answers `None` when the namespace is not there at all, as it is on a kernel
/// without that namespace type.
fn shares_namespace(path: &str) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let theirs = std::fs::metadata(path).ok()?;
    let name = path.rsplit('/').next()?;
    let ours = std::fs::metadata(format!("/proc/self/ns/{name}")).ok()?;
    Some((theirs.dev(), theirs.ino()) == (ours.dev(), ours.ino()))
}

fn run_one_in(
    hook: &Hook<'_>,
    state: &str,
    namespaces: Vec<std::os::fd::OwnedFd>,
) -> Result<()> {
    let mut command = prepare(hook);
    crate::sys::process::join_before_exec(&mut command, namespaces);
    wait_for_hook(command, hook, state)
}

fn run_one(hook: &Hook<'_>, state: &str) -> Result<()> {
    wait_for_hook(prepare(hook), hook, state)
}

/// Builds the command a hook runs as, without starting it.
fn prepare(hook: &Hook<'_>) -> Command {
    let mut command = Command::new(hook.path);
    if let Some((_, rest)) = hook.args.split_first() {
        command.args(rest);
    }
    // A hook inherits nothing: the environment it gets is the one the
    // configuration gave it, so a variable the runtime happened to have does
    // not leak into it.
    command.env_clear();
    for entry in &hook.env {
        if let Some((key, value)) = entry.split_once('=') {
            command.env(key, value);
        }
    }
    command.stdin(Stdio::piped());
    command
}

/// Starts a prepared hook, feeds it the state, and waits for it to finish.
fn wait_for_hook(
    mut command: Command,
    hook: &Hook<'_>,
    state: &str,
) -> Result<()> {
    let mut child = command
        .spawn()
        .with_context(|| format!("starting the hook {}", hook.path))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A hook that does not read its input is normal, so a broken pipe here
        // is not a failure.
        let _ = stdin.write_all(state.as_bytes());
    }

    let Some(seconds) = hook.timeout.filter(|t| *t > 0) else {
        let status = child.wait().context("waiting for the hook")?;
        return check(status, hook);
    };

    let deadline = Instant::now() + Duration::from_secs(seconds.unsigned_abs());
    // Bounded by the deadline; the iteration cap is a second guard.
    for _ in 0..1_000_000u32 {
        if let Some(status) =
            child.try_wait().context("waiting for the hook")?
        {
            return check(status, hook);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("the hook {} exceeded its timeout", hook.path);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    bail!("the hook {} did not finish", hook.path)
}

fn check(status: std::process::ExitStatus, hook: &Hook<'_>) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    match status.code() {
        Some(code) => bail!("the hook {} exited with {code}", hook.path),
        None => bail!("the hook {} was killed by a signal", hook.path),
    }
}
