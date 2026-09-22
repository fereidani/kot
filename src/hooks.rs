//! Running the programs a configuration attaches to the lifecycle.
//!
//! Each hook gets the container's state on standard input, which is how it
//! learns which container it is being run for. A hook that fails stops the
//! lifecycle, except after the container is gone, where there is nothing left
//! to stop and a failure is only worth reporting.

use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};

use crate::oci::spec::Hook;

/// Where a hook runs and where what it prints goes.
///
/// A hook is written against its bundle, so the bundle is its working
/// directory. Its output has nowhere to go by default, the runtime's own
/// streams being the container's, so a bundle that wants it names a file
/// through an annotation.
pub struct Environment<'a> {
    /// The bundle, which becomes the hook's working directory.
    pub bundle: &'a Path,
    /// Where the hook's standard output is appended, if anywhere.
    pub stdout: Option<&'a str>,
    /// Where the hook's standard error is appended, if anywhere.
    pub stderr: Option<&'a str>,
}

/// The annotation naming where hook output goes.
const STDOUT_ANNOTATION: &str = "run.oci.hooks.stdout";
/// The same, for what a hook prints on its error stream.
const STDERR_ANNOTATION: &str = "run.oci.hooks.stderr";

impl<'a> Environment<'a> {
    /// Reads the output annotations a bundle may carry.
    #[must_use]
    pub fn new(bundle: &'a Path, annotations: &[(&'a str, &'a str)]) -> Self {
        let find = |wanted: &str| {
            annotations
                .iter()
                .find(|(key, _)| *key == wanted)
                .map(|(_, value)| *value)
        };
        Self {
            bundle,
            stdout: find(STDOUT_ANNOTATION),
            stderr: find(STDERR_ANNOTATION),
        }
    }

    /// Opens one of the files hook output is appended to.
    ///
    /// The annotation is the caller's, so a relative path in it means one
    /// from where the runtime was started.
    fn open(path: Option<&str>) -> Result<Option<std::fs::File>> {
        let Some(path) = path else {
            return Ok(None);
        };
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(Some)
            .with_context(|| format!("opening {path} for hook output"))
    }
}

/// Runs a list of hooks in order, stopping at the first failure.
pub fn run(
    hooks: &[Hook<'_>],
    state: &str,
    where_: &Environment<'_>,
) -> Result<()> {
    for hook in hooks {
        run_one(hook, state, where_)
            .with_context(|| format!("running the hook {}", hook.path))?;
    }
    Ok(())
}

/// Runs a list of hooks, reporting failures without stopping.
///
/// The specification asks for this at the two points past anything a
/// failure could undo: the payload is already running, or the container is
/// already gone. A hook that fails there is a warning.
pub fn run_best_effort(
    hooks: &[Hook<'_>],
    state: &str,
    where_: &Environment<'_>,
    point: &str,
) {
    for hook in hooks {
        if let Err(error) = run_one(hook, state, where_) {
            crate::log::warn(&format!(
                "{point} hook failed with exit code or error: {error:#} \
                 ({})",
                hook.path
            ));
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
    where_: &Environment<'_>,
    when: Stage,
) -> Result<()> {
    for hook in hooks {
        let (namespaces, pid_namespace) = open_namespaces(pid)?;
        run_one_in(hook, state, namespaces, where_, when, pid_namespace)
            .with_context(|| format!("running the hook {}", hook.path))?;
    }
    Ok(())
}

/// Which side of the change of root a hook runs on.
///
/// It decides the working directory, the only thing that differs:
/// `createContainer` still reaches the bundle, `startContainer` runs where
/// the bundle has no path at all and starts at the container's root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    /// Before the root changed: the bundle is still reachable.
    BeforePivot,
    /// After it: only the container's own filesystem is.
    AfterPivot,
}

/// Opens the namespaces of `pid`, in the order they have to be entered.
fn open_namespaces(pid: i32) -> Result<(Vec<std::os::fd::OwnedFd>, bool)> {
    /// A user namespace decides what the joins after it may do, and a mount
    /// namespace changes what every path means, so they bracket the rest.
    const ORDER: [&str; 7] =
        ["user", "ipc", "uts", "net", "pid", "cgroup", "mnt"];

    let mut paths = Vec::with_capacity(ORDER.len());
    let mut pid_namespace = false;
    for name in ORDER {
        let path = format!("/proc/{pid}/ns/{name}");
        // Only the namespaces the container actually has of its own. A
        // namespace it shares with the runtime is one the hook is already in,
        // and the kernel refuses a user namespace on those terms rather than
        // treating it as the no-op it would be.
        if shares_namespace(&path) == Some(false) {
            pid_namespace |= name == "pid";
            paths.push(path);
        }
    }
    let opened = crate::linux::namespace::open_joins(&paths)
        .context("opening the container's namespaces for a hook")?;
    Ok((opened, pid_namespace))
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
    where_: &Environment<'_>,
    when: Stage,
    pid_namespace: bool,
) -> Result<()> {
    let mut command = prepare(hook, where_)?;
    // The directory is reached through the container's mount namespace, so
    // the move into it waits until the joins are done. `prepare` set it for
    // the ordinary case; the closure below does it at the right moment.
    command.current_dir("/");
    let directory = match when {
        Stage::BeforePivot => {
            std::ffi::CString::new(where_.bundle.as_os_str().as_encoded_bytes())
                .context("the bundle path has a nul in it")?
        }
        Stage::AfterPivot => c"/".to_owned(),
    };
    crate::sys::process::join_before_exec(
        &mut command,
        namespaces,
        Some(directory),
        pid_namespace,
    );
    wait_for_hook(command, hook, state)
}

fn run_one(
    hook: &Hook<'_>,
    state: &str,
    where_: &Environment<'_>,
) -> Result<()> {
    wait_for_hook(prepare(hook, where_)?, hook, state)
}

/// Builds the command a hook runs as, without starting it.
fn prepare(hook: &Hook<'_>, where_: &Environment<'_>) -> Result<Command> {
    let mut command = Command::new(hook.path);
    if let Some((_, rest)) = hook.args.split_first() {
        command.args(rest);
    }
    // A hook that states an environment gets that one and nothing else.
    // One that states none inherits the runtime's, which is what a hook
    // written as a shell script needs to find a program at all.
    if !hook.env.is_empty() {
        command.env_clear();
        for entry in &hook.env {
            if let Some((key, value)) = entry.split_once('=') {
                command.env(key, value);
            }
        }
    }
    command.current_dir(where_.bundle);
    if let Some(file) = Environment::open(where_.stdout)? {
        command.stdout(Stdio::from(file));
    }
    if let Some(file) = Environment::open(where_.stderr)? {
        command.stderr(Stdio::from(file));
    }
    command.stdin(Stdio::piped());
    Ok(command)
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
