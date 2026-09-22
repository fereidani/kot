//! Command line parsing.
//!
//! The surface is fixed by what Podman, CRI-O and the containerd shim already
//! send, so this is a transcription of `runc`'s interface rather than a design
//! of one. Hand written because the grammar is flat, the option set is closed,
//! and an argument parser would be a dependency larger than the thing it
//! parses.

use anyhow::{Result, bail};

use crate::cgroup::Kind;

/// Options that may appear before the command.
#[derive(Clone, Debug, Default)]
pub struct Global {
    /// Where container state lives.
    pub root: Option<String>,
    /// Where diagnostics go.
    pub log: Option<String>,
    /// Format of those diagnostics.
    pub log_format: LogFormat,
    /// How much to report.
    pub level: Level,
    /// Which cgroup manager to use.
    pub cgroup_manager: Kind,
}

/// How diagnostics are rendered.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum LogFormat {
    /// One line per message.
    #[default]
    Text,
    /// One JSON object per message, for a supervisor to parse.
    Json,
}

/// How much to report.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    /// Only failures.
    Error,
    /// Failures and things that might become failures.
    ///
    /// The default: the specification has the runtime warn about several
    /// things it then carries on from, and a caller who never sees those
    /// has no way to know they happened.
    #[default]
    Warning,
    /// Everything.
    Debug,
}

/// What the caller asked for.
///
/// The variants differ a good deal in size, and boxing the large ones would
/// save a few words on a value that exists once per invocation and is read
/// immediately. Naming the fields is worth more than that.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Command {
    /// Build a container without running it.
    Create(Start),
    /// Build a container and run it.
    Run(Start),
    /// Run the payload of a container that was created.
    Start {
        /// Container identifier.
        id: String,
    },
    /// Report a container's state.
    State {
        /// Container identifier.
        id: String,
    },
    /// Send a signal to a container.
    Kill {
        /// Container identifier.
        id: String,
        /// Signal name or number.
        signal: String,
        /// Send to every process rather than just the first.
        all: bool,
    },
    /// Remove a container.
    Delete {
        /// Container identifier.
        id: String,
        /// Kill the container first if it is still running.
        force: bool,
    },
    /// Run another process inside a container.
    Exec(Exec),
    /// List the containers this state root knows about.
    List {
        /// Emit JSON rather than a table.
        json: bool,
        /// Show every container, including stopped ones.
        quiet: bool,
    },
    /// Show the processes in a container.
    Ps {
        /// Container identifier.
        id: String,
        /// Emit JSON rather than a table.
        json: bool,
        /// Arguments passed through to `ps`.
        args: Vec<String>,
    },
    /// Stop every process in a container.
    Pause {
        /// Container identifier.
        id: String,
    },
    /// Let a paused container run again.
    Resume {
        /// Container identifier.
        id: String,
    },
    /// Change a running container's resource limits.
    Update(Update),
    /// Write a starting configuration.
    Spec {
        /// Bundle directory to write into.
        bundle: String,
        /// Generate a configuration for a container without privilege.
        rootless: bool,
    },
    /// Report what a container is using, repeatedly or once.
    Events {
        /// Container identifier.
        id: String,
        /// Seconds between samples.
        interval: u64,
        /// Print one sample and stop.
        once: bool,
    },
    /// Report what this build supports.
    Features,
    /// Report the version.
    Version,
    /// Print usage, either the whole of it or one command's.
    Help,
    /// Print how one command is called.
    CommandHelp(String),
    /// The container init process, which only the runtime itself invokes.
    Init {
        /// Encoded descriptor layout.
        args: String,
    },
}

/// Options shared by `create` and `run`.
///
/// Each boolean is a distinct command line flag, so they stay separate
/// fields rather than becoming a word that call sites would have to decode.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct Start {
    /// Container identifier.
    pub id: String,
    /// Bundle directory.
    pub bundle: String,
    /// Socket the terminal's controlling end is sent to.
    pub console_socket: Option<String>,
    /// File to write the container's process id into.
    pub pid_file: Option<String>,
    /// Extra descriptors to pass to the payload.
    pub preserve_fds: usize,
    /// Use `chroot` rather than `pivot_root`.
    pub no_pivot: bool,
    /// Do not give the container its own session keyring.
    pub no_new_keyring: bool,
    /// Run in the background.
    pub detach: bool,
    /// Configuration file to read instead of `config.json`.
    pub config: Option<String>,
    /// Keep the container's state after a foreground run ends.
    pub keep: bool,
}

/// Options for `exec`.
///
/// Each boolean is a distinct command line flag, so they stay separate fields
/// rather than becoming a word that call sites would have to decode.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct Exec {
    /// Container identifier.
    pub id: String,
    /// Program and arguments.
    pub args: Vec<String>,
    /// Read the process description from a file instead.
    pub process: Option<String>,
    /// Working directory.
    pub cwd: Option<String>,
    /// Environment entries to add.
    pub env: Vec<String>,
    /// Allocate a terminal.
    pub tty: bool,
    /// User, and optionally group, to run as.
    pub user: Option<String>,
    /// Supplementary groups.
    pub additional_gids: Vec<u32>,
    /// Capabilities to add.
    pub caps: Vec<String>,
    /// Socket the terminal's controlling end is sent to.
    pub console_socket: Option<String>,
    /// File to write the process id into.
    pub pid_file: Option<String>,
    /// Run in the background.
    pub detach: bool,
    /// Refuse any later gain of privilege.
    pub no_new_privs: bool,
    /// `AppArmor` profile to transition to.
    pub apparmor: Option<String>,
    /// `SELinux` label to transition to.
    pub process_label: Option<String>,
    /// Extra descriptors to pass through.
    pub preserve_fds: usize,
    /// Run even when the container is paused.
    pub ignore_paused: bool,
    /// Sub-cgroup to run in.
    pub cgroup: Option<String>,
}

/// Options for `update`.
#[derive(Clone, Debug, Default)]
pub struct Update {
    /// Container identifier.
    pub id: String,
    /// Read the new limits from a file, or from standard input when `-`.
    pub resources: Option<String>,
    /// Individual limits given on the command line.
    pub values: Vec<(String, String)>,
}

/// A cursor over the words of a command line.
///
/// Every parser below walks the same way: take a word, and when that word
/// names an option take the word after it as the option's value. Each word is
/// taken once, so a loop over [`Args::word`] runs as many times as there are
/// words and no more.
struct Args<'a> {
    words: &'a [String],
    index: usize,
    /// The value half of a `--name=value` word, waiting to be read by the
    /// option it was attached to.
    attached: Option<&'a str>,
}

impl<'a> Args<'a> {
    const fn new(words: &'a [String]) -> Self {
        Self {
            words,
            index: 0,
            attached: None,
        }
    }

    /// The next word, or nothing when the line is finished.
    ///
    /// A long option may carry its value in the same word, and the engines
    /// that drive a runtime write it both ways. Splitting it here is what
    /// lets every option below read its value the same way, whichever
    /// spelling the caller used.
    fn word(&mut self) -> Option<&'a str> {
        if let Some(value) = self.attached.take() {
            // The option it was attached to does not take a value, so the
            // value stands on its own and is read as the next word would
            // be. That is the same line the caller wrote with a space, and
            // it fails in the same way rather than being dropped.
            return Some(value);
        }
        let word = self.words.get(self.index)?;
        self.index += 1;
        if word.starts_with("--") {
            if let Some((name, value)) = word.split_once('=') {
                self.attached = Some(value);
                return Some(name);
            }
        }
        Some(word.as_str())
    }

    /// Everything not taken yet.
    fn remainder(&self) -> &'a [String] {
        self.words.get(self.index..).unwrap_or(&[])
    }

    /// The word as the caller wrote it, with any attached value still part
    /// of it.
    ///
    /// A word that is passed through to something else rather than read as
    /// an option here has to go on exactly as it arrived: `--color=auto` is
    /// one argument to the program a container runs, and handing that
    /// program two would change what it was asked to do.
    fn unsplit(&mut self, word: &'a str) -> &'a str {
        if self.attached.take().is_none() {
            return word;
        }
        self.index
            .checked_sub(1)
            .and_then(|at| self.words.get(at))
            .map_or(word, String::as_str)
    }

    /// The value of an option, whether it was attached with `=` or written
    /// as the word after it.
    fn value(&mut self, name: &str) -> Result<String> {
        self.word()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("{name} needs a value"))
    }

    /// The same, read as a number of whatever kind the field holds.
    fn number<T: core::str::FromStr>(&mut self, name: &str) -> Result<T> {
        self.value(name)?
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} needs a number"))
    }
}

/// Whether a command's own options include a request for its usage.
fn asks_for_help(rest: &[String]) -> bool {
    for word in rest {
        // The conventional end of options, and the first plain word, both
        // hand the remainder to the command.
        if word == "--" || !word.starts_with('-') {
            return false;
        }
        if word == "--help" || word == "-h" {
            return true;
        }
    }
    false
}

/// How one command is called, for `COMMAND --help`.
///
/// One entry per command: the line it is called on, and its options.
const COMMAND_USAGE: [(&str, &str, &str); 18] = [
    (
        "create",
        "create [options] CONTAINER",
        "  --bundle PATH, --console-socket PATH, --pid-file PATH,\n  \
         --preserve-fds N, --no-pivot, --no-new-keyring, --config NAME\n",
    ),
    (
        "run",
        "run [options] CONTAINER",
        "  --bundle PATH, --console-socket PATH, --pid-file PATH,\n  \
         --preserve-fds N, --no-pivot, --no-new-keyring, --detach,\n  \
         --config NAME\n",
    ),
    ("start", "start CONTAINER", ""),
    ("state", "state CONTAINER", ""),
    (
        "kill",
        "kill [options] CONTAINER [SIGNAL]",
        "  --all, --signal SIGNAL\n",
    ),
    ("delete", "delete [options] CONTAINER", "  --force\n"),
    (
        "exec",
        "exec [options] CONTAINER cmd [args]",
        "  --process PATH, --console-socket PATH, --pid-file PATH,\n  \
         --cwd PATH, --env VAR=VALUE, --user UID[:GID], --cap CAP,\n  \
         --preserve-fds N, --detach, --no-new-privs, --cgroup PATH,\n  \
         --process-label LABEL, --apparmor PROFILE, --tty\n",
    ),
    (
        "list",
        "list [options]",
        "  --quiet, --format text|json, --all\n",
    ),
    (
        "ps",
        "ps [options] CONTAINER [ps options]",
        "  --format table|json\n",
    ),
    ("pause", "pause CONTAINER", ""),
    ("resume", "resume CONTAINER", ""),
    ("unpause", "unpause CONTAINER", ""),
    (
        "update",
        "update [options] CONTAINER",
        "  --resources PATH, and one option per limit\n",
    ),
    ("spec", "spec [options]", "  --bundle PATH, --rootless\n"),
    (
        "events",
        "events [options] CONTAINER",
        "  --interval SECONDS, --stats\n",
    ),
    ("features", "features", ""),
    ("version", "version", ""),
    (
        "ls",
        "ls [options]",
        "  --quiet, --format text|json, --all\n",
    ),
];

/// How a command is called, when the name is one.
#[must_use]
pub fn command_usage(name: &str) -> Option<String> {
    COMMAND_USAGE
        .iter()
        .find(|(command, _, _)| *command == name)
        .map(|(_, line, options)| {
            format!("Usage: kot [global options] {line}\n{options}")
        })
}

/// Parses a command line.
#[allow(clippy::similar_names)]
pub fn parse(argv: &[String]) -> Result<(Global, Command)> {
    let mut global = Global::default();
    let mut args = Args::new(argv.get(1..).unwrap_or(&[]));

    // Bounded by the argument count: every iteration takes one word. The
    // first word that is not a global option is the command's name.
    let name = loop {
        let Some(word) = args.word() else {
            return Ok((global, Command::Help));
        };
        let Some(option) = word.strip_prefix("--") else {
            break word;
        };
        if let Some(command) = global_option(option, &mut args, &mut global)? {
            return Ok((global, command));
        }
    };

    let rest = args.remainder();
    // Every command answers `--help` with how it is called. Only its own
    // options are read for it: past the first word that is not one,
    // `kot exec ctr program --help` is asking that program, not this one.
    if asks_for_help(rest) {
        if let Some(usage) = command_usage(name) {
            return Ok((global, Command::CommandHelp(usage)));
        }
    }
    let command = match name {
        "create" => Command::Create(parse_start(rest)?),
        "run" => Command::Run(parse_start(rest)?),
        "start" => Command::Start {
            id: only_id(rest, "start")?,
        },
        "state" => Command::State {
            id: only_id(rest, "state")?,
        },
        "kill" => parse_kill(rest)?,
        "delete" => parse_delete(rest)?,
        "exec" => Command::Exec(parse_exec(rest)?),
        "list" | "ls" => parse_list(rest),
        "ps" => parse_ps(rest)?,
        "pause" => Command::Pause {
            id: only_id(rest, "pause")?,
        },
        "resume" | "unpause" => Command::Resume {
            id: only_id(rest, "resume")?,
        },
        "update" => Command::Update(parse_update(rest)?),
        "spec" => parse_spec(rest)?,
        "events" => parse_events(rest)?,
        "features" => Command::Features,
        "version" | "-v" | "-V" => Command::Version,
        "help" | "h" | "-h" => Command::Help,
        "__init" => Command::Init {
            args: rest.first().cloned().unwrap_or_default(),
        },
        // Both are checkpoint and restore through CRIU, which this runtime
        // does not carry and reports as unavailable in `features`. An
        // operator who calls one is running an engine that needs it, and
        // naming CRIU tells them which runtime to go back to.
        "checkpoint" | "restore" => bail!(
            "{name} needs CRIU, which this runtime does not implement; \
             `kot features` reports checkpoint support as false"
        ),
        other => bail!("unknown command: {other}"),
    };
    Ok((global, command))
}

/// Applies one global option.
///
/// Returns a command when the option is one that answers the whole command
/// line by itself, such as `--version`, and nothing when there are more
/// options to read.
fn global_option(
    name: &str,
    args: &mut Args<'_>,
    out: &mut Global,
) -> Result<Option<Command>> {
    match name {
        "root" => out.root = Some(args.value("--root")?),
        "log" => out.log = Some(args.value("--log")?),
        "log-format" => {
            out.log_format = match args.value("--log-format")?.as_str() {
                "text" => LogFormat::Text,
                "json" => LogFormat::Json,
                other => bail!("unknown log format: {other}"),
            };
        }
        "log-level" => {
            out.level = match args.value("--log-level")?.as_str() {
                "error" => Level::Error,
                "warn" | "warning" => Level::Warning,
                "debug" | "info" => Level::Debug,
                other => bail!("unknown log level: {other}"),
            };
        }
        "debug" => out.level = Level::Debug,
        "systemd-cgroup" => out.cgroup_manager = Kind::Systemd,
        "cgroup-manager" => {
            let name = args.value("--cgroup-manager")?;
            out.cgroup_manager = Kind::by_name(&name).ok_or_else(|| {
                anyhow::anyhow!("unknown cgroup manager: {name}")
            })?;
        }
        // Accepted and ignored, as crun does, so that a command line
        // written for another runtime does not fail outright.
        "rootless" => {
            let _ = args.value("--rootless")?;
        }
        "version" => return Ok(Some(Command::Version)),
        "help" => return Ok(Some(Command::Help)),
        other => bail!("unknown option: --{other}"),
    }
    Ok(None)
}

/// A command line separated into the options it names and the words it does
/// not.
///
/// The simpler commands all want the same thing: some options that take no
/// value, and one or two plain words. They differ only in which options they
/// know, so the walk lives here and the table stays with the command.
struct Parts<'a> {
    options: Vec<&'a str>,
    words: Vec<&'a str>,
}

impl<'a> Parts<'a> {
    /// Separates a line, accepting whatever options it names.
    ///
    /// Needed by the commands that have to swallow a command line written for
    /// another runtime.
    fn any(rest: &'a [String]) -> Self {
        let (options, words) = rest
            .iter()
            .map(String::as_str)
            .partition(|word| word.starts_with('-'));
        Self { options, words }
    }

    /// The same, refusing any option outside `accept`.
    fn split(rest: &'a [String], accept: &[&str]) -> Result<Self> {
        let out = Self::any(rest);
        for option in &out.options {
            if !accept.contains(option) {
                bail!("unknown option: {option}");
            }
        }
        Ok(out)
    }

    /// True when the line named any of these spellings.
    fn has(&self, spellings: &[&str]) -> bool {
        self.options.iter().any(|seen| spellings.contains(seen))
    }

    /// The only container id on the line.
    fn only_id(&self, command: &str) -> Result<String> {
        match self.words.as_slice() {
            [id] => Ok((*id).to_owned()),
            [] => bail!("{command} needs a container id"),
            _ => bail!("{command} takes one container id"),
        }
    }
}

fn only_id(rest: &[String], command: &str) -> Result<String> {
    Parts::any(rest).only_id(command)
}

fn parse_start(rest: &[String]) -> Result<Start> {
    let mut out = Start {
        bundle: ".".to_owned(),
        ..Start::default()
    };
    let mut args = Args::new(rest);
    while let Some(argument) = args.word() {
        match argument {
            "--bundle" | "-b" => out.bundle = args.value(argument)?,
            "--console-socket" => {
                out.console_socket = Some(args.value(argument)?);
            }
            "--pid-file" => out.pid_file = Some(args.value(argument)?),
            "--preserve-fds" => out.preserve_fds = args.number(argument)?,
            "--no-pivot" => out.no_pivot = true,
            "--no-new-keyring" => out.no_new_keyring = true,
            "--detach" | "-d" => out.detach = true,
            "--config" | "-f" => out.config = Some(args.value(argument)?),
            "--keep" => out.keep = true,
            // Accepted and ignored: this runtime does not reparent the
            // processes a container leaves behind, so there is no subreaper
            // to turn off, and refusing the flag would stop a command line
            // that asks for exactly what already happens.
            "--no-subreaper" => {}
            other if other.starts_with('-') => {
                bail!("unknown option: {other}");
            }
            other => other.clone_into(&mut out.id),
        }
    }
    if out.id.is_empty() {
        bail!("a container id is required");
    }
    Ok(out)
}

fn parse_kill(rest: &[String]) -> Result<Command> {
    let parts = Parts::split(rest, &["--all", "-a"])?;
    let Some(id) = parts.words.first().copied() else {
        bail!("kill needs a container id");
    };
    // The signal is positional and optional, which is how every other runtime
    // spells it.
    let signal = parts.words.get(1).copied().unwrap_or("TERM");
    Ok(Command::Kill {
        id: id.to_owned(),
        signal: signal.to_owned(),
        all: parts.has(&["--all", "-a"]),
    })
}

fn parse_delete(rest: &[String]) -> Result<Command> {
    let parts = Parts::split(rest, &["--force", "-f"])?;
    Ok(Command::Delete {
        id: parts.only_id("delete")?,
        force: parts.has(&["--force", "-f"]),
    })
}

/// Every option other than `--quiet` is accepted and ignored, including
/// `--format` and its value, so that a command line written for another
/// runtime still works.
fn parse_list(rest: &[String]) -> Command {
    let parts = Parts::any(rest);
    Command::List {
        json: parts.words.contains(&"json"),
        quiet: parts.has(&["--quiet", "-q"]),
    }
}

fn parse_ps(rest: &[String]) -> Result<Command> {
    let mut json = false;
    let mut id = None;
    let mut extra = Vec::new();
    let mut args = Args::new(rest);
    while let Some(argument) = args.word() {
        match argument {
            "--format" | "-f" => {
                if args.word() == Some("json") {
                    json = true;
                }
            }
            "--" => {}
            other if id.is_none() && !other.starts_with('-') => {
                id = Some(other.to_owned());
            }
            // Everything else is the caller's own argument to `ps`, and
            // goes on as it was written.
            other => {
                let whole = args.unsplit(other).to_owned();
                extra.push(whole);
            }
        }
    }
    let id = id.ok_or_else(|| anyhow::anyhow!("ps needs a container id"))?;
    Ok(Command::Ps {
        id,
        json,
        args: extra,
    })
}

fn parse_update(rest: &[String]) -> Result<Update> {
    let mut out = Update::default();
    let mut args = Args::new(rest);
    while let Some(argument) = args.word() {
        if argument == "--resources" || argument == "-r" {
            out.resources = Some(args.value(argument)?);
            continue;
        }
        // Anything else spelled as an option is a single limit, named the way
        // the specification names it rather than the way the flag does.
        if let Some(name) = argument.strip_prefix("--") {
            let Some(value) = args.word() else {
                bail!("--{name} needs a value");
            };
            out.values.push((name.to_owned(), value.to_owned()));
            continue;
        }
        argument.clone_into(&mut out.id);
    }
    if out.id.is_empty() {
        bail!("update needs a container id");
    }
    Ok(out)
}

fn parse_spec(rest: &[String]) -> Result<Command> {
    let mut bundle = ".".to_owned();
    let mut rootless = false;
    let mut args = Args::new(rest);
    while let Some(argument) = args.word() {
        match argument {
            "--bundle" | "-b" => bundle = args.value("--bundle")?,
            "--rootless" => rootless = true,
            other => bail!("unknown option: {other}"),
        }
    }
    Ok(Command::Spec { bundle, rootless })
}

fn parse_exec(rest: &[String]) -> Result<Exec> {
    let mut out = Exec::default();
    let mut args = Args::new(rest);
    let mut saw_separator = false;
    while let Some(argument) = args.word() {
        // Options belong to `exec` itself only until the command begins.
        // After the first word of the command, everything is the command's,
        // including words starting with a dash: `exec id sh -c ...` passes
        // `-c` to the shell, not to the runtime.
        let in_command = saw_separator
            || !out.args.is_empty()
            || (!out.id.is_empty() && !argument.starts_with('-'));
        if in_command {
            let argument = args.unsplit(argument);
            if out.id.is_empty() {
                argument.clone_into(&mut out.id);
            } else {
                out.args.push(argument.to_owned());
            }
            continue;
        }
        match argument {
            "--" => saw_separator = true,
            "--process" | "-p" => {
                out.process = Some(args.value(argument)?);
            }
            "--cwd" => out.cwd = Some(args.value(argument)?),
            "--env" | "-e" => out.env.push(args.value(argument)?),
            "--tty" | "-t" => out.tty = true,
            "--user" | "-u" => out.user = Some(args.value(argument)?),
            "--additional-gids" | "-g" => {
                out.additional_gids.push(args.number(argument)?);
            }
            "--cap" => out.caps.push(args.value(argument)?),
            "--console-socket" => {
                out.console_socket = Some(args.value(argument)?);
            }
            "--pid-file" => out.pid_file = Some(args.value(argument)?),
            "--detach" | "-d" => out.detach = true,
            "--no-new-privs" => out.no_new_privs = true,
            "--apparmor" => out.apparmor = Some(args.value(argument)?),
            "--process-label" => {
                out.process_label = Some(args.value(argument)?);
            }
            "--preserve-fds" => out.preserve_fds = args.number(argument)?,
            "--ignore-paused" => out.ignore_paused = true,
            "--cgroup" => out.cgroup = Some(args.value(argument)?),
            other if other.starts_with('-') => {
                bail!("unknown option: {other}");
            }
            other => other.clone_into(&mut out.id),
        }
    }
    if out.id.is_empty() {
        bail!("exec needs a container id");
    }
    if out.args.is_empty() && out.process.is_none() {
        bail!("exec needs a command or --process");
    }
    Ok(out)
}

/// The usage text.
pub const USAGE: &str = "\
kot: an OCI container runtime

Usage: kot [global options] COMMAND [options] [arguments]

Commands:
  create    build a container without running it
  start     run the payload of a container that was created
  run       build a container and run it
  state     report a container's state
  kill      send a signal to a container
  delete    remove a container
  exec      run another process inside a container
  list      list the containers this state root knows about
  ps        show the processes in a container
  pause     stop every process in a container
  resume    let a paused container run again
  update    change a running container's resource limits
  events    report what a container is using
  spec      write a starting configuration
  features  report what this build supports

Global options:
  --root PATH             where container state lives
  --log PATH              where diagnostics go
  --log-format FORMAT     text or json
  --log-level LEVEL       error, warning or debug
  --debug                 the same as --log-level debug
  --systemd-cgroup        manage cgroups through systemd
  --cgroup-manager NAME   cgroupfs, systemd or disabled
  --version               report the version
";

/// Parses `events`.
///
/// The default is a sample every five seconds, the interval a supervisor
/// polling a container expects when it names no interval.
fn parse_events(rest: &[String]) -> Result<Command> {
    /// Seconds between samples when the caller names none.
    const DEFAULT_INTERVAL: u64 = 5;

    let mut id = String::new();
    let mut interval = DEFAULT_INTERVAL;
    let mut once = false;
    let mut args = Args::new(rest);
    while let Some(argument) = args.word() {
        match argument {
            "--interval" => interval = args.number(argument)?,
            "--stats" => once = true,
            other if other.starts_with('-') => {
                bail!("unknown option: {other}");
            }
            other => other.clone_into(&mut id),
        }
    }
    if id.is_empty() {
        bail!("a container id is required");
    }
    if interval == 0 {
        bail!("--interval needs a number of seconds above zero");
    }
    Ok(Command::Events { id, interval, once })
}
