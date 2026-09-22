//! The state directory.
//!
//! One directory per container under the state root, holding a status record
//! and the fifo that separates `create` from `start`. The format is JSON and
//! stays human readable: it is a few hundred bytes and parses in microseconds,
//! so nothing is bought by making it opaque, and a great deal is lost when a
//! container is stuck and nobody can see why.
//!
//! Liveness is the one thing worth care. A recorded process id is not enough
//! on its own, because the kernel reuses them; it is trusted only together
//! with the process start time, which a reused id will not match.

use std::{
    fs,
    os::fd::{AsFd as _, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use bumpalo::Bump;
use rustix::{
    fs::{Mode, OFlags},
    io::Errno,
};

use crate::{json::Writer, oci::json::Parser};

/// Where container state lives for a privileged runtime.
pub const DEFAULT_ROOT: &str = "/run/kot";

/// Name of the status record inside a container's directory.
const STATUS: &str = "state.json";
/// Name the status record is written under before it is renamed into place.
const TEMPORARY: &str = ".state.json.new";
/// Name of the fifo that unblocks a created container.
const FIFO: &str = "exec.fifo";

/// The lifecycle state a container is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// The runtime is still building it.
    Creating,
    /// Built, but the payload has not been run.
    Created,
    /// The payload is running.
    Running,
    /// Every process in the container is stopped.
    ///
    /// Not part of the specification's set, but every other runtime reports
    /// it and callers act on it, so a container that omitted it would look
    /// like it had ignored `pause`.
    Paused,
    /// The payload has exited.
    Stopped,
}

impl Status {
    /// The word the specification uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
        }
    }

    fn by_name(name: &str) -> Option<Self> {
        match name {
            "creating" => Some(Self::Creating),
            "created" => Some(Self::Created),
            "running" => Some(Self::Running),
            "paused" => Some(Self::Paused),
            "stopped" => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// Everything the runtime remembers about a container.
#[derive(Clone, Debug, Default)]
pub struct Record {
    /// Container identifier.
    pub id: String,
    /// Version of the specification the bundle claimed.
    pub oci_version: String,
    /// Absolute path to the bundle.
    pub bundle: String,
    /// Process id of the container's init process.
    pub pid: i32,
    /// Start time of that process, in clock ticks since boot.
    ///
    /// Recorded because process ids are reused, and a stale record that
    /// happens to name a live process would otherwise let the runtime send a
    /// signal to something unrelated.
    pub start_time: u64,
    /// When the container was created, as a timestamp.
    pub created: String,
    /// Path of the container's cgroup, relative to the hierarchy root.
    pub cgroup_path: String,
    /// Transient unit name, when systemd manages the cgroup.
    pub systemd_unit: String,
    /// Which cgroup manager was used, so `delete` undoes what `create` did.
    pub cgroup_manager: String,
    /// User that created the container.
    pub owner: String,
    /// True when the container was created rather than run, so the payload is
    /// waiting on the fifo.
    pub awaiting_start: bool,
    /// Which of the hook lists that run after creation the configuration
    /// has.
    pub hooks: LaterHooks,
    /// Annotations from the configuration, passed through to callers.
    pub annotations: Vec<(String, String)>,
    /// The cache and bandwidth class this runtime created for the
    /// container, empty when it made none.
    ///
    /// Remembered rather than worked out again, because `delete` must
    /// remove only a class this runtime made: one the configuration named
    /// and somebody else created may hold other containers.
    pub rdt_class: String,
    /// True when this runtime made that class and may remove it again.
    pub rdt_owned: bool,
    /// The monitoring group this runtime created for the container, empty
    /// when it made none.
    ///
    /// Kept apart from the class because a container may be monitored
    /// inside a class somebody else owns: the group is this runtime's to
    /// remove even where the class is not.
    pub rdt_monitor: String,
}

/// Which of the hook lists that run after creation a configuration has.
///
/// Those hooks are read back from the bundle by whichever command reaches
/// them, which may be a later run of the runtime. Remembering whether there
/// are any lets the common bundle, which has none, skip reading and parsing
/// its configuration again at each of those points.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LaterHooks {
    /// `startContainer`, run inside the container just before the payload.
    pub start_container: bool,
    /// `poststart`, run once the payload is running.
    pub poststart: bool,
    /// `poststop`, run once the container is gone.
    pub poststop: bool,
}

impl Default for LaterHooks {
    /// The reading of a record that says nothing about its hooks, which is
    /// what a record written before these were kept does: there may be some.
    fn default() -> Self {
        Self {
            start_container: true,
            poststart: true,
            poststop: true,
        }
    }
}

/// The state root, and the operations on it.
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Opens a state root, creating it when missing.
    ///
    /// A caller that names one gets that and nothing else. Without one, the
    /// defaults are tried in order and the first that can be made wins.
    pub fn open(root: Option<&str>) -> Result<Self> {
        if let Some(named) = root {
            let path = PathBuf::from(named);
            make_root(&path).with_context(|| {
                format!("creating the state directory {}", path.display())
            })?;
            return Ok(Self { root: path });
        }

        let mut refused: Option<(PathBuf, std::io::Error)> = None;
        for path in default_roots() {
            match make_root(&path) {
                Ok(()) => return Ok(Self { root: path }),
                // Somewhere else may still serve, so the first refusal is
                // kept to report if nothing does.
                Err(e) if is_refusal(&e) => {
                    refused.get_or_insert((path, e));
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "creating the state directory {}",
                        path.display()
                    )));
                }
            }
        }

        let Some((path, error)) = refused else {
            bail!("there is nowhere to keep container state");
        };
        Err(anyhow::Error::new(error).context(format!(
            "creating the state directory {}; name one with --root",
            path.display()
        )))
    }

    /// The state root itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The directory a container's state lives in.
    #[must_use]
    pub fn directory(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// Creates a container's directory, refusing to reuse a live one.
    ///
    /// The creation itself is the check: a directory that is already there
    /// is a container that already exists.
    pub fn create(&self, id: &str) -> Result<PathBuf> {
        validate_id(id)?;
        let directory = self.directory(id);
        match rustix::fs::mkdir(&directory, Mode::from_raw_mode(0o777)) {
            Ok(()) => Ok(directory),
            Err(Errno::EXIST) => bail!("container with id {id} already exists"),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("creating the state directory for {id}"))),
        }
    }

    /// Removes a container's directory and everything in it.
    ///
    /// The directory holds only what the store put there, so those are
    /// removed by name and the directory after them, without listing it.
    /// One holding anything else is swept the general way.
    pub fn remove(&self, id: &str) -> Result<()> {
        use rustix::fs::{AtFlags, unlinkat};

        let directory = self.directory(id);
        let opened = rustix::fs::open(
            &directory,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let handle = match opened {
            Ok(handle) => handle,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "removing the state directory for {id}"
                )));
            }
        };
        for entry in [STATUS, TEMPORARY, FIFO] {
            match unlinkat(&handle, entry, AtFlags::empty()) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("removing the state for {id}")));
                }
            }
        }
        drop(handle);
        match unlinkat(rustix::fs::CWD, &directory, AtFlags::REMOVEDIR) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(Errno::NOTEMPTY) => fs::remove_dir_all(&directory)
                .with_context(|| {
                    format!("removing the state directory for {id}")
                }),
            Err(e) => Err(anyhow::Error::new(e)
                .context(format!("removing the state directory for {id}"))),
        }
    }

    /// Writes a container's status record, reporting `status` as its state.
    ///
    /// The status is the caller's to state and is never observed here, because
    /// the caller has just established it: a command that has the process
    /// as its child, or has watched it start, knows more than a look at
    /// `/proc` would say, and every later command observes afresh anyway.
    ///
    /// Written to a temporary name and then renamed, so a reader never sees a
    /// half-written record.
    pub fn save(&self, record: &Record, status: Status) -> Result<()> {
        let directory = self.directory(&record.id);
        let target = directory.join(STATUS);
        let temporary = directory.join(TEMPORARY);
        let failed = || format!("writing state for {}", record.id);

        let file = rustix::fs::open(
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o666),
        )
        .with_context(failed)?;
        write_all(file.as_fd(), render(record, status).as_bytes())
            .with_context(failed)?;
        // The record is not flushed: it describes a container that does
        // not survive the crash a flush protects against, and on a
        // disk-backed state root the flush costs a round trip on every
        // container, here nine milliseconds of the fifteen one took to
        // start.
        drop(file);
        rustix::fs::rename(&temporary, &target)
            .with_context(|| format!("committing state for {}", record.id))
    }

    /// Reads a container's status record.
    pub fn load(&self, id: &str) -> Result<Record> {
        let path = self.directory(id).join(STATUS);
        let mut bytes = Vec::new();
        crate::file::read(&path, &mut bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("container {id} does not exist")
            } else {
                anyhow::Error::new(e).context(format!("reading state for {id}"))
            }
        })?;
        let text = core::str::from_utf8(&bytes)
            .with_context(|| format!("parsing state for {id}"))?;
        let arena = Bump::new();
        parse_record(text, &arena)
            .with_context(|| format!("parsing state for {id}"))
    }

    /// Reads a container's record, refusing one whose payload has exited.
    ///
    /// The status is observed, not read back from the record, because the
    /// payload may have exited since the record was written.
    pub fn load_running(&self, id: &str) -> Result<Record> {
        let record = self.load(id)?;
        if observe(&record) == Status::Stopped {
            bail!("container {id} is not running");
        }
        Ok(record)
    }

    /// Every container in the state root.
    pub fn list(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(out);
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context("reading the state directory"));
            }
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned)
            else {
                continue;
            };
            // A directory without a status record is one being built or one
            // whose removal was interrupted; neither is a container to report.
            if let Ok(record) = self.load(&name) {
                out.push(record);
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Creates the fifo that separates `create` from `start`.
    pub fn create_fifo(&self, id: &str) -> Result<OwnedFd> {
        use rustix::fs::{Mode, OFlags, mknodat, open};

        let directory = self.directory(id);
        let path = directory.join(FIFO);
        let c_path = to_c_string(&path)?;
        mknodat(
            rustix::fs::CWD,
            c_path.as_c_str(),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o622),
            0,
        )
        .context("creating the start fifo")?;
        // `mknodat` takes the mode through the umask, which on the usual 022
        // leaves 0600 and takes away exactly the bit that matters. Init
        // reopens this through `/proc/self/fd` after it has become the
        // container's user, and that reopen is checked against the mode here,
        // so a container asked to run as anyone but root would be unable to
        // say it had started. The state directory is the runtime's own, so
        // nothing that cannot already reach the fifo gains by this.
        rustix::fs::chmodat(
            rustix::fs::CWD,
            c_path.as_c_str(),
            Mode::from_raw_mode(0o622),
            rustix::fs::AtFlags::empty(),
        )
        .context("setting the start fifo's mode")?;

        // Opened without access so it can be handed to init as a path alone;
        // init reopens it for writing once it is inside the container.
        open(
            c_path.as_c_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("opening the start fifo")
    }

    /// Opens the fifo for reading, which releases the payload.
    pub fn open_fifo(&self, id: &str) -> Result<OwnedFd> {
        use rustix::fs::{Mode, OFlags, open};
        let path = self.directory(id).join(FIFO);
        let c_path = to_c_string(&path)?;
        open(
            c_path.as_c_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("opening the start fifo")
    }

    /// Removes the fifo once the container has started.
    pub fn remove_fifo(&self, id: &str) {
        let _ = fs::remove_file(self.directory(id).join(FIFO));
    }
}

/// Where state goes when the caller does not say, in the order to try.
///
/// A privileged runtime keeps its state under `/run`; a rootless one keeps it
/// in the directory the session provides. Which of those applies cannot be
/// settled by asking for the effective user id, because a rootless engine runs
/// the runtime inside a user namespace that maps the caller to zero: the
/// answer comes back as root while the authority over the host's `/run` is
/// still the caller's own. So `/run` is attempted rather than assumed, and a
/// refusal moves on to the session's directory.
fn default_roots() -> Vec<PathBuf> {
    let session = session_root();
    if rustix::process::geteuid().is_root() {
        return vec![PathBuf::from(DEFAULT_ROOT), session];
    }
    vec![session]
}

/// The state directory belonging to the session the caller is part of.
fn session_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("kot");
    }
    PathBuf::from(format!(
        "/run/user/{}/kot",
        rustix::process::geteuid().as_raw()
    ))
}

/// Makes a state root, treating one that is already there as made.
///
/// Made outright first: the root is there on every command but the first, and
/// asking whether it is costs the same as making it.
fn make_root(path: &Path) -> std::io::Result<()> {
    match rustix::fs::mkdir(path, Mode::from_raw_mode(0o777)) {
        Ok(()) => Ok(()),
        // Already there, which is every command but the first. It still has
        // to be somewhere this process may write: a root left behind by a
        // privileged run is not one a rootless run can use, and finding that
        // out here is what lets the next location be tried instead of the
        // first container failing.
        Err(Errno::EXIST) => writable(path),
        Err(Errno::NOENT) => fs::create_dir_all(path),
        Err(e) => Err(e.into()),
    }
}

/// Reports whether a directory that already exists is one to write in.
fn writable(path: &Path) -> std::io::Result<()> {
    use rustix::fs::{Access, AtFlags, accessat};

    // Asked of the effective identity, which is the one the writes will be
    // made under.
    accessat(
        rustix::fs::CWD,
        path,
        Access::WRITE_OK | Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .map_err(Into::into)
}

/// True when a location turned the runtime away rather than failing at it.
///
/// These are the answers that mean the place is not the runtime's to write in.
/// Anything else is a real failure and is reported where it happened, because
/// trying somewhere else would only bury it.
fn is_refusal(error: &std::io::Error) -> bool {
    use crate::sys::error::{EACCES, EPERM, EROFS};

    matches!(error.raw_os_error(), Some(EACCES | EPERM | EROFS))
}

/// Rejects an identifier that cannot safely become a name.
///
/// An id becomes a directory name under the state root, a cgroup path
/// component and part of a systemd unit name, so it is held to what all
/// three accept. A separator or a relative component is a path traversal, a
/// leading dot hides the state directory, and a space or a quote turns a
/// unit name into something else.
pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("the container ID must not be empty");
    }
    if id == "." || id == ".." {
        bail!("invalid container ID {id}: it names a directory above itself");
    }
    if id.starts_with('.') {
        bail!("invalid container ID {id}: it must not start with a dot");
    }
    if let Some(bad) = id.chars().find(|c| {
        !c.is_ascii_alphanumeric() && !matches!(c, '_' | '+' | '-' | '.')
    }) {
        bail!(
            "invalid character {bad:?} in the container ID {id}: only \
             letters, digits, and the marks `_`, `+`, `-` and `.` are \
             accepted"
        );
    }
    Ok(())
}

/// The state a container is actually in, which may differ from what was
/// recorded if the payload has exited since.
#[must_use]
pub fn observe(record: &Record) -> Status {
    if record.pid <= 0 {
        return Status::Stopped;
    }
    if !is_alive(record.pid, record.start_time) {
        return Status::Stopped;
    }
    if record.awaiting_start {
        Status::Created
    } else {
        Status::Running
    }
}

/// True when the recorded process is still the one that was recorded.
#[must_use]
pub fn is_alive(pid: i32, start_time: u64) -> bool {
    let Some(observed) = process_start_time(pid) else {
        return false;
    };
    // A start time of zero means the record predates the check, so fall back
    // to existence alone instead of refusing to believe in the container.
    start_time == 0 || observed == start_time
}

/// Reads a process's start time from `/proc`.
///
/// Field twenty-two of `stat`, which is stable across kernel versions and is
/// what makes a process id safe to trust.
///
/// One open, one read and one close. The line has a command name of at most
/// sixteen bytes and fifty-one numbers of at most twenty digits, so it is
/// under eleven hundred bytes however it is filled in, and a buffer twice
/// that takes the whole of it in one read.
#[must_use]
pub fn process_start_time(pid: i32) -> Option<u64> {
    let mut path = crate::sys::PathBuf::<32>::new();
    path.push_str("/proc/").ok()?;
    path.push_i64(i64::from(pid)).ok()?;
    path.push_str("/stat").ok()?;
    let file = rustix::fs::open(
        path.as_c_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let mut buffer = [0u8; 2048];
    let read = rustix::io::read(&file, &mut buffer[..]).ok()?;
    let text = core::str::from_utf8(buffer.get(..read)?).ok()?;
    // The command name is in parentheses and may itself contain spaces, so
    // the fields after it are found from the last closing parenthesis.
    let after = text.rfind(')').map(|at| at + 1)?;
    let rest = text.get(after..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Writes the whole of `bytes` to `fd`.
fn write_all(fd: BorrowedFd<'_>, bytes: &[u8]) -> rustix::io::Result<()> {
    let mut written = 0usize;
    // Bounded by the length: every pass writes at least one byte or fails.
    while written < bytes.len() {
        let rest = bytes.get(written..).unwrap_or(&[]);
        let moved = rustix::io::write(fd, rest)?;
        if moved == 0 {
            return Err(Errno::IO);
        }
        written += moved;
    }
    Ok(())
}

/// Renders a status record.
fn render(record: &Record, status: Status) -> String {
    let mut json = Writer::new();
    write_public(&mut json, record, status, true);

    // Everything below is the runtime's own bookkeeping, not the
    // specification's, kept in one place so a reader can tell them apart.
    json.object(Some("kot"));
    json.number(
        Some("startTime"),
        i64::try_from(record.start_time).unwrap_or(0),
    );
    json.string(Some("created"), &record.created);
    json.string(Some("cgroupPath"), &record.cgroup_path);
    json.string(Some("systemdUnit"), &record.systemd_unit);
    json.string(Some("cgroupManager"), &record.cgroup_manager);
    json.string(Some("owner"), &record.owner);
    json.boolean(Some("awaitingStart"), record.awaiting_start);
    json.boolean(Some("startContainerHooks"), record.hooks.start_container);
    json.boolean(Some("poststartHooks"), record.hooks.poststart);
    json.boolean(Some("poststopHooks"), record.hooks.poststop);
    json.end_object();
    json.end_object();
    json.finish()
}

/// Reads the next value as a string, replacing `out` with it.
fn take_string(parser: &mut Parser<'_>, out: &mut String) -> Result<()> {
    parser.string()?.clone_into(out);
    Ok(())
}

/// Parses a status record.
fn parse_record(text: &str, arena: &Bump) -> Result<Record> {
    let mut parser = Parser::new(text.as_bytes(), arena);
    let mut record = Record::default();
    parser.enter_object()?;
    while let Some(key) = parser.next_key()? {
        match key {
            "ociVersion" => take_string(&mut parser, &mut record.oci_version)?,
            "id" => take_string(&mut parser, &mut record.id)?,
            "status" => {
                let value = parser.string()?;
                record.awaiting_start =
                    Status::by_name(value) == Some(Status::Created);
            }
            "pid" => record.pid = i32::try_from(parser.i64()?).unwrap_or(0),
            "bundle" => take_string(&mut parser, &mut record.bundle)?,
            "annotations" => {
                let mut pairs = Vec::new();
                parser.string_map(&mut pairs)?;
                record.annotations = pairs
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect();
            }
            "kot" => parse_private(&mut parser, &mut record)?,
            _ => parser.skip_value()?,
        }
    }
    Ok(record)
}

/// Parses the `kot` section, which holds the runtime's own bookkeeping.
fn parse_private(parser: &mut Parser<'_>, record: &mut Record) -> Result<()> {
    parser.enter_object()?;
    while let Some(key) = parser.next_key()? {
        match key {
            "startTime" => record.start_time = parser.u64()?,
            "created" => take_string(parser, &mut record.created)?,
            "cgroupPath" => take_string(parser, &mut record.cgroup_path)?,
            "systemdUnit" => take_string(parser, &mut record.systemd_unit)?,
            "rdtClass" => take_string(parser, &mut record.rdt_class)?,
            "rdtOwned" => record.rdt_owned = parser.bool()?,
            "rdtMonitor" => take_string(parser, &mut record.rdt_monitor)?,
            "cgroupManager" => {
                take_string(parser, &mut record.cgroup_manager)?;
            }
            "owner" => take_string(parser, &mut record.owner)?,
            "awaitingStart" => record.awaiting_start = parser.bool()?,
            "startContainerHooks" => {
                record.hooks.start_container = parser.bool()?;
            }
            "poststartHooks" => record.hooks.poststart = parser.bool()?,
            "poststopHooks" => record.hooks.poststop = parser.bool()?,
            _ => parser.skip_value()?,
        }
    }
    Ok(())
}

/// Converts a path into the NUL-terminated form syscalls take.
pub fn to_c_string(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("path contains a NUL byte")
}

/// Renders the state record the specification defines, for `kot state`.
#[must_use]
pub fn render_public(record: &Record, status: Status) -> String {
    let mut json = Writer::new();
    write_public(&mut json, record, status, false);
    json.end_object();
    json.finish()
}

/// Writes the fields a caller is allowed to see.
///
/// The stored record always names the annotation object so that its shape is
/// stable; the public report omits an empty one, as the specification does.
fn write_public(
    json: &mut Writer,
    record: &Record,
    status: Status,
    empty_annotations: bool,
) {
    json.object(None);
    json.string(Some("ociVersion"), &record.oci_version);
    json.string(Some("id"), &record.id);
    json.string(Some("status"), status.as_str());
    // A stopped container has no process, and the id it used to have is one
    // the host is free to hand to something else. Reporting it would let a
    // caller signal or attribute an unrelated process to this container.
    let pid = if status == Status::Stopped {
        0
    } else {
        record.pid
    };
    json.number(Some("pid"), i64::from(pid));
    json.string(Some("bundle"), &record.bundle);
    if empty_annotations || !record.annotations.is_empty() {
        json.object(Some("annotations"));
        for (key, value) in &record.annotations {
            json.string(Some(key), value);
        }
        json.end_object();
    }
}
