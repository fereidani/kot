//! Creating, configuring and removing a container's cgroup.
//!
//! Two managers, selected by the caller: one writes the cgroup filesystem
//! directly, the other asks systemd to create a transient scope. The systemd
//! path is where the latency is, and three things are done differently there
//! to get it back:
//!
//! - The call that creates the scope is sent and not waited on, so the driver
//!   can go on preparing mounts and emitting the seccomp filter while systemd
//!   works. Measured on this host, sending takes 0.02 ms and the cgroup is
//!   usable about 11 ms later.
//! - Readiness is detected by watching for the cgroup directory, without
//!   waiting for systemd's job completion signal.
//! - Teardown does not block on a `StopUnit` job. Measured, an empty transient
//!   scope is collected in about 1 ms; blocking on the job costs 150 ms.

use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

use crate::{
    cgroup::{
        dbus::{
            Connection, message,
            systemd::{self, Mode, Property},
        },
        layout::{self, Layout},
        unit::{self, UnitProperty},
        v1, v2,
        write::{self, Writes},
    },
    oci::spec::{Memory, Resources},
    sys::{
        error::{Context, Error, Result},
        path::Path,
    },
};

/// Which manager to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Kind {
    /// Write the cgroup filesystem directly.
    #[default]
    Cgroupfs,
    /// Ask systemd for a transient scope.
    Systemd,
    /// Do not manage cgroups at all.
    Disabled,
}

impl Kind {
    /// Resolves the `--cgroup-manager` value.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "cgroupfs" => Some(Self::Cgroupfs),
            "systemd" => Some(Self::Systemd),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// The slice the system's own manager puts a container in.
const SYSTEM_SLICE: &str = "system.slice";

/// The slice a user's manager puts one in, which is not the same.
const USER_SLICE: &str = "app.slice";

/// How long to wait for a systemd scope to appear or disappear.
///
/// Measured, creation takes about 11 ms and collection about 1 ms. A second is
/// three orders of magnitude of headroom and still bounds a systemd that has
/// stopped answering.
const SYSTEMD_DEADLINE: Duration = Duration::from_secs(1);

/// A container's cgroup.
pub struct Manager {
    kind: Kind,
    layout: Layout,
    /// Path relative to the hierarchy root.
    path: Path,
    /// Transient unit name, on the systemd path.
    unit: Option<String>,
    /// Slice the unit belongs to.
    slice: String,
    connection: Option<Connection>,
    /// Serial of the outstanding scope request, so its reply can be matched
    /// while waiting for the cgroup to appear.
    pending: Option<u32>,
    /// True while the limits the scope request carried are still current.
    ///
    /// The request states them, so the first `apply` has nothing systemd has
    /// not already acted on, and sending them again would put a round trip on
    /// the start path for no change. Every later change still has to be sent.
    scope_carries_limits: bool,
    /// Descriptor of the container's directory, once it exists.
    directory: Option<OwnedFd>,
    /// Properties the configuration put on the unit through annotations.
    unit_properties: Vec<UnitProperty>,
    /// One directory per controller, on the legacy hierarchy.
    ///
    /// Each legacy controller is a separate tree with its own mount point, so
    /// a container occupies one directory in each of them instead of one
    /// directory overall. Empty on the unified hierarchy, where `directory` is
    /// the whole story.
    legacy: Vec<(String, OwnedFd)>,
}

impl Manager {
    /// Prepares a manager without touching the host.
    ///
    /// `cgroups_path` is the configuration's value. On the systemd path it has
    /// the `slice:prefix:name` shape; elsewhere it is a path relative to the
    /// hierarchy root. An empty value gets a path derived from the container
    /// id, which every caller expects when it leaves the field out.
    pub fn new(
        kind: Kind,
        cgroups_path: Option<&str>,
        container_id: &str,
    ) -> Result<Self> {
        let layout = Layout::detect()?;
        let mut manager = Self {
            legacy: Vec::new(),
            kind,
            layout,
            path: Path::new(),
            unit: None,
            slice: SYSTEM_SLICE.to_owned(),
            connection: None,
            pending: None,
            scope_carries_limits: false,
            unit_properties: Vec::new(),
            directory: None,
        };

        match (kind, cgroups_path) {
            (Kind::Disabled, _) => {}
            (Kind::Systemd, Some(value)) if value.contains(':') => {
                manager.parse_systemd_path(value)?;
            }
            (Kind::Systemd, _) => {
                manager.unit = Some(format!("kot-{container_id}.scope"));
                manager.build_systemd_path()?;
            }
            (Kind::Cgroupfs, Some(value)) if !value.is_empty() => {
                manager.path.push_str(value)?;
            }
            (Kind::Cgroupfs, _) => {
                manager.path.push_str("/kot/")?;
                manager.path.push_str(container_id)?;
            }
        }
        Ok(manager)
    }

    /// Splits the `slice:prefix:name` form systemd callers use.
    fn parse_systemd_path(&mut self, value: &str) -> Result<()> {
        let mut parts = value.split(':');
        let (Some(slice), Some(prefix), Some(name)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::msg(
                "cgroupsPath: expected slice:prefix:name for systemd",
            ));
        };
        if parts.next().is_some() {
            return Err(Error::msg("cgroupsPath: too many parts"));
        }
        if !slice.is_empty() {
            #[allow(clippy::case_sensitive_file_extension_comparisons)]
            let named = slice.ends_with(".slice");
            self.slice = if named {
                slice.to_owned()
            } else {
                format!("{slice}.slice")
            };
        }
        self.unit = Some(format!("{prefix}-{name}.scope"));
        self.build_systemd_path()
    }

    /// Builds the path a transient scope's cgroup will have.
    ///
    /// systemd expands a dashed slice name into nested directories, so
    /// `a-b.slice` lives under `a.slice/a-b.slice`.
    fn build_systemd_path(&mut self) -> Result<()> {
        self.path.clear();
        self.path.push_str("/")?;
        for component in expand_slice(&self.slice) {
            self.path.join(component.as_bytes())?;
        }
        if let Some(unit) = self.unit.as_deref() {
            self.path.join(unit.as_bytes())?;
        }
        Ok(())
    }

    /// Puts the scope where a user's own systemd will make it.
    ///
    /// A user manager's units hang below its own service in the tree rather
    /// than below the system's slices, and the slice it puts an application
    /// in by default is not the one the system manager uses.
    fn place_under(&mut self, uid: u32) -> Result<()> {
        if self.slice == SYSTEM_SLICE {
            USER_SLICE.clone_into(&mut self.slice);
        }
        self.path.clear();
        self.path.push_str("/user.slice/user-")?;
        self.path.push_u64(u64::from(uid))?;
        self.path.push_str(".slice/user@")?;
        self.path.push_u64(u64::from(uid))?;
        self.path.push_str(".service")?;
        for component in expand_slice(&self.slice) {
            self.path.join(component.as_bytes())?;
        }
        if let Some(unit) = self.unit.as_deref() {
            self.path.join(unit.as_bytes())?;
        }
        Ok(())
    }

    /// Points a rebuilt manager at the cgroup a previous run recorded.
    ///
    /// Where a scope landed is not derivable from the container's name alone:
    /// it depends on which systemd made it. A later command takes the answer
    /// from the state record instead of working it out again.
    pub fn relocate(&mut self, path: &str) -> Result<()> {
        if path.is_empty() {
            return Ok(());
        }
        self.path.clear();
        self.path.push_str(path)
    }

    /// The container's cgroup path, relative to the hierarchy root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The transient unit name, when there is one.
    #[must_use]
    pub fn unit(&self) -> Option<&str> {
        self.unit.as_deref()
    }

    /// Which manager this is.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The directory descriptor, once the cgroup exists.
    #[must_use]
    pub fn directory(&self) -> Option<BorrowedFd<'_>> {
        self.directory.as_ref().map(AsFd::as_fd)
    }

    /// The directory a controller's files live in.
    ///
    /// On the unified hierarchy every file is in the one directory, so the
    /// controller a write names is ignored. On the legacy one each controller
    /// has its own tree, and this is the only way to reach the right one.
    #[must_use]
    pub fn place(&self, controller: &str) -> Option<BorrowedFd<'_>> {
        if self.legacy.is_empty() {
            return self.directory.as_ref().map(AsFd::as_fd);
        }
        self.legacy
            .iter()
            .find(|(name, _)| name == controller)
            .map(|(_, fd)| fd.as_fd())
    }

    /// Every directory the container occupies.
    fn places(&self) -> impl Iterator<Item = BorrowedFd<'_>> {
        self.directory
            .iter()
            .map(AsFd::as_fd)
            .chain(self.legacy.iter().map(|(_, fd)| fd.as_fd()))
    }

    /// True once the cgroup exists in whichever hierarchy this host uses.
    fn opened(&self) -> bool {
        self.directory.is_some() || !self.legacy.is_empty()
    }

    /// The container's cgroup as an absolute path under the hierarchy root.
    fn full_path(&self) -> Result<Path> {
        let relative = core::str::from_utf8(self.path.as_bytes())
            .map_err(|_| Error::msg("cgroup: path is not UTF-8"))?;
        layout::unified_path(relative)
    }

    /// Creates the cgroup before the container's process exists, and names
    /// the directory a clone can place that process in directly.
    ///
    /// Only the cgroupfs manager on the unified hierarchy can offer this. A
    /// process born in its cgroup never has to be moved there, and moving one
    /// is not the cheap write it looks like: the migration takes a lock whose
    /// writer side waits out a read-copy-update grace period, which is several
    /// milliseconds on a host that is otherwise idle. systemd builds its scope
    /// around a process id and so has nothing to offer before the clone, and
    /// the legacy hierarchy has one directory per controller, with no single
    /// place to be born into.
    pub fn precreate(
        &mut self,
        resources: Option<&Resources<'_>>,
    ) -> Result<Option<BorrowedFd<'_>>> {
        if self.kind != Kind::Cgroupfs || self.layout.has_legacy() {
            return Ok(None);
        }
        self.create_directly(resources)?;
        Ok(self.directory())
    }

    /// Starts creating the cgroup, without waiting for it.
    ///
    /// On the cgroupfs path this finishes the job outright, unless
    /// [`Manager::precreate`] already did. On the systemd path it sends the
    /// request and returns, leaving the wait to [`Manager::wait_ready`], so
    /// the caller can overlap the round trip with everything else it has to
    /// do.
    pub fn begin_create(
        &mut self,
        pid: i32,
        resources: Option<&Resources<'_>>,
    ) -> Result<()> {
        match self.kind {
            Kind::Disabled => Ok(()),
            Kind::Cgroupfs if self.opened() => Ok(()),
            Kind::Cgroupfs => self.create_directly(resources),
            Kind::Systemd => self.request_scope(pid, resources),
        }
    }

    fn create_directly(
        &mut self,
        resources: Option<&Resources<'_>>,
    ) -> Result<()> {
        // A hybrid host keeps its controllers in the legacy trees, so the
        // unified tree there is not where limits are written.
        if self.layout.has_legacy() {
            return self.open_legacy(true);
        }
        enable_controllers(&self.path, resources)?;
        let full = self.full_path()?;
        self.directory = Some(layout::open_or_create(&full)?);
        Ok(())
    }

    /// Sends the limits systemd owns to the unit that owns them.
    fn update_unit_properties(
        &mut self,
        resources: Option<&Resources<'_>>,
    ) -> Result<()> {
        let Some(unit) = self.unit.clone() else {
            return Ok(());
        };
        let mut properties = Vec::new();
        push_systemd_properties(self.layout, resources, &mut properties)?;
        if properties.is_empty() {
            return Ok(());
        }
        let connection = connection(
            &mut self.connection,
            "cgroup: no connection to systemd",
        )?;
        // Not made to persist: the unit lives only as long as the container,
        // so a change written to disk would outlive what it describes.
        systemd::set_unit_properties(connection, &unit, true, &properties)
            .map(|_| ())
    }

    /// Opens the container's directory in every mounted controller.
    ///
    /// Reopening, unlike creating, accepts a host that has since unmounted a
    /// controller: reporting one that used to exist would make a rebuilt
    /// manager unusable for the controllers that remain.
    fn open_legacy(&mut self, create: bool) -> Result<()> {
        let relative = self.relative()?.to_owned();
        let mounts = layout::Mounts::detect()?;
        for (controller, point) in mounts.points() {
            let path = layout::controller_path(point, &relative)?;
            let opened = if create {
                let fd = layout::open_or_create(&path)?;
                if controller == "cpuset" {
                    layout::seed_cpuset(point, &relative)?;
                }
                Some(fd)
            } else {
                layout::open_directory(&path).ok()
            };
            if let Some(fd) = opened {
                self.legacy.push((controller.to_owned(), fd));
            }
        }
        if create && self.legacy.is_empty() {
            return Err(Error::msg("cgroup: no legacy controller is mounted"));
        }
        Ok(())
    }

    /// Waits for the cgroup and reports whether there is one to write to.
    ///
    /// A disabled manager answers false, not an error: there is no cgroup by
    /// the caller's own choice, so every operation on one is a success that
    /// does nothing. Callers have to stop on false, because what follows it
    /// operates on directories a disabled manager does not have.
    fn ready(&mut self) -> Result<bool> {
        if self.kind == Kind::Disabled {
            return Ok(false);
        }
        self.wait_ready()?;
        if !self.opened() {
            return Err(Error::msg("cgroup: not created"));
        }
        Ok(true)
    }

    /// Whether there is a cgroup to read figures out of.
    ///
    /// Unlike the check above, a container whose cgroup has gone is not an
    /// error here: a caller asking what a container is using while it exits
    /// gets no figures rather than a failure, and it was going to see the
    /// container stop on its next look anyway.
    pub fn ready_for_stats(&mut self) -> Result<bool> {
        if self.kind == Kind::Disabled {
            return Ok(false);
        }
        self.wait_ready()?;
        Ok(self.opened())
    }

    /// Takes the unit properties an annotation set names.
    ///
    /// Only the systemd manager has a unit to put them on; elsewhere they
    /// describe something that does not exist, which is the configuration's
    /// mistake to make rather than this runtime's to refuse.
    ///
    /// # Errors
    ///
    /// When an annotation names a property this runtime cannot write.
    pub fn take_unit_properties(
        &mut self,
        annotations: &[(&str, &str)],
    ) -> Result<()> {
        if self.kind != Kind::Systemd {
            return Ok(());
        }
        self.unit_properties = unit::from_annotations(annotations)?;
        Ok(())
    }

    /// The configured path, relative to whichever hierarchy root applies.
    fn relative(&self) -> Result<&str> {
        core::str::from_utf8(self.path.as_bytes())
            .map_err(|_| Error::msg("cgroup: path is not UTF-8"))
    }

    fn request_scope(
        &mut self,
        pid: i32,
        resources: Option<&Resources<'_>>,
    ) -> Result<()> {
        let Some(unit) = self.unit.clone() else {
            return Err(Error::msg("cgroup: systemd manager has no unit name"));
        };
        // Which systemd answers decides where the scope will be, so the
        // connection is opened before the request is described rather than
        // when it is sent.
        let owner =
            connection(&mut self.connection, "cgroup: no connection")?.owner();
        if let Some(uid) = owner {
            self.place_under(uid)?;
        }
        let pids = [pid.unsigned_abs()];
        let mut properties = Vec::with_capacity(8);
        properties.push(Property::Str("Description", "kot container"));
        properties.push(Property::Str("Slice", &self.slice));
        // Delegation lets the runtime write the cgroup files systemd does not
        // cover, without systemd undoing them.
        properties.push(Property::Bool("Delegate", true));
        properties.push(Property::Bool("DefaultDependencies", false));
        properties.push(Property::Pids("PIDs", &pids));
        push_systemd_properties(self.layout, resources, &mut properties)?;
        // Last, so a property the configuration named itself decides.
        for property in &self.unit_properties {
            properties.push(property.as_property());
        }

        let connection =
            connection(&mut self.connection, "cgroup: no connection")?;
        let serial = systemd::start_transient_unit(
            connection,
            &unit,
            Mode::Replace,
            &properties,
        )?;
        self.pending = Some(serial);
        self.scope_carries_limits = resources.is_some();
        Ok(())
    }

    /// Reads whatever systemd has sent, and reports an error reply.
    ///
    /// The request was fired without waiting, so this is where a rejected
    /// request surfaces. Without it a bad property would show up only as a
    /// cgroup that never appears, which says nothing about why.
    fn check_reply(&mut self) -> Result<()> {
        let Some(serial) = self.pending else {
            return Ok(());
        };
        let Some(connection) = self.connection.as_mut() else {
            return Ok(());
        };
        if !connection.poll()? {
            return Ok(());
        }
        // Bounded: each iteration removes one message from the inbox.
        for _ in 0..256 {
            let outcome = connection.take_message(|header, _| {
                if header.reply_serial != Some(serial) {
                    return Ok(None);
                }
                if header.kind != message::ERROR {
                    return Ok(Some(Ok(())));
                }
                let name = header.error_name.unwrap_or("unknown");
                Ok(Some(Err(describe_rejection(name))))
            })?;
            match outcome {
                None => return Ok(()),
                Some(None) => {}
                Some(Some(reply)) => {
                    self.pending = None;
                    return reply;
                }
            }
        }
        Ok(())
    }

    /// Waits until the cgroup directory exists and opens it.
    ///
    /// Polling for the directory instead of waiting for systemd's job signal
    /// is the whole difference between about 11 ms and the 15 ms a job wait
    /// costs, and it removes the need to subscribe to signals at all.
    pub fn wait_ready(&mut self) -> Result<()> {
        if self.opened() || self.kind == Kind::Disabled {
            return Ok(());
        }
        if self.layout.has_legacy() {
            // Rebuilt from a state record: the directories already exist, so
            // this only reopens what a previous run created.
            return self.open_legacy(false);
        }
        let full = self.full_path()?;
        // Nothing is on its way unless this manager is the one that asked for
        // it. The cgroupfs path never asks, and a manager rebuilt from a
        // state record is answering for a container somebody else created:
        // either the directory is there, or the container has gone and no
        // amount of waiting will bring it back. Waiting anyway spent the
        // whole deadline on every command a stopped container was named in.
        if self.kind == Kind::Cgroupfs || self.pending.is_none() {
            self.directory = layout::open_directory(&full).ok();
            return Ok(());
        }
        let appeared = wait_until(|| {
            if let Ok(fd) = layout::open_directory(&full) {
                self.directory = Some(fd);
                return Ok(true);
            }
            self.check_reply()?;
            Ok(false)
        })?;
        if appeared {
            Ok(())
        } else {
            Err(Error::msg("cgroup: systemd scope did not appear"))
        }
    }

    /// Writes the resource limits.
    pub fn apply(&mut self, resources: Option<&Resources<'_>>) -> Result<()> {
        let Some(resources) = resources else {
            return Ok(());
        };
        let (Kind::Cgroupfs | Kind::Systemd) = self.kind else {
            // Cgroup management was turned off and the configuration still
            // states limits. There is nowhere to put them, so the container
            // runs without the restrictions it describes. Refusing would be
            // the answer if this were the configuration's doing, but it is
            // the caller's: they asked for no cgroup on the command line,
            // over a bundle they may not control. Saying so is what keeps
            // it from being silent.
            if resources.are_requested() {
                crate::log::warn(
                    "the configuration states resource limits and cgroup \
                     management is disabled, so none of them are applied",
                );
            }
            return Ok(());
        };
        if !self.ready()? {
            return Ok(());
        }

        self.check_memory_headroom(resources)?;

        let mut writes = Writes::new();
        if self.layout.has_legacy() {
            v1::lower(resources, &mut writes)?;
        } else {
            v2::lower(
                resources,
                &mut writes,
                self.current_bandwidth(resources)?,
            )?;
        }

        // The limits systemd owns are set through the unit. Writing the files
        // would be a second source of truth and a race with the
        // unit's own job. `create` puts them in the scope request; every later
        // change has to be sent as a property update, or it would be dropped
        // without anything saying so.
        if self.kind == Kind::Systemd
            && !core::mem::take(&mut self.scope_carries_limits)
        {
            self.update_unit_properties(Some(resources))?;
        }

        for entry in writes.entries() {
            if self.kind == Kind::Systemd
                && covered_by_systemd(entry.file.as_bytes())
            {
                continue;
            }
            let Some(directory) = self.place(entry.controller) else {
                // A controller the host has not mounted cannot be configured,
                // which is the same situation as one the kernel lacks.
                if entry.optional {
                    continue;
                }
                return Err(Error::msg("cgroup: controller is not mounted"));
            };
            write::apply(directory, core::slice::from_ref(entry))?;
        }
        Ok(())
    }

    /// Moves a process into the cgroup.
    pub fn add_process(&mut self, pid: i32) -> Result<()> {
        if !self.ready()? {
            return Ok(());
        }
        let mut value = write::ValueBuf::new();
        value.push_i64(i64::from(pid))?;
        // One write on the unified hierarchy, one per controller on the
        // legacy one, because a process joins each tree separately.
        for directory in self.places() {
            write::write_one(
                directory,
                c"cgroup.procs",
                value.as_bytes(),
                false,
            )?;
        }
        Ok(())
    }

    /// Opens the directory below the container's cgroup that `exec --cgroup`
    /// names, creating it when it is not there yet.
    ///
    /// Answers `None` when there is no single directory a process could be
    /// born into: a disabled manager, or the legacy hierarchy, where a process
    /// joins one tree per controller and has to be moved after the fact.
    pub fn sub_directory(&mut self, sub: &str) -> Result<Option<OwnedFd>> {
        if !self.ready()? || !self.legacy.is_empty() {
            return Ok(None);
        }
        let Some(directory) = self.directory.as_ref() else {
            return Ok(None);
        };
        open_sub(directory.as_fd(), sub).map(Some)
    }

    /// Puts a process where the container's own process is.
    ///
    /// The unified hierarchy takes no process into a cgroup that has
    /// children, so a container that makes cgroups of its own, such as one
    /// running systemd, cannot be joined at the top. Its payload has moved
    /// into a subtree, and a process joining the container belongs under
    /// the same limits, which is where the payload is now.
    ///
    /// # Errors
    ///
    /// When the payload's cgroup cannot be read or the process cannot be
    /// written into it.
    pub fn add_process_beside(&mut self, pid: i32, payload: i32) -> Result<()> {
        match self.subtree_of(payload)? {
            Some(sub) => self.add_process_in(pid, &sub),
            None => self.add_process(pid),
        }
    }

    /// Where `pid` sits below the container's own cgroup, if it is below it.
    ///
    /// Read from the process itself rather than worked out from the plan,
    /// because whatever moved it there is the container's business and the
    /// runtime is not told about it.
    fn subtree_of(&self, pid: i32) -> Result<Option<String>> {
        if self.layout.has_legacy() {
            // Only the unified hierarchy refuses a process in a cgroup with
            // children, and a legacy tree has a path per controller rather
            // than the one this reads.
            return Ok(None);
        }
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|_| {
                Error::msg("cgroup: cannot read the payload cgroup")
            })?;
        let Some(path) = text
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .map(|path| path.trim_start_matches('/'))
        else {
            return Ok(None);
        };
        let own = self.relative()?.trim_start_matches('/');
        let Some(rest) = path.strip_prefix(own) else {
            return Ok(None);
        };
        let rest = rest.trim_start_matches('/');
        Ok((!rest.is_empty()).then(|| rest.to_owned()))
    }

    /// Places a process in a directory below the container's cgroup.
    ///
    /// `exec --cgroup` asks for exactly this: a process that runs inside the
    /// container but under its own limits. An empty name means the container's
    /// own cgroup, which is where a plain `exec` belongs.
    pub fn add_process_in(&mut self, pid: i32, sub: &str) -> Result<()> {
        if sub.is_empty() {
            return self.add_process(pid);
        }
        if !self.ready()? {
            return Ok(());
        }
        let mut value = write::ValueBuf::new();
        value.push_i64(i64::from(pid))?;
        let mut made = 0usize;
        // One subdirectory per tree, for the same reason a process joins
        // every tree: each controller keeps its own hierarchy.
        for directory in self.places() {
            let sub_fd = open_sub(directory, sub)?;
            write::write_one(
                sub_fd.as_fd(),
                c"cgroup.procs",
                value.as_bytes(),
                false,
            )?;
            made += 1;
        }
        debug_assert!(made > 0, "an opened cgroup has at least one directory");
        Ok(())
    }

    /// Removes the cgroup.
    ///
    /// On the systemd path this asks systemd to stop the unit and returns
    /// without waiting for the job, then confirms by watching the directory
    /// disappear. That keeps the postcondition a caller may rely on while
    /// paying the one millisecond systemd actually needs instead of the
    /// hundred and fifty the job accounting costs.
    pub fn destroy(&mut self) -> Result<()> {
        self.directory = None;
        self.legacy.clear();
        match self.kind {
            Kind::Disabled => Ok(()),
            Kind::Cgroupfs => self.remove_directory(),
            Kind::Systemd => self.stop_scope(),
        }
    }

    fn remove_directory(&mut self) -> Result<()> {
        // One directory on the unified hierarchy, one per controller on the
        // legacy one. A tree that is already gone needs nothing done to it.
        if self.layout.has_legacy() {
            let relative = self.relative()?;
            let mounts = layout::Mounts::detect()?;
            for (_, point) in mounts.points() {
                let path = layout::controller_path(point, relative)?;
                remove_one(&path)?;
            }
            return Ok(());
        }
        remove_one(&self.full_path()?)
    }

    fn stop_scope(&mut self) -> Result<()> {
        let Some(unit) = self.unit.clone() else {
            return Ok(());
        };
        let connection =
            connection(&mut self.connection, "cgroup: no connection")?;
        // Fire and do not wait for the job. A scope with no processes left is
        // collected by definition, and the confirmation below is cheaper than
        // the signal would be.
        let _ = systemd::stop_unit(connection, &unit, Mode::Replace);
        let _ = systemd::reset_failed_unit(connection, &unit);

        let full = self.full_path()?;
        if wait_until(|| Ok(layout::open_directory(&full).is_err()))? {
            Ok(())
        } else {
            Err(Error::msg("cgroup: systemd scope did not disappear"))
        }
    }

    /// Stops or resumes every process in the cgroup.
    pub fn freeze(&mut self, frozen: bool) -> Result<()> {
        if self.kind == Kind::Disabled {
            return Ok(());
        }
        self.wait_ready()?;
        if !self.layout.has_legacy() {
            let Some(directory) = self.place("") else {
                return Err(Error::msg("cgroup: not created"));
            };
            let value: &[u8] = if frozen { b"1" } else { b"0" };
            return write::write_one(directory, c"cgroup.freeze", value, false);
        }
        let Some(directory) = self.place("freezer") else {
            return Err(Error::msg("cgroup: the freezer is not mounted"));
        };

        // The legacy freezer is not synchronous: writing the state starts a
        // transition that can land in `FREEZING` and stay there while a
        // process finishes an uninterruptible sleep.
        let value: &[u8] = if frozen {
            v1::freezer::FROZEN
        } else {
            v1::freezer::THAWED
        };
        write::write_one(directory, c"freezer.state", value, false)?;
        if !frozen {
            return Ok(());
        }
        let settled = v1::settle_freezer(directory)?;
        if settled {
            Ok(())
        } else {
            Err(Error::msg("cgroup: freezer did not reach the frozen state"))
        }
    }

    /// True when the cgroup is stopped.
    ///
    /// Read afresh each time, because a container outlives the process
    /// that paused it: the command that reports a container's state is a
    /// different run of the runtime from the one that froze it.
    pub fn frozen(&mut self) -> Result<bool> {
        if self.kind == Kind::Disabled {
            return Ok(false);
        }
        // A later run of the runtime has not opened the directory yet when it
        // reports on a container an earlier run froze.
        self.wait_ready()?;
        let legacy = self.layout.has_legacy();
        let (file, wanted): (&core::ffi::CStr, &[u8]) = if legacy {
            (c"freezer.state", v1::freezer::FROZEN)
        } else {
            (c"cgroup.freeze", b"1")
        };
        let Some(directory) = self.place(if legacy { "freezer" } else { "" })
        else {
            return Ok(false);
        };
        let mut buffer = [0u8; 32];
        let read = write::read_one(directory, file, &mut buffer)?;
        let Some(value) = buffer.get(..read) else {
            return Ok(false);
        };
        Ok(value.trim_ascii().starts_with(wanted))
    }

    /// Reads the CPU bandwidth in force, for an update naming half of it.
    ///
    /// `cpu.max` holds quota and period together, so writing it needs both.
    /// A configuration that names one of them is changing that one, and the
    /// other has to be carried over rather than reset to a default. Nothing
    /// is read when the configuration names both, or neither.
    fn current_bandwidth(
        &self,
        resources: &Resources<'_>,
    ) -> Result<v2::Bandwidth> {
        let mut current = v2::Bandwidth::default();
        let Some(cpu) = resources.cpu.as_ref() else {
            return Ok(current);
        };
        if cpu.quota.is_some() == cpu.period.is_some() {
            return Ok(current);
        }
        let Some(directory) = self.place("") else {
            return Ok(current);
        };

        let mut buffer = [0u8; 64];
        let read = match write::read_one(directory, c"cpu.max", &mut buffer) {
            Ok(read) => read,
            // Nothing in force yet, so the defaults are the right answer.
            Err(e) if e.is_not_found() => return Ok(current),
            Err(e) => return Err(e),
        };
        let text = core::str::from_utf8(buffer.get(..read).unwrap_or(&[]))
            .map_err(|_| Error::msg("cgroup: cpu.max is not UTF-8"))?;
        let mut fields = text.split_whitespace();
        // The kernel writes the word for no limit in the quota position, and
        // an unparsable field leaves the value absent, which is the same
        // thing as far as the write that follows is concerned.
        current.quota = fields.next().and_then(|field| field.parse().ok());
        current.period = fields.next().and_then(|field| field.parse().ok());
        Ok(current)
    }

    /// Refuses a new memory limit the container is already over.
    ///
    /// Writing a limit below current usage does not fail. The kernel takes
    /// it and then reclaims to make it true, or kills the container when it
    /// cannot. A configuration setting `checkBeforeUpdate` is saying it
    /// would rather the update be refused than have that happen, so the
    /// usage is read first and nothing is written.
    fn check_memory_headroom(&self, resources: &Resources<'_>) -> Result<()> {
        let Some(memory) = resources.memory.as_ref() else {
            return Ok(());
        };
        // Checked again by the decision itself; here it saves two reads on
        // every update that did not ask for the check.
        if memory.check_before_update != Some(true) {
            return Ok(());
        }
        let legacy = self.layout.has_legacy();
        let Some(directory) = self.place(if legacy { "memory" } else { "" })
        else {
            return Ok(());
        };

        let (used_file, swap_used_file) = if legacy {
            (c"memory.usage_in_bytes", c"memory.memsw.usage_in_bytes")
        } else {
            (c"memory.current", c"memory.swap.current")
        };
        let used = read_amount(directory, used_file)?;
        let swap_used = read_amount(directory, swap_used_file)?;
        memory_headroom(memory, used, swap_used, legacy)
    }

    /// Reads the process ids in the cgroup, and in every cgroup below it,
    /// into `out`.
    ///
    /// A process in a sub-cgroup is still in the container. `exec --cgroup`
    /// puts one there by request, and a container managing its own tree puts
    /// its own there; reading only the top level would leave them running
    /// after a signal meant for every process, and invisible to a caller
    /// asking what is in the container.
    pub fn processes(&mut self, out: &mut Vec<i32>) -> Result<()> {
        out.clear();
        if self.kind == Kind::Disabled {
            return Ok(());
        }
        self.wait_ready()?;
        let Some(directory) = self.places().next() else {
            return Ok(());
        };
        let mut text = Vec::new();
        collect_processes(directory, &mut text, out, 0)
    }
}

/// How deep a tree of sub-cgroups is walked.
///
/// Nesting is a container's own doing and has no reason to be deep. The
/// bound is what keeps the walk below from recursing without end on a tree
/// somebody is building while it is read, and it bounds the stack.
const MAX_CGROUP_DEPTH: u32 = 16;

/// Appends the processes in one cgroup and everything below it.
///
/// `text` is the caller's buffer for the file contents, reused down the
/// walk so that a deep tree does not allocate once per level.
fn collect_processes(
    directory: BorrowedFd<'_>,
    text: &mut Vec<u8>,
    out: &mut Vec<i32>,
    depth: u32,
) -> Result<()> {
    use rustix::fs::{FileType, Mode, OFlags};

    text.clear();
    write::read_all(directory, c"cgroup.procs", text)?;
    let listed = core::str::from_utf8(text)
        .map_err(|_| Error::msg("cgroup: procs is not UTF-8"))?;
    for line in listed.split_whitespace() {
        if let Ok(pid) = line.parse() {
            out.push(pid);
        }
    }
    if depth >= MAX_CGROUP_DEPTH {
        // Stopping quietly here would tell a caller signalling every
        // process that it had reached them all when it had not.
        crate::log::warn(
            "cgroup: the tree is nested deeper than this runtime walks, so \
             some processes were not counted",
        );
        return Ok(());
    }

    // The directory is reopened for reading because the descriptor the
    // manager holds was opened with `O_PATH`, which cannot be listed.
    let listing = rustix::fs::openat(
        directory,
        c".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("cgroup: open the directory for listing")?;
    let entries = rustix::fs::Dir::read_from(&listing)
        .context("cgroup: read the directory")?;
    for entry in entries {
        let entry = entry.context("cgroup: read a directory entry")?;
        if entry.file_type() != FileType::Directory {
            continue;
        }
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let child = rustix::fs::openat(
            &listing,
            name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("cgroup: open a sub-cgroup")?;
        // Safe to reuse: this level's contents were parsed above, and the
        // call clears the buffer before filling it again.
        collect_processes(child.as_fd(), text, out, depth + 1)?;
    }
    Ok(())
}

/// Turns a D-Bus error name into something worth reading.
///
/// systemd's rejection names are precise but opaque, so the ones the runtime
/// can provoke get a sentence of their own.
fn describe_rejection(name: &str) -> Error {
    if name.contains("UnitExists") {
        Error::msg("cgroup: systemd already has a unit with this name")
    } else if name.contains("InvalidArgs") || name.contains("PropertyReadOnly")
    {
        Error::msg("cgroup: systemd rejected a unit property")
    } else if name.contains("AccessDenied") {
        Error::msg("cgroup: systemd refused the request")
    } else {
        Error::msg("cgroup: systemd rejected the scope request")
    }
}

/// Expands `a-b-c.slice` into the nested directories systemd creates for it.
fn expand_slice(slice: &str) -> Vec<String> {
    let Some(stem) = slice.strip_suffix(".slice") else {
        return vec![slice.to_owned()];
    };
    if stem == "-" || stem.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut prefix = String::new();
    for part in stem.split('-') {
        if !prefix.is_empty() {
            prefix.push('-');
        }
        prefix.push_str(part);
        out.push(format!("{prefix}.slice"));
    }
    out
}

/// Opens the systemd connection on first use.
///
/// This takes the slot, not the whole manager, so that the borrow covers one
/// field, leaving the caller free to keep naming the rest of it while it
/// builds the message.
fn connection<'a>(
    slot: &'a mut Option<Connection>,
    missing: &'static str,
) -> Result<&'a mut Connection> {
    if slot.is_none() {
        *slot = Some(Connection::open(None)?);
    }
    slot.as_mut().ok_or_else(|| Error::msg(missing))
}

/// Opens a directory below a cgroup, creating it when it is not there.
fn open_sub(parent: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    crate::cgroup::layout::ensure_below(name.as_bytes())?;
    let mut path = crate::sys::path::PathBuf::<256>::new();
    for component in crate::sys::path::components(name.as_bytes()) {
        path.join(component)?;
    }
    match mkdirat(parent, path.as_c_str(), Mode::from_raw_mode(0o755)) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == crate::sys::error::EEXIST => {}
        Err(e) => {
            return Err(Error::from(e).describe("cgroup: create sub-cgroup"));
        }
    }
    openat(
        parent,
        path.as_c_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::from(e).describe("cgroup: open sub-cgroup"))
}

/// Removes one cgroup directory, treating an absent one as removed.
fn remove_one(path: &Path) -> Result<()> {
    match rustix::fs::rmdir(path.as_c_str()) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == crate::sys::error::ENOENT => Ok(()),
        // A container that made cgroups of its own leaves them as children
        // of this one, and the kernel refuses to remove a cgroup that has
        // any. They are inside the container's own cgroup, so removing
        // them takes nothing that is not the container's.
        Err(e) if e.raw_os_error() == crate::sys::error::EBUSY => {
            remove_children(path);
            match rustix::fs::rmdir(path.as_c_str()) {
                Ok(()) => Ok(()),
                Err(e) if e.raw_os_error() == crate::sys::error::ENOENT => {
                    Ok(())
                }
                Err(e) => {
                    Err(Error::from(e).describe("cgroup: remove directory"))
                }
            }
        }
        Err(e) => Err(Error::from(e).describe("cgroup: remove directory")),
    }
}

/// Removes every cgroup below `path`, deepest first.
///
/// Nothing is reported: a child that cannot be removed leaves the parent
/// there too, which is what the caller sees. The depth bound guards against
/// a hierarchy that keeps growing while it is walked.
fn remove_children(path: &Path) {
    /// How deep the walk goes before it gives up.
    const MAX_DEPTH: usize = 16;

    let mut level: Vec<std::path::PathBuf> =
        vec![std::path::PathBuf::from(path.to_string())];
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    for _ in 0..MAX_DEPTH {
        let mut next = Vec::new();
        for directory in &level {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    next.push(entry.path());
                }
            }
        }
        if next.is_empty() {
            break;
        }
        found.extend_from_slice(&next);
        level = next;
    }
    // Deepest first, which is the only order the kernel accepts.
    for directory in found.iter().rev() {
        let _ = std::fs::remove_dir(directory);
    }
}

/// True for a cgroup file the transient unit's properties already set.
fn covered_by_systemd(file: &[u8]) -> bool {
    matches!(
        file,
        b"memory.max"
            | b"memory.low"
            | b"memory.swap.max"
            | b"cpu.weight"
            | b"cpu.max"
            | b"pids.max"
            | b"io.weight"
            | b"memory.limit_in_bytes"
            | b"memory.soft_limit_in_bytes"
            | b"cpu.shares"
            | b"blkio.weight"
    )
}

/// Adds the limits systemd understands to a transient unit's properties.
///
/// Every file `covered_by_systemd` skips has to appear here. A file skipped
/// there with no property sent for it is a limit dropped twice over: once by
/// the write that does not happen, and once by the property that never goes.
fn push_systemd_properties<'a>(
    layout: Layout,
    resources: Option<&'a Resources<'a>>,
    out: &mut Vec<Property<'a>>,
) -> Result<()> {
    let Some(resources) = resources else {
        return Ok(());
    };
    if let Some(memory) = resources.memory.as_ref() {
        push_limit(out, "MemoryMax", memory.limit);
        push_limit(out, "MemoryLow", memory.reservation);
        // The legacy hierarchy takes the combined total in a file this
        // runtime writes itself, so only the unified one needs the property,
        // and it counts swap alone.
        if let (false, Some(total)) = (layout.has_legacy(), memory.swap) {
            let swap = v2::swap_limit(total, memory.limit)?;
            push_limit(out, "MemorySwapMax", Some(swap));
        }
    }
    if let Some(cpu) = resources.cpu.as_ref() {
        if let Some(shares) = cpu.shares {
            out.push(Property::U64("CPUWeight", v2::shares_to_weight(shares)));
        }
        if let Some(quota) = cpu.quota.filter(|q| *q > 0) {
            let period = cpu.period.unwrap_or(100_000).max(1);
            // systemd states the quota as microseconds of CPU time per second,
            // not per period.
            let per_second =
                quota.unsigned_abs().saturating_mul(1_000_000) / period;
            out.push(Property::U64("CPUQuotaPerSecUSec", per_second));
        }
    }
    if let Some(weight) = resources.block_io.as_ref().and_then(|io| io.weight) {
        // The two hierarchies scale the weight differently and systemd names
        // each one separately, so the property follows the tree the limits
        // are going into.
        out.push(if layout.has_legacy() {
            Property::U64("BlockIOWeight", u64::from(weight))
        } else {
            Property::U64("IOWeight", v2::io_weight(weight))
        });
    }
    push_limit(out, "TasksMax", resources.pids_limit);
    Ok(())
}

/// Adds a limit the configuration states, if it states one.
///
/// A negative value is how the specification spells no limit, and systemd
/// spells the same thing as the largest number there is. Leaving it out
/// instead would say nothing, which on an update means the limit already in
/// force stays: a caller lifting one would be told it worked and find it had
/// not moved.
fn push_limit(
    out: &mut Vec<Property<'_>>,
    name: &'static str,
    value: Option<i64>,
) {
    if let Some(value) = value {
        let stated = if value < 0 {
            u64::MAX
        } else {
            value.unsigned_abs()
        };
        out.push(Property::U64(name, stated));
    }
}

/// Enables the controllers a container needs in its parent's subtree.
fn enable_controllers(
    path: &Path,
    resources: Option<&Resources<'_>>,
) -> Result<()> {
    let wanted = v2::subtree_control(resources);
    if wanted.is_empty() {
        return Ok(());
    }
    // Every ancestor between the root and the container has to delegate the
    // controllers, or the container's own directory will not have the files.
    let components: Vec<&[u8]> =
        crate::sys::path::components(path.as_bytes()).collect();
    let Some((_, ancestors)) = components.split_last() else {
        return Ok(());
    };
    let mut chain = Path::new();
    chain.push_str(layout::ROOT)?;
    for component in ancestors {
        chain.join(component)?;
        let fd = layout::open_or_create(&chain)?;
        // A controller the parent does not have cannot be delegated, and a
        // host that deliberately left one off should not be overridden.
        let _ = write::write_one(
            fd.as_fd(),
            c"cgroup.subtree_control",
            wanted.as_bytes(),
            false,
        );
    }
    Ok(())
}

/// How long to wait before the check after `turn`.
///
/// The first few turns do not wait at all: a scope usually appears within a
/// handful of scheduling slots, and a sleep there would cost more than the
/// thing being waited for. After that the pause doubles up to a few
/// milliseconds, which for an eleven millisecond round trip is a handful of
/// wakeups rather than the hundreds of thousands of yields it replaces.
/// Those yields were time taken from the container being started, on exactly
/// the busy or single-processor host where it is scarcest.
#[must_use]
pub fn backoff(turn: u32) -> Duration {
    /// Turns that yield rather than sleep.
    const SPINS: u32 = 8;
    /// The first pause after those turns.
    const FIRST: Duration = Duration::from_micros(50);
    /// The longest a single pause may be.
    const LONGEST: Duration = Duration::from_millis(2);

    if turn < SPINS {
        return Duration::ZERO;
    }
    let doublings = (turn - SPINS).min(16);
    let pause = FIRST.saturating_mul(1u32 << doublings);
    if pause > LONGEST { LONGEST } else { pause }
}

/// Waits until `ready` holds, and reports whether it did.
///
/// Bounded twice over: by the deadline, and by an iteration count that keeps a
/// pathological scheduler from spinning here forever.
fn wait_until(mut ready: impl FnMut() -> Result<bool>) -> Result<bool> {
    let start = Instant::now();
    for turn in 0..100_000u32 {
        if ready()? {
            return Ok(true);
        }
        if start.elapsed() > SYSTEMD_DEADLINE {
            break;
        }
        let pause = backoff(turn);
        if pause.is_zero() {
            std::thread::yield_now();
        } else {
            std::thread::sleep(pause);
        }
    }
    Ok(false)
}

/// Reads a byte count from a cgroup file, treating an absent file and the
/// kernel's "no limit" word as zero.
///
/// A controller the host did not mount accounts nothing, and a figure that
/// cannot be read is not evidence that the container is over a limit.
fn read_amount(
    directory: BorrowedFd<'_>,
    file: &core::ffi::CStr,
) -> Result<u64> {
    let mut buffer = [0u8; 32];
    let read = match write::read_one(directory, file, &mut buffer) {
        Ok(read) => read,
        Err(e) if e.is_not_found() => return Ok(0),
        Err(e) => return Err(e),
    };
    let text = core::str::from_utf8(buffer.get(..read).unwrap_or(&[]))
        .map_err(|_| Error::msg("cgroup: usage is not UTF-8"))?;
    Ok(text.trim().parse().unwrap_or(0))
}

/// Decides whether a memory update may be written, given what is in use.
///
/// The usage figures are read from the container's cgroup by the caller, so
/// the decision itself is arithmetic and can be checked without one.
///
/// The configuration states `swap` as the total of memory and swap together.
/// On the unified hierarchy that total is two counters; the legacy controller
/// keeps the combined figure in one, so only the unified case adds them.
pub fn memory_headroom(
    memory: &Memory,
    used: u64,
    swap_used: u64,
    legacy: bool,
) -> Result<()> {
    if memory.check_before_update != Some(true) {
        return Ok(());
    }
    if let Some(limit) = memory.limit.filter(|limit| *limit >= 0) {
        ensure_above(
            limit,
            used,
            "cgroup: the new memory limit is below the memory in use",
        )?;
    }
    if let Some(swap) = memory.swap.filter(|swap| *swap >= 0) {
        let total = if legacy { swap_used } else { used + swap_used };
        ensure_above(
            swap,
            total,
            "cgroup: the new swap limit is below the memory in use",
        )?;
    }
    Ok(())
}

/// Refuses a limit that is already below what is in use.
fn ensure_above(limit: i64, used: u64, message: &'static str) -> Result<()> {
    let limit = u64::try_from(limit).unwrap_or(0);
    if limit >= used {
        return Ok(());
    }
    Err(Error::msg(message))
}
