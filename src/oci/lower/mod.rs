//! Turning a validated [`Spec`] into a plan.
//!
//! This is where every string becomes a number, every path becomes an offset,
//! and every question about whether the configuration makes sense gets its
//! final answer. What comes out is a byte arena that the container init
//! process can apply without parsing, allocating, or deciding anything.

pub mod mounts;
pub mod seccomp;
pub mod tables;

use crate::{
    oci::{
        plan::{
            Builder, Container, Process, Section, process_flag, put_container,
            put_process,
            record::{
                DeviceOp, IdRange, NamespaceOp, PathAction, PathOp, RlimitOp,
                WriteOp,
            },
        },
        spec::{self, Spec},
    },
    seccomp::Compiler,
    sys::{
        caps::CapSets,
        clone::{
            CLONE_NEWCGROUP, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME,
            CLONE_NEWUSER,
        },
        error::{Error, Result},
    },
};

/// Settings the caller supplies that are not in `config.json`.
///
/// Each of these comes from a distinct command line option, so they stay
/// separate fields rather than becoming a flag word that call sites would have
/// to decode.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct Settings {
    /// Absolute path to the root filesystem, already resolved against the
    /// bundle directory.
    pub rootfs: String,
    /// Use `chroot` instead of `pivot_root`.
    pub no_pivot: bool,
    /// Do not give the container its own session keyring.
    pub no_new_keyring: bool,
    /// Fail rather than skip when a seccomp rule names an unknown syscall.
    pub seccomp_fail_unknown_syscall: bool,
    /// Skip `setgroups`, which the `keep_original_groups` extension asks for.
    pub keep_original_groups: bool,
    /// Join an existing container rather than building one, as `exec` does.
    pub join_only: bool,
    /// The host runs the unified cgroup hierarchy.
    ///
    /// Bundles ask for a `cgroup` mount because the specification's example
    /// says so, and on a unified host there is no such filesystem to mount.
    /// Every runtime substitutes `cgroup2`, which the container actually
    /// wants.
    pub cgroup_v2: bool,
}

/// A namespace the driver has to open before init can enter it.
#[derive(Clone, Debug)]
pub struct JoinRequest {
    /// The `CLONE_NEW*` bit.
    pub flag: u64,
    /// Path to the namespace file.
    pub path: String,
}

/// A mount whose id mapping the driver has to realise as a user namespace.
///
/// The mount record names its request by position in [`Lowered::idmaps`], and
/// the driver hands the namespaces over in that same order, so neither side
/// has to carry the mount's own index.
#[derive(Clone, Debug)]
pub struct IdmapRequest {
    /// Ranges of the uid mapping.
    pub uid_ranges: Vec<IdRange>,
    /// Ranges of the gid mapping.
    pub gid_ranges: Vec<IdRange>,
}

/// The result of lowering.
#[derive(Default)]
pub struct Lowered {
    /// The plan arena.
    pub arena: Vec<u8>,
    /// Namespaces the driver opens and passes to init, in this order.
    ///
    /// A namespace record's descriptor index refers to a position in this
    /// list.
    pub joins: Vec<JoinRequest>,
    /// Mounts needing a user namespace for their id mapping.
    pub idmaps: Vec<IdmapRequest>,
    /// True when the container runs in a user namespace the runtime creates,
    /// so the driver has to write the mapping files.
    pub creates_userns: bool,
    /// True when init has to fork once more after unsharing, because the pid
    /// namespace could not be created at clone time.
    pub forks_after_unshare: bool,
    /// True when init waits to be put in the container's cgroup before making
    /// a cgroup namespace, so the driver knows to tell it when that is done.
    pub creates_cgroupns: bool,
}

/// Scratch buffers the caller owns and reuses.
#[derive(Default)]
pub struct Scratch {
    builder: Builder,
    compiler: Compiler,
    data: String,
    program: Vec<u8>,
}

impl Scratch {
    /// Empty scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Lowers a configuration into a plan.
pub fn plan(
    scratch: &mut Scratch,
    spec: &Spec<'_>,
    settings: &Settings,
) -> Result<Lowered> {
    scratch.builder.clear();
    let linux = spec.linux.as_ref();
    let mut out = Lowered::default();

    let namespaces = namespaces(&mut out, linux)?;
    let container =
        container(&mut scratch.builder, spec, settings, &namespaces)?;
    put_container(&mut scratch.builder, &container)?;

    // The filter is emitted before the process record is written, because the
    // record carries the flags the install needs and those come out of the
    // emitter rather than out of the configuration.
    let seccomp_flags = write_seccomp(scratch, linux, settings)?;

    let mut process = process(&mut scratch.builder, spec, settings)?;
    process.seccomp_flags = seccomp_flags;
    put_process(&mut scratch.builder, &process)?;

    write_namespaces(&mut scratch.builder, &namespaces)?;
    write_args_and_env(&mut scratch.builder, spec)?;
    write_mounts(scratch, spec, settings, &mut out)?;
    write_devices(&mut scratch.builder, linux)?;
    write_paths(&mut scratch.builder, linux)?;
    write_sysctls(&mut scratch.builder, linux, &mut scratch.data)?;
    write_rlimits(&mut scratch.builder, spec)?;
    write_id_maps(&mut scratch.builder, linux, &mut out)?;
    write_additional_gids(&mut scratch.builder, spec)?;

    out.arena = scratch.builder.finish()?;
    Ok(out)
}

/// How the container's namespaces are arranged.
struct Namespaces {
    clone_flags: u64,
    unshare_flags: u64,
    /// A cgroup namespace was asked for, to be created once init is in the
    /// container's cgroup rather than at the clone.
    cgroup: bool,
    records: Vec<NamespaceOp>,
}

/// Decides which namespaces are created at clone time and which after.
///
/// Two constraints drive this. A created pid namespace only makes init pid one
/// if it exists at clone time, and a joined user namespace has to be entered
/// before anything else is created, or the new namespaces end up owned by the
/// wrong user namespace. When both apply, init unshares and forks once more.
fn namespaces(
    out: &mut Lowered,
    linux: Option<&spec::Linux<'_>>,
) -> Result<Namespaces> {
    let mut created = 0u64;
    let mut joined = Vec::new();
    if let Some(linux) = linux {
        for namespace in &linux.namespaces {
            let flag = tables::namespace(namespace.kind)
                .ok_or_else(|| Error::msg("namespace: unknown type"))?;
            match namespace.path {
                Some(path) => {
                    joined.push(JoinRequest {
                        flag,
                        path: path.to_owned(),
                    });
                }
                None => created |= flag,
            }
        }
    }

    // A cgroup namespace is taken out of the set here and made later, by
    // init, once the driver has put it in the container's cgroup. Made at the
    // clone it would be rooted at the runtime's cgroup instead, and the
    // container would see the host's tree under `/sys/fs/cgroup`.
    let cgroup = created & CLONE_NEWCGROUP != 0;
    created &= !CLONE_NEWCGROUP;

    // A time namespace is taken out too, and for a sharper reason: its
    // clocks can only be set while nothing is in it, and a process created
    // by a clone that carries the flag is already inside. `unshare` is the
    // only way in that leaves a moment to set them, and it puts the
    // caller's children in the namespace rather than the caller, so init
    // unshares it, writes the offsets, and forks.
    let time = created & CLONE_NEWTIME;
    created &= !CLONE_NEWTIME;

    let joins_user = joined.iter().any(|j| j.flag == CLONE_NEWUSER);
    let (clone_flags, unshare_flags) = if joins_user {
        (0, created)
    } else {
        (created, 0)
    };
    let unshare_flags = unshare_flags | time;

    out.creates_userns = created & CLONE_NEWUSER != 0;
    out.creates_cgroupns = cgroup;
    // Either of these leaves init outside the namespace it just made, so a
    // fork is what puts the container in it.
    out.forks_after_unshare =
        unshare_flags & (CLONE_NEWPID | CLONE_NEWTIME) != 0;

    // A joined namespace is entered in a fixed order: the user namespace
    // first, because it decides what the rest are allowed to do, and the mount
    // namespace last, because entering it changes what every later path means.
    joined.sort_by_key(|j| match j.flag {
        CLONE_NEWUSER => 0,
        CLONE_NEWNS => 2,
        _ => 1,
    });

    let mut records = Vec::with_capacity(joined.len());
    for (index, join) in joined.iter().enumerate() {
        records.push(NamespaceOp {
            clone_flag: join.flag,
            fd_index: i32::try_from(index)
                .map_err(|_| Error::msg("namespace: too many to join"))?,
        });
    }
    out.joins = joined;
    Ok(Namespaces {
        clone_flags,
        unshare_flags,
        cgroup,
        records,
    })
}

fn container(
    builder: &mut Builder,
    spec: &Spec<'_>,
    settings: &Settings,
    namespaces: &Namespaces,
) -> Result<Container> {
    let linux = spec.linux.as_ref();
    let propagation = linux
        .and_then(|l| l.rootfs_propagation)
        .map(|name| {
            tables::propagation(name)
                .ok_or_else(|| Error::msg("rootfsPropagation: unknown mode"))
        })
        .transpose()?
        .unwrap_or(0);

    let creates_userns = namespaces.clone_flags & CLONE_NEWUSER != 0
        || namespaces.unshare_flags & CLONE_NEWUSER != 0;

    // The clocks the configuration shifts, carried in the plan because the
    // only moment they can be set is inside init, between unsharing the
    // namespace and forking into it.
    let offset = |name: &str| {
        linux.and_then(|linux| {
            linux
                .time_offsets
                .iter()
                .find(|(clock, _)| *clock == name)
                .map(|(_, offset)| *offset)
        })
    };
    let boottime = offset("boottime");
    let monotonic = offset("monotonic");

    Ok(Container {
        clone_flags: namespaces.clone_flags,
        set_boottime: boottime.is_some(),
        boottime_secs: boottime.map_or(0, |o| o.secs),
        boottime_nanos: boottime.map_or(0, |o| o.nanosecs),
        set_monotonic: monotonic.is_some(),
        monotonic_secs: monotonic.map_or(0, |o| o.secs),
        monotonic_nanos: monotonic.map_or(0, |o| o.nanosecs),
        unshare_flags: namespaces.unshare_flags,
        rootfs: builder.intern(&settings.rootfs)?,
        rootfs_readonly: spec.root.as_ref().is_some_and(|r| r.readonly),
        rootfs_propagation: propagation,
        no_pivot: settings.no_pivot,
        hostname: builder.intern(spec.hostname.unwrap_or(""))?,
        domainname: builder.intern(spec.domainname.unwrap_or(""))?,
        new_keyring: !settings.no_new_keyring,
        // The kernel refuses a gid map from a process that can still call
        // `setgroups`, unless it holds `CAP_SETGID` in the parent namespace.
        // Denying it up front is how an unprivileged mapping is allowed at
        // all.
        deny_setgroups: creates_userns,
        join_only: settings.join_only,
        cgroup_namespace: namespaces.cgroup,
    })
}

fn process(
    builder: &mut Builder,
    spec: &Spec<'_>,
    settings: &Settings,
) -> Result<Process> {
    let Some(source) = spec.process.as_ref() else {
        // Nothing was asked for, so nothing is granted: the empty sets are
        // still installed rather than left to the runtime's own privilege.
        let mut out = Process::default();
        out.set(process_flag::HAS_CAPS, true);
        return Ok(out);
    };
    let mut out = Process {
        uid: source.user.uid,
        gid: source.user.gid,
        cwd: builder.intern(if source.cwd.is_empty() {
            "/"
        } else {
            source.cwd
        })?,
        ..Process::default()
    };

    out.set(process_flag::TERMINAL, source.terminal);
    out.set(process_flag::NO_NEW_PRIVS, source.no_new_privileges);
    out.set(
        process_flag::KEEP_ORIGINAL_GROUPS,
        settings.keep_original_groups,
    );

    if let Some(umask) = source.user.umask {
        out.umask = umask;
        out.set(process_flag::HAS_UMASK, true);
    }
    if let Some(size) = source.console_size {
        out.console_height = size.height;
        out.console_width = size.width;
    }
    if let Some(adjustment) = source.oom_score_adj {
        out.oom_score_adj = i32::try_from(adjustment)
            .map_err(|_| Error::msg("oomScoreAdj: out of range"))?;
        out.set(process_flag::HAS_OOM_SCORE_ADJ, true);
    }
    // Capability sets are always installed, even when the configuration names
    // none. A payload running as user zero inherits whatever the runtime
    // holds otherwise, which is the opposite of what an absent section asks
    // for: no capabilities were requested, so none are kept.
    out.set(process_flag::HAS_CAPS, true);
    if let Some(capabilities) = source.capabilities.as_ref() {
        let sets = capability_sets(capabilities)?;
        out.cap_effective = sets.effective;
        out.cap_permitted = sets.permitted;
        out.cap_inheritable = sets.inheritable;
        out.cap_bounding = sets.bounding;
        out.cap_ambient = sets.ambient;
    }
    out.apparmor = builder.intern(source.apparmor_profile.unwrap_or(""))?;
    out.selinux = builder.intern(source.selinux_label.unwrap_or(""))?;

    lower_scheduling(source, &mut out)?;
    lower_linux_process(builder, spec.linux.as_ref(), &mut out)?;
    Ok(out)
}

/// Lowers the two fields that say how the payload is scheduled.
fn lower_scheduling(
    source: &spec::Process<'_>,
    out: &mut Process,
) -> Result<()> {
    if let Some(scheduler) = source.scheduler.as_ref() {
        out.sched_policy = tables::scheduler_policy(scheduler.policy)
            .ok_or_else(|| Error::msg("scheduler: unknown policy"))?;
        for flag in &scheduler.flags {
            out.sched_flags |= tables::scheduler_flag(flag)
                .ok_or_else(|| Error::msg("scheduler: unknown flag"))?;
        }
        out.sched_nice = i32::try_from(scheduler.nice)
            .map_err(|_| Error::msg("scheduler: nice out of range"))?;
        out.sched_priority = u32::try_from(scheduler.priority)
            .map_err(|_| Error::msg("scheduler: priority out of range"))?;
        out.sched_runtime = scheduler.runtime;
        out.sched_deadline = scheduler.deadline;
        out.sched_period = scheduler.period;
        out.set(process_flag::HAS_SCHEDULER, true);
    }
    if let Some(priority) = source.io_priority.as_ref() {
        out.ioprio_class = tables::ioprio_class(priority.class)
            .ok_or_else(|| Error::msg("ioPriority: unknown class"))?;
        out.ioprio_priority = u32::try_from(priority.priority)
            .map_err(|_| Error::msg("ioPriority: out of range"))?;
        out.set(process_flag::HAS_IOPRIO, true);
    }
    Ok(())
}

/// Lowers the per-process settings that live under `linux` rather than under
/// `process`, which is where the specification put them.
fn lower_linux_process(
    builder: &mut Builder,
    linux: Option<&spec::Linux<'_>>,
    out: &mut Process,
) -> Result<()> {
    if let Some(personality) = linux.and_then(|l| l.personality.as_ref()) {
        out.personality = tables::personality(personality.domain)
            .ok_or_else(|| Error::msg("personality: unknown domain"))?;
        for flag in &personality.flags {
            out.personality |= tables::personality_flag(flag)
                .ok_or_else(|| Error::msg("personality: unknown flag"))?;
        }
        out.set(process_flag::HAS_PERSONALITY, true);
    }
    if let Some(policy) = linux.and_then(|l| l.memory_policy.as_ref()) {
        out.mempolicy_mode = tables::mempolicy_mode(policy.mode)
            .ok_or_else(|| Error::msg("memoryPolicy: unknown mode"))?;
        for flag in &policy.flags {
            out.mempolicy_flags |= tables::mempolicy_flag(flag)
                .ok_or_else(|| Error::msg("memoryPolicy: unknown flag"))?;
        }
        out.mempolicy_nodes = builder.intern(policy.nodes.unwrap_or(""))?;
        out.set(process_flag::HAS_MEMPOLICY, true);
    }
    if let Some(seccomp) = linux.and_then(|l| l.seccomp.as_ref()) {
        out.seccomp_listener =
            builder.intern(seccomp.listener_path.unwrap_or(""))?;
        out.seccomp_metadata =
            builder.intern(seccomp.listener_metadata.unwrap_or(""))?;
        out.set(process_flag::HAS_SECCOMP, true);
    }
    Ok(())
}

/// Converts the five capability name lists into bitmasks.
fn capability_sets(source: &spec::Capabilities<'_>) -> Result<CapSets> {
    let mut sets = CapSets::default();
    let lists = [
        (&source.effective, &mut sets.effective),
        (&source.permitted, &mut sets.permitted),
        (&source.inheritable, &mut sets.inheritable),
        (&source.bounding, &mut sets.bounding),
        (&source.ambient, &mut sets.ambient),
    ];
    for (names, target) in lists {
        let Some(names) = names.as_ref() else {
            continue;
        };
        for name in names {
            let cap = crate::sys::caps::by_name(name).ok_or_else(|| {
                Error::msg("capabilities: unknown capability name")
            })?;
            *target |= 1u64 << cap;
        }
    }
    Ok(sets)
}

fn write_namespaces(
    builder: &mut Builder,
    namespaces: &Namespaces,
) -> Result<()> {
    let mut open = builder.begin(Section::Namespaces)?;
    for record in &namespaces.records {
        record.encode(builder.records());
        open.advance();
    }
    builder.end(open)
}

fn write_args_and_env(builder: &mut Builder, spec: &Spec<'_>) -> Result<()> {
    let empty = Vec::new();
    let (args, env) = spec
        .process
        .as_ref()
        .map_or((&empty, &empty), |p| (&p.args, &p.env));

    // Interning appends to the string section and records to the body, which
    // are separate buffers, so the two can be interleaved.
    for (section, source) in [(Section::Args, args), (Section::Env, env)] {
        let mut open = builder.begin(section)?;
        for value in source {
            let value = builder.intern(value)?;
            builder.records().str(value);
            open.advance();
        }
        builder.end(open)?;
    }
    Ok(())
}

fn write_mounts(
    scratch: &mut Scratch,
    spec: &Spec<'_>,
    settings: &Settings,
    out: &mut Lowered,
) -> Result<()> {
    let mut open = scratch.builder.begin(Section::Mounts)?;
    for source in &spec.mounts {
        let mut op = mounts::mount(
            &mut scratch.builder,
            source,
            &mut scratch.data,
            settings.cgroup_v2,
            spec.linux
                .as_ref()
                .and_then(|l| l.mount_label)
                .unwrap_or(""),
        )?;
        // The mapping travels as a user namespace the driver builds, and the
        // record names it by position in that list.
        if !source.uid_mappings.is_empty() || !source.gid_mappings.is_empty() {
            op.idmap_fd = i32::try_from(out.idmaps.len())
                .map_err(|_| Error::msg("mount: too many id mappings"))?;
            out.idmaps.push(IdmapRequest {
                uid_ranges: source.uid_mappings.iter().map(range).collect(),
                gid_ranges: source.gid_mappings.iter().map(range).collect(),
            });
        }
        op.encode(scratch.builder.records());
        open.advance();
    }
    scratch.builder.end(open)
}

fn write_devices(
    builder: &mut Builder,
    linux: Option<&spec::Linux<'_>>,
) -> Result<()> {
    let mut open = builder.begin(Section::Devices)?;
    if let Some(linux) = linux {
        for device in &linux.devices {
            let op = DeviceOp {
                path: builder.intern(device.path)?,
                kind: device
                    .kind
                    .as_bytes()
                    .first()
                    .copied()
                    .ok_or_else(|| Error::msg("device: type is required"))?,
                major: u32::try_from(device.major)
                    .map_err(|_| Error::msg("device: major out of range"))?,
                minor: u32::try_from(device.minor)
                    .map_err(|_| Error::msg("device: minor out of range"))?,
                mode: device.file_mode.unwrap_or(0o666),
                uid: device.uid.unwrap_or(0),
                gid: device.gid.unwrap_or(0),
            };
            op.encode(builder.records());
            open.advance();
        }
    }

    // The specification requires these to exist whether or not the bundle
    // lists them, and a container missing them fails in ways that look like
    // anything but a missing device node.
    for &(path, kind, major, minor, mode) in &tables::DEFAULT_DEVICES {
        let interned = builder.intern(path)?;
        let configured = linux.is_some_and(|l| {
            l.devices.iter().any(|device| device.path == path)
        });
        if configured {
            continue;
        }
        let op = DeviceOp {
            path: interned,
            kind,
            major,
            minor,
            mode,
            uid: 0,
            gid: 0,
        };
        op.encode(builder.records());
        open.advance();
    }

    builder.end(open)
}

fn write_paths(
    builder: &mut Builder,
    linux: Option<&spec::Linux<'_>>,
) -> Result<()> {
    let mut open = builder.begin(Section::Paths)?;
    if let Some(linux) = linux {
        let lists = [
            (&linux.masked_paths, PathAction::Mask),
            (&linux.readonly_paths, PathAction::ReadOnly),
        ];
        for (paths, action) in lists {
            for path in paths {
                let op = PathOp::new(builder.intern(path)?, action);
                op.encode(builder.records());
                open.advance();
            }
        }
    }
    builder.end(open)
}

fn write_sysctls(
    builder: &mut Builder,
    linux: Option<&spec::Linux<'_>>,
    data: &mut String,
) -> Result<()> {
    let mut open = builder.begin(Section::Sysctls)?;
    if let Some(linux) = linux {
        for &(key, value) in &linux.sysctl {
            // The kernel names these with dots; the file they live in uses
            // separators. Converting here keeps init free of string work.
            data.clear();
            data.extend(key.chars().map(|c| if c == '.' { '/' } else { c }));
            let op = WriteOp {
                key: builder.intern(data)?,
                value: builder.intern(value)?,
            };
            op.encode(builder.records());
            open.advance();
        }
    }
    builder.end(open)
}

fn write_rlimits(builder: &mut Builder, spec: &Spec<'_>) -> Result<()> {
    let mut open = builder.begin(Section::Rlimits)?;
    if let Some(process) = spec.process.as_ref() {
        for limit in &process.rlimits {
            let op = RlimitOp {
                resource: tables::rlimit(limit.kind)
                    .ok_or_else(|| Error::msg("rlimits: unknown limit"))?,
                soft: limit.soft,
                hard: limit.hard,
            };
            op.encode(builder.records());
            open.advance();
        }
    }
    builder.end(open)
}

fn write_id_maps(
    builder: &mut Builder,
    linux: Option<&spec::Linux<'_>>,
    out: &mut Lowered,
) -> Result<()> {
    let empty = Vec::new();
    let (uid, gid) =
        linux.map_or((&empty, &empty), |l| (&l.uid_mappings, &l.gid_mappings));

    // A configuration that makes a user namespace and names no mapping is
    // asking for the caller's own identity inside it, which is what a
    // rootless bundle written by hand almost always means. Refusing would
    // turn the simplest such bundle away for a mapping the runtime can
    // work out; mapping nothing at all would leave every file in the image
    // owned by nobody the container knows.
    let derived;
    let uid = if out.creates_userns && uid.is_empty() {
        derived = [own_range(rustix::process::geteuid().as_raw())];
        &derived[..]
    } else {
        uid
    };
    let derived_gid;
    let gid = if out.creates_userns && gid.is_empty() {
        derived_gid = [own_range(rustix::process::getegid().as_raw())];
        &derived_gid[..]
    } else {
        gid
    };

    write_ranges(builder, Section::UidMap, uid)?;
    write_ranges(builder, Section::GidMap, gid)?;
    Ok(())
}

/// The mapping a container gets when the configuration names none: the
/// caller's own id, and nothing else.
fn own_range(id: u32) -> spec::IdMapping {
    spec::IdMapping {
        container_id: 0,
        host_id: id,
        size: 1,
    }
}

fn write_ranges(
    builder: &mut Builder,
    section: Section,
    source: &[spec::IdMapping],
) -> Result<()> {
    let mut open = builder.begin(section)?;
    for mapping in source {
        range(mapping).encode(builder.records());
        open.advance();
    }
    builder.end(open)
}

fn write_additional_gids(builder: &mut Builder, spec: &Spec<'_>) -> Result<()> {
    let mut open = builder.begin(Section::AdditionalGids)?;
    if let Some(process) = spec.process.as_ref() {
        for &gid in &process.user.additional_gids {
            builder.records().u32(gid);
            open.advance();
        }
    }
    builder.end(open)
}

/// Emits the filter and writes it into the plan, returning the install flags.
fn write_seccomp(
    scratch: &mut Scratch,
    linux: Option<&spec::Linux<'_>>,
    settings: &Settings,
) -> Result<u32> {
    let Some(config) = linux.and_then(|l| l.seccomp.as_ref()) else {
        let open = scratch.builder.begin(Section::Seccomp)?;
        scratch.builder.end(open)?;
        return Ok(0);
    };
    let flags = seccomp::filter(
        &mut scratch.compiler,
        config,
        settings.seccomp_fail_unknown_syscall,
        &mut scratch.program,
    )?;

    let mut open = scratch.builder.begin(Section::Seccomp)?;
    scratch.builder.records().bytes(&scratch.program);
    open.set_count(
        u32::try_from(scratch.program.len())
            .map_err(|_| Error::msg("seccomp: program too large"))?,
    );
    scratch.builder.end(open)?;
    Ok(flags)
}

fn range(source: &spec::IdMapping) -> IdRange {
    IdRange {
        container_id: source.container_id,
        host_id: source.host_id,
        size: source.size,
    }
}
