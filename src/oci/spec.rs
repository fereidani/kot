//! The OCI runtime configuration, as types that borrow the file they were
//! read from.
//!
//! These mirror runtime-spec 1.3.0. Nothing here is interpreted: a `Spec` is
//! what the file said, and turning that into what the runtime will do is the
//! job of validation and lowering. Keeping the two apart is why a bundle can
//! be refused before any of its configuration has been applied.

/// A parsed `config.json`.
#[derive(Default, Debug)]
pub struct Spec<'a> {
    /// Version of the runtime specification the bundle claims to follow.
    pub version: &'a str,
    /// The container process.
    ///
    /// Absent is legal for `create`; `start` then fails, as the specification
    /// asks.
    pub process: Option<Process<'a>>,
    /// The container's root filesystem.
    pub root: Option<Root<'a>>,
    /// Hostname inside the UTS namespace.
    pub hostname: Option<&'a str>,
    /// NIS domain name inside the UTS namespace.
    pub domainname: Option<&'a str>,
    /// Filesystems to mount, in order.
    pub mounts: Vec<Mount<'a>>,
    /// Programs to run at defined points in the lifecycle.
    pub hooks: Option<Hooks<'a>>,
    /// Opaque key and value pairs, passed through to state and to hooks.
    pub annotations: Vec<(&'a str, &'a str)>,
    /// Linux-specific configuration.
    pub linux: Option<Linux<'a>>,
    /// Platform sections this runtime does not implement, recorded so that
    /// validation can reject the bundle rather than ignore it.
    pub foreign_platforms: Vec<&'a str>,
}

/// The program the container runs.
#[derive(Default, Debug)]
pub struct Process<'a> {
    /// Attach a pseudo-terminal.
    pub terminal: bool,
    /// Initial size of that terminal.
    pub console_size: Option<ConsoleSize>,
    /// Identity the program runs as.
    pub user: User,
    /// Program and arguments.
    pub args: Vec<&'a str>,
    /// Windows-style command line, rejected on Linux.
    pub command_line: Option<&'a str>,
    /// Environment, as `NAME=value` entries.
    pub env: Vec<&'a str>,
    /// Working directory inside the container.
    pub cwd: &'a str,
    /// Capability sets.
    pub capabilities: Option<Capabilities<'a>>,
    /// Resource limits applied before `execve`.
    pub rlimits: Vec<Rlimit<'a>>,
    /// Refuse any later gain of privilege.
    pub no_new_privileges: bool,
    /// `AppArmor` profile to transition to.
    pub apparmor_profile: Option<&'a str>,
    /// Adjustment to the out-of-memory score.
    pub oom_score_adj: Option<i64>,
    /// Scheduling policy.
    pub scheduler: Option<Scheduler<'a>>,
    /// `SELinux` label to transition to.
    pub selinux_label: Option<&'a str>,
    /// I/O scheduling class and priority.
    pub io_priority: Option<IoPriority<'a>>,
    /// CPU affinity around `execve`.
    pub exec_cpu_affinity: Option<CpuAffinity<'a>>,
}

/// Terminal dimensions.
#[derive(Default, Clone, Copy, Debug)]
pub struct ConsoleSize {
    /// Rows.
    pub height: u32,
    /// Columns.
    pub width: u32,
}

/// The identity a container process runs as.
#[derive(Default, Clone, Debug)]
pub struct User {
    /// User id inside the container.
    pub uid: u32,
    /// Primary group id inside the container.
    pub gid: u32,
    /// File creation mask.
    pub umask: Option<u32>,
    /// Supplementary groups.
    pub additional_gids: Vec<u32>,
}

/// The five capability sets.
#[derive(Default, Debug)]
pub struct Capabilities<'a> {
    /// Upper bound on what may ever be gained.
    pub bounding: Option<Vec<&'a str>>,
    /// Capabilities in force.
    pub effective: Option<Vec<&'a str>>,
    /// Capabilities preserved across `execve`.
    pub inheritable: Option<Vec<&'a str>>,
    /// Capabilities that may be made effective.
    pub permitted: Option<Vec<&'a str>>,
    /// Capabilities that survive `execve` for an unprivileged program.
    pub ambient: Option<Vec<&'a str>>,
}

impl<'a> Capabilities<'a> {
    /// Grants one capability named on a command line.
    ///
    /// The capability goes into the bounding, permitted and effective sets,
    /// which is what lets the program use it. It reaches the inheritable and
    /// ambient sets only where the configuration already asks for
    /// inheritance. A capability survives `execve` for an unprivileged
    /// program through the ambient set, and the kernel admits one there only
    /// when it is already in both the permitted and the inheritable set, so
    /// the two go together or not at all. Adding to the inheritable set
    /// alone would grant nothing on its own while still changing what
    /// happens when the program later executes a file carrying capabilities,
    /// which is more privilege than was asked for and in the one direction
    /// that outlives the process.
    pub fn grant(&mut self, name: &'a str) {
        let inherits =
            self.inheritable.as_ref().is_some_and(|set| !set.is_empty());
        for set in
            [&mut self.bounding, &mut self.permitted, &mut self.effective]
        {
            set.get_or_insert_with(Vec::new).push(name);
        }
        if inherits {
            for set in [&mut self.inheritable, &mut self.ambient] {
                set.get_or_insert_with(Vec::new).push(name);
            }
        }
    }
}

/// One resource limit.
#[derive(Default, Clone, Copy, Debug)]
pub struct Rlimit<'a> {
    /// Limit name, such as `RLIMIT_NOFILE`.
    pub kind: &'a str,
    /// Hard limit.
    pub hard: u64,
    /// Soft limit.
    pub soft: u64,
}

/// A scheduling policy request.
#[derive(Default, Debug)]
pub struct Scheduler<'a> {
    /// Policy name, such as `SCHED_OTHER`.
    pub policy: &'a str,
    /// Nice value for the time-sharing policies.
    pub nice: i64,
    /// Static priority for the real-time policies.
    pub priority: i64,
    /// Policy flags.
    pub flags: Vec<&'a str>,
    /// Deadline policy: runtime budget in nanoseconds.
    pub runtime: u64,
    /// Deadline policy: relative deadline in nanoseconds.
    pub deadline: u64,
    /// Deadline policy: period in nanoseconds.
    pub period: u64,
}

/// An I/O priority request.
#[derive(Default, Clone, Copy, Debug)]
pub struct IoPriority<'a> {
    /// Class name, such as `IOPRIO_CLASS_BE`.
    pub class: &'a str,
    /// Priority within the class.
    pub priority: i64,
}

/// CPU affinity around `execve`.
#[derive(Default, Clone, Copy, Debug)]
pub struct CpuAffinity<'a> {
    /// Affinity while the runtime is still setting up.
    pub initial: Option<&'a str>,
    /// Affinity handed to the payload.
    pub final_set: Option<&'a str>,
}

/// The container's root filesystem.
#[derive(Default, Debug)]
pub struct Root<'a> {
    /// Path to the root, relative to the bundle unless absolute.
    pub path: &'a str,
    /// Mount the root read only.
    pub readonly: bool,
}

/// One filesystem to mount into the container.
#[derive(Default, Debug)]
pub struct Mount<'a> {
    /// Where it appears inside the container.
    pub destination: &'a str,
    /// Filesystem type, or `bind` for a bind mount.
    pub kind: Option<&'a str>,
    /// Source device, directory or file.
    pub source: Option<&'a str>,
    /// Mount options, both kernel flags and filesystem-specific strings.
    pub options: Vec<&'a str>,
    /// Uid mapping applied to this mount alone.
    pub uid_mappings: Vec<IdMapping>,
    /// Gid mapping applied to this mount alone.
    pub gid_mappings: Vec<IdMapping>,
}

/// One range of an id mapping.
#[derive(Default, Clone, Copy, Debug)]
pub struct IdMapping {
    /// First id inside the container.
    pub container_id: u32,
    /// First id outside it.
    pub host_id: u32,
    /// How many ids the range covers.
    pub size: u32,
}

/// One hook program.
#[derive(Default, Debug)]
pub struct Hook<'a> {
    /// Program to run, an absolute path in the runtime's namespace.
    pub path: &'a str,
    /// Arguments, including argument zero.
    pub args: Vec<&'a str>,
    /// Environment.
    pub env: Vec<&'a str>,
    /// Seconds to wait before killing the hook, if any.
    pub timeout: Option<i64>,
}

/// Programs to run at defined points in the lifecycle.
#[derive(Default, Debug)]
pub struct Hooks<'a> {
    /// Deprecated, superseded by `create_runtime` and `create_container`.
    pub prestart: Vec<Hook<'a>>,
    /// After the namespaces are created, in the runtime's namespace.
    pub create_runtime: Vec<Hook<'a>>,
    /// After the namespaces are created, in the container's namespace.
    pub create_container: Vec<Hook<'a>>,
    /// Just before the payload runs, in the container's namespace.
    pub start_container: Vec<Hook<'a>>,
    /// After the payload has started.
    pub poststart: Vec<Hook<'a>>,
    /// After the container is deleted.
    pub poststop: Vec<Hook<'a>>,
}

/// Linux-specific configuration.
#[derive(Default, Debug)]
pub struct Linux<'a> {
    /// User namespace uid mapping.
    pub uid_mappings: Vec<IdMapping>,
    /// User namespace gid mapping.
    pub gid_mappings: Vec<IdMapping>,
    /// Kernel parameters to set inside the container's namespaces.
    pub sysctl: Vec<(&'a str, &'a str)>,
    /// Resource limits.
    pub resources: Option<Resources<'a>>,
    /// Where the container's cgroup lives.
    pub cgroups_path: Option<&'a str>,
    /// Namespaces to create or join.
    pub namespaces: Vec<Namespace<'a>>,
    /// Device nodes to create inside the container.
    pub devices: Vec<Device<'a>>,
    /// Network interfaces to move into the container.
    pub net_devices: Vec<(&'a str, Option<&'a str>)>,
    /// Seccomp filter.
    pub seccomp: Option<Seccomp<'a>>,
    /// Propagation mode applied to the root filesystem.
    pub rootfs_propagation: Option<&'a str>,
    /// Paths hidden from the container.
    pub masked_paths: Vec<&'a str>,
    /// Paths the container may read but not write.
    pub readonly_paths: Vec<&'a str>,
    /// `SELinux` label applied to the container mounts.
    pub mount_label: Option<&'a str>,
    /// Intel resource director technology settings.
    pub intel_rdt: Option<IntelRdt<'a>>,
    /// NUMA memory policy.
    pub memory_policy: Option<MemoryPolicy<'a>>,
    /// Execution domain.
    pub personality: Option<Personality<'a>>,
    /// Offsets for the time namespace.
    pub time_offsets: Vec<(&'a str, TimeOffset)>,
}

/// One namespace to create or join.
#[derive(Default, Clone, Copy, Debug)]
pub struct Namespace<'a> {
    /// Namespace type, such as `pid` or `mount`.
    pub kind: &'a str,
    /// Path to an existing namespace to join, or empty to create a new one.
    pub path: Option<&'a str>,
}

/// One device node to create inside the container.
#[derive(Default, Debug)]
pub struct Device<'a> {
    /// Path inside the container.
    pub path: &'a str,
    /// `c`, `b`, `u` or `p`.
    pub kind: &'a str,
    /// Major number.
    pub major: i64,
    /// Minor number.
    pub minor: i64,
    /// Permission bits.
    pub file_mode: Option<u32>,
    /// Owning user.
    pub uid: Option<u32>,
    /// Owning group.
    pub gid: Option<u32>,
}

/// Offset applied to one clock in a time namespace.
#[derive(Default, Clone, Copy, Debug)]
pub struct TimeOffset {
    /// Whole seconds.
    pub secs: i64,
    /// Additional nanoseconds.
    pub nanosecs: u32,
}

/// Execution domain settings.
#[derive(Default, Debug)]
pub struct Personality<'a> {
    /// `LINUX` or `LINUX32`.
    pub domain: &'a str,
    /// Additional flags.
    pub flags: Vec<&'a str>,
}

/// NUMA memory policy.
#[derive(Default, Debug)]
pub struct MemoryPolicy<'a> {
    /// Policy mode, such as `MPOL_BIND`.
    pub mode: &'a str,
    /// Node list, in the kernel's textual form.
    pub nodes: Option<&'a str>,
    /// Policy flags.
    pub flags: Vec<&'a str>,
}

/// Intel resource director technology settings.
#[derive(Default, Debug)]
pub struct IntelRdt<'a> {
    /// Class of service identifier.
    pub clos_id: Option<&'a str>,
    /// Raw schemata lines.
    pub schemata: Vec<&'a str>,
    /// Level three cache allocation.
    pub l3_cache_schema: Option<&'a str>,
    /// Memory bandwidth allocation.
    pub mem_bw_schema: Option<&'a str>,
    /// Enable monitoring for this class.
    pub enable_monitoring: bool,
}

/// Resource limits, as the configuration states them.
#[derive(Default, Debug)]
pub struct Resources<'a> {
    /// Device access rules.
    pub devices: Vec<DeviceRule<'a>>,
    /// Memory limits.
    pub memory: Option<Memory>,
    /// CPU limits.
    pub cpu: Option<Cpu<'a>>,
    /// Process count limit.
    pub pids_limit: Option<i64>,
    /// Block I/O limits.
    pub block_io: Option<BlockIo>,
    /// Huge page limits.
    pub hugepage_limits: Vec<HugepageLimit<'a>>,
    /// Network class and priorities.
    pub network: Option<Network<'a>>,
    /// Remote direct memory access limits.
    pub rdma: Vec<(&'a str, Rdma)>,
    /// Values written straight through to the unified hierarchy.
    pub unified: Vec<(&'a str, &'a str)>,
}

impl Resources<'_> {
    /// Whether the section asks for anything a cgroup would have to enforce.
    ///
    /// Every field here is a limit or a rule that only a cgroup can apply.
    /// A caller that turned cgroup management off and still stated one is
    /// asking for something that cannot be done, and the answer to that is
    /// to say so rather than to start a container with none of the
    /// isolation the configuration describes.
    /// A section that is present but states nothing does not count. Tooling
    /// writes `"memory": {}` where a template had a place for limits and the
    /// caller set none, and a container refused for that would be refused
    /// for punctuation.
    #[must_use]
    pub fn are_requested(&self) -> bool {
        let memory = self.memory.as_ref().is_some_and(Memory::is_set);
        let cpu = self.cpu.as_ref().is_some_and(Cpu::is_set);
        let block_io = self.block_io.as_ref().is_some_and(BlockIo::is_set);
        !self.devices.is_empty()
            || memory
            || cpu
            || block_io
            || self.pids_limit.is_some()
            || !self.hugepage_limits.is_empty()
            || self.network.is_some()
            || !self.rdma.is_empty()
            || !self.unified.is_empty()
    }
}

/// One device access rule.
#[derive(Default, Clone, Copy, Debug)]
pub struct DeviceRule<'a> {
    /// Allow or deny.
    pub allow: bool,
    /// `a`, `c` or `b`.
    pub kind: Option<&'a str>,
    /// Major number, or `None` for any.
    pub major: Option<i64>,
    /// Minor number, or `None` for any.
    pub minor: Option<i64>,
    /// Any of `r`, `w` and `m`.
    pub access: Option<&'a str>,
}

/// Memory limits.
#[derive(Default, Clone, Copy, Debug)]
pub struct Memory {
    /// Hard limit in bytes.
    pub limit: Option<i64>,
    /// Soft limit in bytes.
    pub reservation: Option<i64>,
    /// Combined memory and swap limit in bytes.
    pub swap: Option<i64>,
    /// Kernel memory limit, ignored on the unified hierarchy.
    pub kernel: Option<i64>,
    /// Kernel socket memory limit.
    pub kernel_tcp: Option<i64>,
    /// Swap tendency.
    pub swappiness: Option<u64>,
    /// Turn the out-of-memory killer off.
    pub disable_oom_killer: Option<bool>,
    /// Use hierarchical accounting, cgroup v1 only.
    pub use_hierarchy: Option<bool>,
    /// Refuse an update that would immediately kill the container.
    pub check_before_update: Option<bool>,
}

/// CPU limits.
#[derive(Default, Clone, Copy, Debug)]
pub struct Cpu<'a> {
    /// Relative weight.
    pub shares: Option<u64>,
    /// Bandwidth in microseconds per period.
    pub quota: Option<i64>,
    /// Burst allowance in microseconds.
    pub burst: Option<u64>,
    /// Period in microseconds.
    pub period: Option<u64>,
    /// Real-time bandwidth in microseconds.
    pub realtime_runtime: Option<i64>,
    /// Real-time period in microseconds.
    pub realtime_period: Option<u64>,
    /// CPUs the container may run on.
    pub cpus: Option<&'a str>,
    /// Memory nodes the container may use.
    pub mems: Option<&'a str>,
    /// Mark the container idle.
    pub idle: Option<i64>,
}

/// Block I/O limits.
#[derive(Default, Clone, Debug)]
pub struct BlockIo {
    /// Relative weight.
    pub weight: Option<u16>,
    /// Weight for the cgroup's own tasks, cgroup v1 only.
    pub leaf_weight: Option<u16>,
    /// Per-device weights.
    pub weight_device: Vec<WeightDevice>,
    /// Per-device read bandwidth limits.
    pub throttle_read_bps: Vec<ThrottleDevice>,
    /// Per-device write bandwidth limits.
    pub throttle_write_bps: Vec<ThrottleDevice>,
    /// Per-device read operation limits.
    pub throttle_read_iops: Vec<ThrottleDevice>,
    /// Per-device write operation limits.
    pub throttle_write_iops: Vec<ThrottleDevice>,
}

/// A per-device block I/O weight.
#[derive(Default, Clone, Copy, Debug)]
pub struct WeightDevice {
    /// Device major number.
    pub major: i64,
    /// Device minor number.
    pub minor: i64,
    /// Relative weight.
    pub weight: Option<u16>,
    /// Weight for the cgroup's own tasks.
    pub leaf_weight: Option<u16>,
}

/// A per-device block I/O rate limit.
#[derive(Default, Clone, Copy, Debug)]
pub struct ThrottleDevice {
    /// Device major number.
    pub major: i64,
    /// Device minor number.
    pub minor: i64,
    /// Bytes or operations per second.
    pub rate: u64,
}

/// A huge page limit.
#[derive(Default, Clone, Copy, Debug)]
pub struct HugepageLimit<'a> {
    /// Page size, such as `2MB`.
    pub page_size: &'a str,
    /// Limit in bytes.
    pub limit: u64,
}

/// Network class and per-interface priorities.
#[derive(Default, Debug)]
pub struct Network<'a> {
    /// Network class identifier.
    pub class_id: Option<u32>,
    /// Per-interface egress priorities.
    pub priorities: Vec<(&'a str, u32)>,
}

/// Remote direct memory access limits for one device.
#[derive(Default, Clone, Copy, Debug)]
pub struct Rdma {
    /// Maximum host channel adapter handles.
    pub hca_handles: Option<u32>,
    /// Maximum host channel adapter objects.
    pub hca_objects: Option<u32>,
}

/// A seccomp filter, as the configuration states it.
#[derive(Default, Debug)]
pub struct Seccomp<'a> {
    /// Action for syscalls no rule names.
    pub default_action: &'a str,
    /// Errno for the default action, when it carries one.
    pub default_errno_ret: Option<u32>,
    /// Architectures the filter covers.
    pub architectures: Vec<&'a str>,
    /// Filter flags.
    pub flags: Vec<&'a str>,
    /// Socket a notification listener is sent to.
    pub listener_path: Option<&'a str>,
    /// Opaque datum sent alongside the listener.
    pub listener_metadata: Option<&'a str>,
    /// Rules, in order.
    pub syscalls: Vec<Syscall<'a>>,
}

/// One seccomp rule.
#[derive(Default, Debug)]
pub struct Syscall<'a> {
    /// Syscall names the rule covers.
    pub names: Vec<&'a str>,
    /// Action when the rule matches.
    pub action: &'a str,
    /// Errno for the action, when it carries one.
    pub errno_ret: Option<u32>,
    /// Conditions on the arguments.
    pub args: Vec<SyscallArg<'a>>,
}

/// One condition on a syscall argument.
#[derive(Default, Clone, Copy, Debug)]
pub struct SyscallArg<'a> {
    /// Which argument, counted from zero.
    pub index: u32,
    /// Value compared against, or the mask for a masked comparison.
    pub value: u64,
    /// Second operand, used by the masked comparison.
    pub value_two: u64,
    /// Comparison operator.
    pub op: &'a str,
}

impl Memory {
    /// Whether the section states any limit at all.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        self.limit.is_some()
            || self.reservation.is_some()
            || self.swap.is_some()
            || self.kernel.is_some()
            || self.kernel_tcp.is_some()
            || self.swappiness.is_some()
            || self.disable_oom_killer.is_some()
            || self.use_hierarchy.is_some()
    }
}

impl Cpu<'_> {
    /// Whether the section states any limit at all.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        self.shares.is_some()
            || self.quota.is_some()
            || self.burst.is_some()
            || self.period.is_some()
            || self.realtime_runtime.is_some()
            || self.realtime_period.is_some()
            || self.cpus.is_some()
            || self.mems.is_some()
            || self.idle.is_some()
    }
}

impl BlockIo {
    /// Whether the section states any limit at all.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.weight.is_some()
            || self.leaf_weight.is_some()
            || !self.weight_device.is_empty()
            || !self.throttle_read_bps.is_empty()
            || !self.throttle_write_bps.is_empty()
            || !self.throttle_read_iops.is_empty()
            || !self.throttle_write_iops.is_empty()
    }
}
