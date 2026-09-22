//! The plan: exactly what the container init process will do, as bytes.
//!
//! A plan is one contiguous arena with a header, a string section, and a
//! section per kind of record. Everything inside it is addressed by offset
//! rather than by pointer, so the driver can write it to a sealed memory file
//! and init can map that file anywhere and read it directly.
//!
//! Three properties follow from that shape, and each one replaces a rule that
//! would otherwise have to be enforced by review:
//!
//! - The executor cannot allocate. It holds a mapped buffer and resolves
//!   offsets within it; there is no parser and no owned collection reachable
//!   from it.
//! - The executor cannot fail for configuration reasons. Every question about
//!   whether the configuration is valid was answered while building the plan,
//!   in the driver, where failing is cheap and the message can be good.
//! - The plan is byte-comparable, so a golden-file test can assert the exact
//!   plan a given `config.json` produces, including the exact filter program.

#[macro_use]
mod layout;

pub mod codec;
pub mod record;

use crate::{
    oci::plan::{
        codec::{Reader, Str, Writer},
        layout::BoolPad2,
        record::{
            DeviceOp, IdRange, MountOp, NamespaceOp, PathOp, RlimitOp, WriteOp,
        },
    },
    sys::error::{Error, Result},
};

/// Identifies a kot plan. Spells `KOTP` in a little endian dump.
pub const MAGIC: u32 = 0x5054_4f4b;

/// Layout revision.
///
/// Init refuses a plan whose revision it does not know, so a mismatched pair
/// of binaries cannot misread offsets.
pub const VERSION: u32 = 3;

/// Sections a plan is divided into.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    /// Raw bytes every [`Str`] points into.
    Strings = 0,
    /// A single record describing the container's namespaces and rootfs.
    Container = 1,
    /// A single record describing the payload process.
    Process = 2,
    /// Mounts, in the order they are established.
    Mounts = 3,
    /// Device nodes to create.
    Devices = 4,
    /// Masked and read-only paths.
    Paths = 5,
    /// Kernel parameters to set.
    Sysctls = 6,
    /// Resource limits.
    Rlimits = 7,
    /// The emitted seccomp program, as raw instruction bytes.
    Seccomp = 8,
    /// User namespace uid mapping.
    UidMap = 9,
    /// User namespace gid mapping.
    GidMap = 10,
    /// Namespaces to join or create after the clone.
    Namespaces = 11,
    /// Payload arguments, as string references.
    Args = 12,
    /// Payload environment, as string references.
    Env = 13,
    /// Supplementary groups.
    AdditionalGids = 14,
}

/// How many sections a plan has.
pub const SECTION_COUNT: usize = 15;

impl Section {
    /// Slot this section occupies in the header, which is its discriminant.
    const fn index(self) -> usize {
        self as usize
    }
}

/// Where a section lives and how much it holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extent {
    /// Offset from the start of the arena.
    pub at: u32,
    /// Number of records, or bytes for the string section.
    pub count: u32,
}

record! {
    /// The container's shape: namespaces, root filesystem, identity.
    ///
    /// The booleans are separate fields rather than a packed word because each
    /// one is read exactly once, in a different place, and naming them is worth
    /// more than the four bytes packing would save.
    #[allow(clippy::struct_excessive_bools)]
    pub struct Container {
        /// Namespaces created by the clone that made init.
        clone_flags: u64,
        /// Namespaces init unshares for itself, after the clone.
        unshare_flags: u64,
        /// Path to the root filesystem, absolute in the runtime's namespace.
        rootfs: Str,
        /// Propagation applied to the root before anything is mounted under
        /// it.
        rootfs_propagation: u64,
        /// Hostname to set in the UTS namespace.
        hostname: Str,
        /// NIS domain name to set in the UTS namespace.
        domainname: Str,
        /// Mount the root read only.
        rootfs_readonly: bool,
        /// Use `chroot` rather than `pivot_root`, which is weaker and only
        /// used when the caller explicitly asks.
        no_pivot: bool,
        /// Give the container its own session keyring.
        new_keyring: bool,
        /// Write `deny` to `setgroups` before the gid map, which the kernel
        /// requires for an unprivileged user namespace.
        deny_setgroups: bool,
        /// Join the namespaces and run the payload without building a
        /// filesystem.
        ///
        /// What `exec` needs: the container already exists, so there is
        /// nothing to mount and nothing to pivot into.
        join_only: bool,
        /// Offset applied to the boot-time clock, in whole seconds.
        boottime_secs: i64,
        /// Offset applied to the monotonic clock, in whole seconds.
        monotonic_secs: i64,
        /// Additional nanoseconds on the boot-time offset.
        boottime_nanos: u32,
        /// Additional nanoseconds on the monotonic offset.
        monotonic_nanos: u32,
        /// Whether the boot-time clock is offset at all, which zero cannot
        /// say on its own: a configuration may ask for exactly no offset.
        set_boottime: bool,
        /// Whether the monotonic clock is offset at all.
        set_monotonic: bool,
        /// Make a cgroup namespace, after the driver has moved init into the
        /// container's cgroup.
        ///
        /// Held apart from `clone_flags` because the moment matters: a cgroup
        /// namespace is rooted wherever its creator sits at the time, so
        /// making it at the clone would root it in the runtime's own cgroup
        /// and the container would see the wrong tree.
        cgroup_namespace: BoolPad2,
    }
}

record! {
    /// The payload process: identity, privileges, and everything applied to
    /// it just before `execve`.
    pub struct Process {
        /// User id inside the container.
        uid: u32,
        /// Group id inside the container.
        gid: u32,
        /// File creation mask, when the configuration sets one.
        umask: u32,
        /// Working directory inside the container.
        cwd: Str,
        /// Capabilities in force.
        cap_effective: u64,
        /// Capabilities that may be made effective.
        cap_permitted: u64,
        /// Capabilities preserved across `execve`.
        cap_inheritable: u64,
        /// Upper bound on what may ever be gained.
        cap_bounding: u64,
        /// Capabilities that survive `execve` unprivileged.
        cap_ambient: u64,
        /// Out-of-memory score adjustment.
        oom_score_adj: i32,
        /// Terminal dimensions, rows.
        console_height: u32,
        /// Terminal dimensions, columns.
        console_width: u32,
        /// `AppArmor` profile to transition to.
        apparmor: Str,
        /// `SELinux` label to transition to.
        selinux: Str,
        /// Execution domain, when one is requested.
        personality: u64,
        /// Scheduling policy number.
        sched_policy: u32,
        /// Scheduling flags.
        sched_flags: u64,
        /// Nice value.
        sched_nice: i32,
        /// Static priority.
        sched_priority: u32,
        /// Deadline policy runtime, in nanoseconds.
        sched_runtime: u64,
        /// Deadline policy deadline, in nanoseconds.
        sched_deadline: u64,
        /// Deadline policy period, in nanoseconds.
        sched_period: u64,
        /// I/O priority class.
        ioprio_class: u32,
        /// I/O priority within the class.
        ioprio_priority: u32,
        /// NUMA memory policy mode.
        mempolicy_mode: u32,
        /// NUMA memory policy flags.
        mempolicy_flags: u32,
        /// NUMA node list, in the kernel's textual form.
        mempolicy_nodes: Str,
        /// Flags for `seccomp(SECCOMP_SET_MODE_FILTER)`.
        seccomp_flags: u32,
        /// Socket a notification listener is sent to.
        seccomp_listener: Str,
        /// Opaque datum sent alongside the listener.
        seccomp_metadata: Str,
        /// A mask of [`process_flag`] values.
        flags: u32,
    }
}

/// Boolean settings of the payload process, packed into one word.
pub mod process_flag {
    /// Attach a pseudo-terminal.
    pub const TERMINAL: u32 = 1 << 0;
    /// Refuse any later gain of privilege.
    pub const NO_NEW_PRIVS: u32 = 1 << 1;
    /// A file creation mask was requested.
    pub const HAS_UMASK: u32 = 1 << 2;
    /// Capability sets were given.
    pub const HAS_CAPS: u32 = 1 << 3;
    /// An out-of-memory score adjustment was given.
    pub const HAS_OOM_SCORE_ADJ: u32 = 1 << 4;
    /// An execution domain was requested.
    pub const HAS_PERSONALITY: u32 = 1 << 5;
    /// A scheduling policy was requested.
    pub const HAS_SCHEDULER: u32 = 1 << 6;
    /// An I/O priority was requested.
    pub const HAS_IOPRIO: u32 = 1 << 7;
    /// A NUMA memory policy was requested.
    pub const HAS_MEMPOLICY: u32 = 1 << 8;
    /// Skip `setgroups`, which the `keep_original_groups` extension asks for.
    pub const KEEP_ORIGINAL_GROUPS: u32 = 1 << 9;
    /// A seccomp filter is present.
    pub const HAS_SECCOMP: u32 = 1 << 10;
}

impl Process {
    /// True when `flag` is set.
    #[must_use]
    pub const fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Sets `flag` when `on`, and clears it otherwise.
    pub const fn set(&mut self, flag: u32, on: bool) {
        if on {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }
}

/// Bytes the header occupies before the first section.
const HEADER_SIZE: usize = 4 + 4 + 4 + 4 + SECTION_COUNT * 8;

/// Builds a plan arena.
///
/// The caller writes strings first, keeping the [`Str`] handles, then writes
/// each section in turn. Sections may be written in any order; the header
/// records where each one landed.
#[derive(Default)]
pub struct Builder {
    body: Writer,
    strings: Writer,
    extents: [Extent; SECTION_COUNT],
}

impl Builder {
    /// Discards everything, keeping the buffers for reuse.
    pub fn clear(&mut self) {
        self.body.clear();
        self.strings.clear();
        self.extents = [Extent::default(); SECTION_COUNT];
    }

    /// Interns a string, returning a reference into the string section.
    ///
    /// Identical strings are stored once. A configuration repeats the same
    /// mount options and the same `/proc` prefix many times, so the search is
    /// worth its cost.
    pub fn intern(&mut self, value: &str) -> Result<Str> {
        self.intern_bytes(value.as_bytes())
    }

    /// Interns raw bytes.
    pub fn intern_bytes(&mut self, value: &[u8]) -> Result<Str> {
        if value.is_empty() {
            return Ok(Str::EMPTY);
        }
        if let Some(at) = find(self.strings.as_bytes(), value) {
            return Ok(Str {
                at: u32::try_from(at).map_err(|_| {
                    Error::msg("plan: string section too large")
                })?,
                len: u32::try_from(value.len())
                    .map_err(|_| Error::msg("plan: string too long"))?,
            });
        }
        let at = u32::try_from(self.strings.len())
            .map_err(|_| Error::msg("plan: string section too large"))?;
        let len = u32::try_from(value.len())
            .map_err(|_| Error::msg("plan: string too long"))?;
        self.strings.bytes(value);
        // A terminator is stored so that a path can be handed to a syscall
        // without copying it into a separate buffer first.
        self.strings.u8(0);
        Ok(Str { at, len })
    }

    /// Begins a section, returning a handle that must be ended.
    pub fn begin(&mut self, section: Section) -> Result<Open> {
        self.body.align(8);
        let at = u32::try_from(self.body.len())
            .map_err(|_| Error::msg("plan: arena too large"))?;
        Ok(Open {
            section,
            at,
            count: 0,
        })
    }

    /// Records a section's extent.
    pub fn end(&mut self, open: Open) -> Result<()> {
        let Some(slot) = self.extents.get_mut(open.section.index()) else {
            return Err(Error::msg("plan: unknown section"));
        };
        *slot = Extent {
            at: open.at,
            count: open.count,
        };
        Ok(())
    }

    /// The writer records are appended through.
    pub const fn records(&mut self) -> &mut Writer {
        &mut self.body
    }

    /// Finishes the arena and returns it.
    ///
    /// The string section is placed last, so record offsets do not move as
    /// strings are interned.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        self.body.align(8);
        let strings_at = u32::try_from(HEADER_SIZE + self.body.len())
            .map_err(|_| Error::msg("plan: arena too large"))?;
        let strings_len = u32::try_from(self.strings.len())
            .map_err(|_| Error::msg("plan: string section too large"))?;
        if let Some(slot) = self.extents.get_mut(Section::Strings.index()) {
            *slot = Extent {
                at: strings_at,
                count: strings_len,
            };
        }

        let total = HEADER_SIZE + self.body.len() + self.strings.len();
        let mut out = Writer::with_capacity(total);
        out.u32(MAGIC);
        out.u32(VERSION);
        out.u32(
            u32::try_from(total)
                .map_err(|_| Error::msg("plan: arena too large"))?,
        );
        out.u32(
            u32::try_from(SECTION_COUNT)
                .map_err(|_| Error::msg("plan: section count"))?,
        );
        for (index, extent) in self.extents.iter().enumerate() {
            // Record offsets were measured from the start of the body, which
            // sits after the header, so shift them. The string section was
            // already placed at its final offset above.
            let at = if index == Section::Strings.index() {
                extent.at
            } else {
                extent.at.saturating_add(
                    u32::try_from(HEADER_SIZE)
                        .map_err(|_| Error::msg("plan: header size"))?,
                )
            };
            out.u32(at);
            out.u32(extent.count);
        }
        debug_assert_eq!(out.len(), HEADER_SIZE, "header size is fixed");
        out.bytes(self.body.as_bytes());
        out.bytes(self.strings.as_bytes());
        Ok(out.take())
    }
}

/// A section being written.
#[derive(Clone, Copy, Debug)]
pub struct Open {
    section: Section,
    at: u32,
    count: u32,
}

impl Open {
    /// Notes that one more record was appended.
    pub const fn advance(&mut self) {
        self.count += 1;
    }

    /// Sets the count directly, for the sections whose count is a byte length
    /// rather than a record count.
    pub const fn set_count(&mut self, count: u32) {
        self.count = count;
    }
}

/// A read-only view over a plan arena.
#[derive(Clone, Copy)]
pub struct View<'a> {
    arena: &'a [u8],
    extents: [Extent; SECTION_COUNT],
    strings: &'a [u8],
}

impl<'a> View<'a> {
    /// Validates the header and wraps the arena.
    pub fn new(arena: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(arena);
        if r.u32()? != MAGIC {
            return Err(Error::msg("plan: not a plan"));
        }
        if r.u32()? != VERSION {
            return Err(Error::msg("plan: version mismatch"));
        }
        let total = r.u32()? as usize;
        if total != arena.len() {
            return Err(Error::msg("plan: length mismatch"));
        }
        if r.u32()? as usize != SECTION_COUNT {
            return Err(Error::msg("plan: section count mismatch"));
        }
        let mut extents = [Extent::default(); SECTION_COUNT];
        for extent in &mut extents {
            *extent = Extent {
                at: r.u32()?,
                count: r.u32()?,
            };
        }
        let strings = {
            let Some(extent) = extents.get(Section::Strings.index()) else {
                return Err(Error::msg("plan: no string section"));
            };
            let at = extent.at as usize;
            let len = extent.count as usize;
            arena.get(at..at + len).ok_or_else(|| {
                Error::msg("plan: string section out of range")
            })?
        };
        Ok(Self {
            arena,
            extents,
            strings,
        })
    }

    /// Resolves a string reference.
    pub fn text(&self, reference: Str) -> Result<&'a str> {
        core::str::from_utf8(self.raw(reference)?)
            .map_err(|_| Error::msg("plan: string is not UTF-8"))
    }

    /// Resolves a string reference to raw bytes.
    pub fn raw(&self, reference: Str) -> Result<&'a [u8]> {
        if reference.is_empty() {
            return Ok(&[]);
        }
        let at = reference.at as usize;
        let len = reference.len as usize;
        self.strings
            .get(at..at + len)
            .ok_or_else(|| Error::msg("plan: string out of range"))
    }

    /// Resolves a string reference to a NUL-terminated string.
    ///
    /// The terminator is stored alongside every interned string, so a path can
    /// go straight to a syscall without being copied first.
    pub fn c_str(&self, reference: Str) -> Result<&'a core::ffi::CStr> {
        if reference.is_empty() {
            return Ok(c"");
        }
        let at = reference.at as usize;
        let len = reference.len as usize;
        let bytes = self
            .strings
            .get(at..=at + len)
            .ok_or_else(|| Error::msg("plan: string out of range"))?;
        core::ffi::CStr::from_bytes_with_nul(bytes)
            .map_err(|_| Error::msg("plan: string not terminated"))
    }

    /// How many records a section holds.
    #[must_use]
    pub fn count(&self, section: Section) -> u32 {
        self.extents.get(section.index()).map_or(0, |e| e.count)
    }

    /// A reader positioned at the start of a section.
    pub fn reader(&self, section: Section) -> Result<Reader<'a>> {
        let Some(extent) = self.extents.get(section.index()) else {
            return Err(Error::msg("plan: unknown section"));
        };
        Reader::at(self.arena, extent.at as usize)
    }

    /// The container record.
    pub fn container(&self) -> Result<Container> {
        let mut r = self.reader(Section::Container)?;
        Container::decode(&mut r)
    }

    /// The process record.
    pub fn process(&self) -> Result<Process> {
        let mut r = self.reader(Section::Process)?;
        Process::decode(&mut r)
    }

    /// Calls `visit` for each record of a section.
    ///
    /// The loop is bounded by the record count the header declares, and each
    /// decode advances the reader, so it cannot run away on a damaged arena.
    pub fn for_each<T, F>(
        &self,
        section: Section,
        decode: impl Fn(&mut Reader<'a>) -> Result<T>,
        mut visit: F,
    ) -> Result<()>
    where
        F: FnMut(T) -> Result<()>,
    {
        let count = self.count(section);
        let mut r = self.reader(section)?;
        for _ in 0..count {
            visit(decode(&mut r)?)?;
        }
        Ok(())
    }

    /// Calls `visit` for each mount, in order.
    pub fn mounts<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(MountOp) -> Result<()>,
    {
        self.for_each(Section::Mounts, MountOp::decode, visit)
    }

    /// Calls `visit` for each device node.
    pub fn devices<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(DeviceOp) -> Result<()>,
    {
        self.for_each(Section::Devices, DeviceOp::decode, visit)
    }

    /// Calls `visit` for each masked or read-only path.
    pub fn paths<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(PathOp) -> Result<()>,
    {
        self.for_each(Section::Paths, PathOp::decode, visit)
    }

    /// Calls `visit` for each kernel parameter.
    pub fn sysctls<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(WriteOp) -> Result<()>,
    {
        self.for_each(Section::Sysctls, WriteOp::decode, visit)
    }

    /// Calls `visit` for each resource limit.
    pub fn rlimits<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(RlimitOp) -> Result<()>,
    {
        self.for_each(Section::Rlimits, RlimitOp::decode, visit)
    }

    /// Calls `visit` for each namespace to join or create.
    pub fn namespaces<F>(&self, visit: F) -> Result<()>
    where
        F: FnMut(NamespaceOp) -> Result<()>,
    {
        self.for_each(Section::Namespaces, NamespaceOp::decode, visit)
    }

    /// Calls `visit` for each range of an id mapping.
    pub fn id_map<F>(&self, section: Section, visit: F) -> Result<()>
    where
        F: FnMut(IdRange) -> Result<()>,
    {
        self.for_each(section, IdRange::decode, visit)
    }

    /// Reads a section of string references into `out`.
    pub fn string_list(
        &self,
        section: Section,
        out: &mut Vec<Str>,
    ) -> Result<()> {
        out.clear();
        let count = self.count(section);
        let mut r = self.reader(section)?;
        for _ in 0..count {
            out.push(r.str()?);
        }
        Ok(())
    }

    /// Reads the supplementary group list into `out`.
    pub fn additional_gids(&self, out: &mut Vec<u32>) -> Result<()> {
        out.clear();
        let count = self.count(Section::AdditionalGids);
        let mut r = self.reader(Section::AdditionalGids)?;
        for _ in 0..count {
            out.push(r.u32()?);
        }
        Ok(())
    }

    /// The emitted seccomp program, as raw bytes.
    ///
    /// The caller reinterprets these as instructions when handing them to the
    /// kernel, which takes them as an opaque byte count anyway.
    pub fn seccomp(&self) -> Result<&'a [u8]> {
        let count = self.count(Section::Seccomp) as usize;
        let mut r = self.reader(Section::Seccomp)?;
        r.take(count)
    }
}

/// Finds `needle` in `haystack`, at a position where it is followed by a NUL,
/// so that an interned string's terminator belongs to it.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() >= haystack.len() {
        return None;
    }
    haystack.windows(needle.len() + 1).position(|w| {
        w.get(..needle.len()) == Some(needle) && w.last() == Some(&0)
    })
}

/// Writes a `Container` record into a builder.
pub fn put_container(builder: &mut Builder, value: &Container) -> Result<()> {
    let mut open = builder.begin(Section::Container)?;
    value.encode(builder.records());
    open.advance();
    builder.end(open)
}

/// Writes a `Process` record into a builder.
pub fn put_process(builder: &mut Builder, value: &Process) -> Result<()> {
    let mut open = builder.begin(Section::Process)?;
    value.encode(builder.records());
    open.advance();
    builder.end(open)
}
