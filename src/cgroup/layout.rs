//! Which cgroup hierarchy the host runs, and where its controllers live.
//!
//! The answer is settled once per invocation and cached, because it cannot
//! change while the runtime is running and because probing it per container
//! would put a `statfs` and a mount table scan on the critical path.

use std::{
    os::fd::{AsFd as _, BorrowedFd, OwnedFd},
    sync::atomic::{AtomicU8, Ordering},
};

use crate::sys::{
    error::{Context, Error, Result},
    path::Path,
};

/// Where the cgroup filesystem is mounted.
pub const ROOT: &str = "/sys/fs/cgroup";

/// Magic number of the unified hierarchy, from `statfs`.
const CGROUP2_MAGIC: u64 = 0x6367_7270;

/// How the host arranges cgroups.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// One tree, controllers enabled per node.
    Unified,
    /// One tree per controller.
    Legacy,
    /// Legacy controllers alongside a unified tree.
    Hybrid,
}

/// Cached answer. Zero means not yet probed.
static CACHED: AtomicU8 = AtomicU8::new(0);

impl Layout {
    /// Probes the host, or returns the cached answer.
    pub fn detect() -> Result<Self> {
        match CACHED.load(Ordering::Relaxed) {
            1 => return Ok(Self::Unified),
            2 => return Ok(Self::Legacy),
            3 => return Ok(Self::Hybrid),
            _ => {}
        }
        let layout = Self::probe()?;
        CACHED.store(
            match layout {
                Self::Unified => 1,
                Self::Legacy => 2,
                Self::Hybrid => 3,
            },
            Ordering::Relaxed,
        );
        Ok(layout)
    }

    fn probe() -> Result<Self> {
        let stat = rustix::fs::statfs(ROOT).context("cgroup: statfs")?;
        #[allow(clippy::cast_sign_loss, clippy::useless_conversion)]
        let magic = u64::try_from(stat.f_type).unwrap_or(0);
        if magic == CGROUP2_MAGIC {
            return Ok(Self::Unified);
        }
        // A hybrid host mounts the unified tree beside the legacy ones, by
        // convention at `unified`. Its presence distinguishes the two legacy
        // arrangements, and it matters because a container may need a cgroup
        // namespace rooted in the unified tree.
        let unified = std::path::Path::new(ROOT).join("unified");
        if unified.is_dir() {
            Ok(Self::Hybrid)
        } else {
            Ok(Self::Legacy)
        }
    }

    /// True when the unified hierarchy is available, whether alone or beside
    /// the legacy one.
    #[must_use]
    pub const fn has_unified(self) -> bool {
        matches!(self, Self::Unified | Self::Hybrid)
    }

    /// True when per-controller trees are present.
    #[must_use]
    pub const fn has_legacy(self) -> bool {
        matches!(self, Self::Legacy | Self::Hybrid)
    }
}

/// Every legacy controller the runtime knows how to configure.
pub const CONTROLLERS: [&str; 12] = [
    "cpu", "cpuacct", "cpuset", "memory", "devices", "freezer", "net_cls",
    "net_prio", "blkio", "pids", "hugetlb", "rdma",
];

/// Where each legacy controller is mounted.
///
/// A distribution may mount `cpu` and `cpuacct` together, or put them
/// somewhere other than the conventional place, so the answer comes from the
/// mount table instead of from a guess.
#[derive(Default)]
pub struct Mounts {
    entries: Vec<(String, String)>,
}

impl Mounts {
    /// Reads `/proc/self/mountinfo` and records every cgroup mount.
    pub fn detect() -> Result<Self> {
        let text = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| from_io(&e, "cgroup: read mountinfo"))?;
        let mut out = Self::default();
        for line in text.lines() {
            out.add_line(line);
        }
        Ok(out)
    }

    fn add_line(&mut self, line: &str) {
        // The optional fields between the root and the separator make this
        // positional from both ends: everything before ` - ` is the mount, and
        // everything after names the filesystem.
        let Some((head, tail)) = line.split_once(" - ") else {
            return;
        };
        let mut tail_fields = tail.split_whitespace();
        let Some(fstype) = tail_fields.next() else {
            return;
        };
        if fstype != "cgroup" {
            return;
        }
        let Some(options) = tail_fields.nth(1) else {
            return;
        };
        let Some(point) = head.split_whitespace().nth(4) else {
            return;
        };

        for option in options.split(',') {
            let name = option.strip_prefix("name=").unwrap_or(option);
            if CONTROLLERS.contains(&name) || option.starts_with("name=") {
                self.entries.push((name.to_owned(), point.to_owned()));
            }
        }
    }

    /// Every controller that is mounted, with its mount point.
    pub fn points(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, point)| (name.as_str(), point.as_str()))
    }
}

/// Builds the absolute path of a container's cgroup in the unified tree.
///
/// The configuration states the path with a leading separator, which joining
/// would read as "start again from the root" and which would land the
/// container's cgroup outside the hierarchy entirely.
pub fn unified_path(relative: &str) -> Result<Path> {
    controller_path(ROOT, relative)
}

/// Builds the absolute path of a container's cgroup in a legacy controller.
///
/// Each legacy controller is a separate tree with its own mount point, so the
/// same container occupies one directory per controller, never one overall.
pub fn controller_path(point: &str, relative: &str) -> Result<Path> {
    ensure_below(relative.as_bytes())?;
    let mut path = Path::from(point.as_bytes())?;
    for component in crate::sys::path::components(relative.as_bytes()) {
        path.join(component)?;
    }
    Ok(path)
}

/// Refuses a relative cgroup path that would climb out of what it is joined
/// to.
///
/// The components are joined one at a time, which already reads a leading
/// separator as nothing rather than as the filesystem root. A `..` is the
/// remaining way out: it names the parent of the hierarchy node the caller
/// meant, so the limits, the device rules and the process list the
/// configuration asked for would land on a sibling container's cgroup, or on
/// the root of the tree where they apply to everything on the host.
pub fn ensure_below(relative: &[u8]) -> Result<()> {
    for component in crate::sys::path::components(relative) {
        if component == b".." {
            return Err(Error::msg(
                "cgroup: a path component of .. would leave the hierarchy",
            ));
        }
    }
    Ok(())
}

/// Opens a cgroup directory, creating it and its parents when needed.
///
/// Returns a descriptor, not a path, so that every later write is an `openat`
/// relative to it, which is both fewer syscalls and immune to the directory
/// being moved underneath us.
pub fn open_or_create(path: &Path) -> Result<OwnedFd> {
    use rustix::fs::Mode;

    // The leaf is created before anything is looked at. A container's own
    // cgroup never exists yet and its parents always do, so this is one
    // call where looking first and then walking the ancestors is six.
    match rustix::fs::mkdir(path.as_c_str(), Mode::from_raw_mode(0o755)) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == crate::sys::error::EEXIST => {}
        Err(e) if e.raw_os_error() == crate::sys::error::ENOENT => {
            create_directories(path)?;
        }
        Err(e) => {
            // A parent that refuses a new directory is not a failure when
            // the one asked for is already there, which is how a delegated
            // cgroup arrives.
            return open_directory(path).map_err(|_| {
                Error::from(e).describe("cgroup: create directory")
            });
        }
    }
    open_directory(path)
}

/// Opens a directory, so that later work is `openat` relative to it.
pub fn open_directory(path: &Path) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path.as_c_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("cgroup: open directory")
}

/// Creates every missing component of `path`.
///
/// The loop is bounded by the number of components, which the path buffer
/// bounds in turn.
fn create_directories(path: &Path) -> Result<()> {
    use rustix::fs::Mode;

    // One buffer grows a component at a time, so the prefix is built once
    // instead of rebuilt for every ancestor.
    let mut partial = Path::from(b"/")?;
    for component in crate::sys::path::components(path.as_bytes()) {
        partial.join(component)?;
        match rustix::fs::mkdir(partial.as_c_str(), Mode::from_raw_mode(0o755))
        {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == crate::sys::error::EEXIST => {}
            Err(e) => {
                return Err(Error::from(e).describe("cgroup: create directory"));
            }
        }
    }
    Ok(())
}

fn from_io(error: &std::io::Error, context: &'static str) -> Error {
    Error::new(error.raw_os_error().unwrap_or(0), context)
}

/// Gives every cpuset directory on the way to a container something to run
/// on.
///
/// A cpuset directory is created empty, and the controller refuses to take a
/// process while either its CPU list or its memory node list is. The values
/// are not inherited by the kernel: each new level starts blank and has to be
/// filled in from the level above, which is why the whole path is walked
/// rather than only its last component.
///
/// A level that already names something is left exactly as it is, so a
/// configuration that sets `cpuset.cpus` keeps what it asked for. A parent
/// that names nothing leaves nothing to copy, which happens on a host where
/// the controller is mounted but unused; the container is no worse off than
/// the cgroup it was going into.
pub fn seed_cpuset(point: &str, relative: &str) -> Result<()> {
    let mut path = Path::from(point.as_bytes())?;
    let mut parent = open_directory(&path)?;

    for component in crate::sys::path::components(relative.as_bytes()) {
        path.join(component)?;
        let child = open_directory(&path)?;
        for file in [c"cpuset.cpus", c"cpuset.mems"] {
            inherit_if_empty(parent.as_fd(), child.as_fd(), file)?;
        }
        parent = child;
    }
    Ok(())
}

/// Copies one cpuset value down a level, unless the level below has its own.
fn inherit_if_empty(
    parent: BorrowedFd<'_>,
    child: BorrowedFd<'_>,
    file: &core::ffi::CStr,
) -> Result<()> {
    use crate::cgroup::write::{read_one, write_one};

    let mut buffer = [0u8; 4096];
    let read = read_one(child, file, &mut buffer)?;
    if !buffer.get(..read).unwrap_or(&[]).trim_ascii().is_empty() {
        return Ok(());
    }
    let mut inherited = [0u8; 4096];
    let read = read_one(parent, file, &mut inherited)?;
    let value = inherited.get(..read).unwrap_or(&[]).trim_ascii();
    if value.is_empty() {
        return Ok(());
    }
    write_one(child, file, value, false)
}
