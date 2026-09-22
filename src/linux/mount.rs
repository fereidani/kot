//! Establishing the container's mounts.
//!
//! Everything goes through the mount API introduced in Linux 5.2 and extended
//! in 5.12: `fsopen` and `fsmount` for a new superblock, `open_tree` for a
//! bind source, `move_mount` to attach, and `mount_setattr` for flags and id
//! mappings. The older `mount(2)` path is kept for hosts without it, selected
//! once by a probe rather than per mount.
//!
//! Destinations are resolved with `openat2` under `RESOLVE_BENEATH` and
//! `RESOLVE_NO_MAGICLINKS`, relative to a descriptor for the container's
//! root, so the kernel does the confinement and there is no window between
//! checking a path and using it. That is the whole of the defence against the
//! symlink and mount races that have been the recurring bug class here, and
//! it is why the older `mount(2)` path above is a fallback for the mount API
//! alone: `openat2` is required either way.

use core::ffi::CStr;
use std::{
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    sync::atomic::{AtomicU8, Ordering},
};

use crate::{
    linux::copyup,
    oci::plan::{
        Container, View,
        record::{MountKind, MountOp, mount_flag},
    },
    sys::{
        error::{
            Context, EACCES, EINVAL, ENOENT, ENOSYS, ENOTDIR, EPERM, Error,
            Result,
        },
        mountattr::{self, MountAttr},
        path::{Path, PathBuf},
    },
};

/// Whether the kernel has the mount API. Zero means not yet probed.
static MOUNT_API: AtomicU8 = AtomicU8::new(0);

/// True when the kernel supports `fsopen` and friends.
///
/// Probed once by calling it, rather than by reading a version number. The
/// filesystem named has to be one the kernel has: an unknown name sends it
/// looking for a module, which costs milliseconds and a helper process.
pub fn has_mount_api() -> bool {
    match MOUNT_API.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let available = rustix::mount::fsopen(
        "tmpfs",
        rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC,
    )
    .is_ok();
    MOUNT_API.store(u8::from(!available) + 1, Ordering::Relaxed);
    available
}

/// Resolves paths inside the container root, reusing directory descriptors
/// for shared prefixes.
///
/// A stock configuration names sixteen paths under `/proc` and half a dozen
/// mounts and nodes under `/dev`. Every directory a walk passes through is
/// kept, so a later path that shares a prefix starts from the deepest
/// directory already open instead of from the root, and a directory asked for
/// twice costs one resolution. The descriptors are lent out, never copied, so
/// a hit costs no syscall at all.
pub struct Resolver {
    root: OwnedFd,
    /// Every directory resolved so far, under its normalised path.
    cache: Vec<(PathBuf<256>, OwnedFd)>,
}

impl Resolver {
    /// Opens the container root and prepares an empty cache.
    pub fn new(root: &CStr) -> Result<Self> {
        let root = open_directory(root, "mount: open container root")?;
        Ok(Self {
            root,
            cache: Vec::new(),
        })
    }

    /// The container root every path here is resolved against.
    pub fn root(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    /// Forgets the cached descriptor for `path` and everything under it.
    ///
    /// A descriptor names an inode, not a name, so once a mount lands on a
    /// directory the cached descriptor still refers to the directory that is
    /// now hidden underneath it. Anything resolved through it afterwards would
    /// silently reach the wrong filesystem, which is exactly the kind of
    /// mistake that looks like a missing file much later.
    pub fn invalidate(&mut self, path: &[u8]) {
        // A path too long to normalise was never cached either.
        let Ok(wanted) = normalise(path) else {
            return;
        };
        self.cache
            .retain(|(key, _)| !covers(wanted.as_bytes(), key.as_bytes()));
    }

    /// Opens a path inside the container, confined by the kernel.
    ///
    /// `create` says what to make when the path is not there: a mount
    /// destination has to exist before anything can be moved onto it, and
    /// whether it should be a directory or a file depends on what is being
    /// mounted rather than on the path itself.
    ///
    /// The descriptor is the caller's own. A directory destination is better
    /// asked for with [`Resolver::open_directory`], which lends the cached one
    /// instead of copying it.
    pub fn open(&mut self, path: &[u8], create: Create) -> Result<OwnedFd> {
        if create == Create::Directories || path.last() == Some(&b'/') {
            let directory = self.open_directory(path, create)?;
            return rustix::io::dup(directory)
                .context("mount: duplicate directory");
        }
        let Some((directory, name)) = crate::sys::path::split_last(path) else {
            return Self::open_in(self.root.as_fd(), path, create);
        };
        let parent_mode = if create == Create::File {
            Create::Directories
        } else {
            Create::Nothing
        };
        let parent = self.open_directory(directory, parent_mode)?;
        Self::open_in(parent, name, create)
    }

    /// Opens a path inside the container without following a final symbolic
    /// link.
    ///
    /// The parent is resolved the usual confined way; only the last component
    /// is left unresolved, so the descriptor names the link and a mount moved
    /// onto it covers the link rather than its target. Nothing is created: a
    /// destination asked for this way is one the image already ships.
    pub fn open_nofollow(&mut self, path: &[u8]) -> Result<OwnedFd> {
        let Some((directory, name)) = crate::sys::path::split_last(path) else {
            let mut name = PathBuf::<256>::new();
            name.push_bytes(path)?;
            return open_component_as(
                self.root.as_fd(),
                name.as_c_str(),
                false,
                true,
            );
        };
        let parent = self.open_directory(directory, Create::Nothing)?;
        let mut name_buf = PathBuf::<256>::new();
        name_buf.push_bytes(name)?;
        open_component_as(parent, name_buf.as_c_str(), false, true)
    }

    /// Opens a directory, creating it and its parents when asked, and keeps
    /// every directory the walk passed through for the walks after it.
    ///
    /// The descriptor stays owned by the cache, so a repeat of a prefix costs
    /// nothing. Anything that changes what a path names has to call
    /// [`Resolver::invalidate`] afterwards.
    pub fn open_directory(
        &mut self,
        path: &[u8],
        create: Create,
    ) -> Result<BorrowedFd<'_>> {
        let wanted = normalise(path)?;
        let wanted = wanted.as_bytes();

        // The walk starts from the deepest directory already open on the way.
        let mut at = None;
        let mut covered = 1usize;
        for (index, (key, _)) in self.cache.iter().enumerate() {
            let key = key.as_bytes();
            if key.len() >= covered && covers(key, wanted) {
                at = Some(index);
                covered = key.len();
            }
        }

        let mut key = match at.and_then(|index| self.cache.get(index)) {
            Some((key, _)) => key.clone(),
            None => PathBuf::from(b"/")?,
        };
        let rest = wanted.get(covered..).unwrap_or(&[]);
        for component in crate::sys::path::components(rest) {
            let parent = self.directory_at(at);
            let mut name = PathBuf::<256>::new();
            name.push_bytes(component)?;
            // Opened before anything is made: nearly every directory a
            // bundle mounts on is one the image ships, and making it first
            // would be a refused call for each of them.
            let opened = match open_component(parent, name.as_c_str(), true) {
                Ok(opened) => opened,
                Err(e)
                    if create == Create::Directories && e.errno() == ENOENT =>
                {
                    create_at(
                        parent,
                        name.as_c_str(),
                        Create::Directories,
                        "mount: create directory",
                    )?;
                    open_component(parent, name.as_c_str(), true)?
                }
                Err(e) => return Err(e),
            };
            key.join(component)?;
            self.cache.push((key.clone(), opened));
            at = Some(self.cache.len() - 1);
        }
        Ok(self.directory_at(at))
    }

    /// The cached directory at `at`, or the root when there is none.
    ///
    /// An index the cache does not have is answered with the root, which
    /// resolves every path correctly and merely does so from further up.
    fn directory_at(&self, at: Option<usize>) -> BorrowedFd<'_> {
        at.and_then(|index| self.cache.get(index))
            .map_or(self.root.as_fd(), |(_, fd)| fd.as_fd())
    }

    fn open_in(
        parent: BorrowedFd<'_>,
        name: &[u8],
        create: Create,
    ) -> Result<OwnedFd> {
        let mut path = PathBuf::<256>::new();
        path.push_bytes(name)?;
        // As for a directory: what the image ships is opened, and only a
        // name it lacks is made.
        match open_component(parent, path.as_c_str(), false) {
            Err(e) if create == Create::File && e.errno() == ENOENT => {
                create_at(
                    parent,
                    path.as_c_str(),
                    Create::File,
                    "mount: create file",
                )?;
                open_component(parent, path.as_c_str(), false)
            }
            opened => opened,
        }
    }
}

/// What to create along the way when a path does not exist.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Create {
    /// Fail when something is missing.
    Nothing,
    /// Create missing directories.
    Directories,
    /// Create missing directories and an empty file at the end.
    File,
}

/// The one spelling of a path the cache is keyed by: absolute, with single
/// separators and no trailing one.
fn normalise(path: &[u8]) -> Result<PathBuf<256>> {
    let mut out = PathBuf::from(b"/")?;
    for component in crate::sys::path::components(path) {
        out.join(component)?;
    }
    Ok(out)
}

/// True when `prefix` names `path` itself or a directory above it.
///
/// Both are normalised, so a component boundary is exactly a separator.
fn covers(prefix: &[u8], path: &[u8]) -> bool {
    prefix == path
        || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
}

/// Applies the propagation mode a mount's options asked for.
///
/// A mount inherits its parent's mode unless the configuration names one, and
/// the whole tree is made private before any of this runs, so this only has
/// work to do when a mount asks to be shared, a slave, or unbindable.
fn propagate(
    plan: &View<'_>,
    resolver: &mut Resolver,
    op: &MountOp,
) -> Result<()> {
    use crate::oci::lower::tables::ms;

    let mode = op.propagation & !ms::REC;
    if mode == 0 {
        return Ok(());
    }
    let target = plan.raw(op.target)?;
    let destination = resolver.open(target, Create::Nothing)?;
    let attr = MountAttr {
        propagation: mode,
        ..MountAttr::default()
    };
    mountattr::mount_setattr_fd(
        destination.as_fd(),
        op.propagation & ms::REC != 0,
        &attr,
    )
    .map_err(|e| e.describe("mount: set propagation"))
}

/// Filesystems the kernel generates the contents of, by the number `statfs`
/// reports for each.
///
/// Every entry on one of these is a window onto something the kernel owns: a
/// process, a device, a control group, a policy. None of them holds a file the
/// configuration put there, so a mount landing on one is covering a name the
/// kernel means to answer for itself.
const KERNEL_OWNED: [i64; 14] = [
    0x0000_9fa0,           // proc
    0x6265_6572,           // sysfs
    0x0000_1cd1,           // devpts
    0x0027_e0eb,           // cgroup
    0x6367_7270,           // cgroup2
    0xcafe_4a11u32 as i64, // bpf
    0x7472_6163,           // tracefs
    0x6462_6720,           // debugfs
    0x7363_6673,           // securityfs
    0xf97c_ff8cu32 as i64, // selinuxfs
    0x6165_676c,           // pstore
    0x4249_4e4d,           // binfmt_misc
    0x6e73_6673,           // nsfs
    0xde5e_81e4u32 as i64, // efivarfs
];

/// Refuses a destination the kernel answers for, when it is not being
/// followed.
///
/// Following a link puts the mount wherever the link leads, which the
/// confinement already bounds. Not following it puts the mount on the link
/// itself, and on a filesystem the kernel generates that means shadowing an
/// entry the kernel expects to resolve: a process's own view of itself, a
/// control group's membership file, the interface a policy is read through.
/// The list is wider than the three filesystems a container usually reaches,
/// because the cost of refusing one of these is a configuration that has to
/// say what it means, and the cost of allowing one is not bounded at all.
fn refuse_kernel_owned_destination(destination: BorrowedFd<'_>) -> Result<()> {
    let stat = rustix::fs::fstatfs(destination)
        .context("mount: inspect the destination filesystem")?;
    let kind = stat.f_type;
    if KERNEL_OWNED.contains(&kind) {
        return Err(Error::msg(
            "mount: the kernel answers for this destination, so it may not \
             be covered unfollowed",
        ));
    }
    Ok(())
}

/// True when a bind source is a symbolic link rather than what it points at.
fn source_is_symlink(source: &CStr) -> bool {
    use rustix::fs::{AtFlags, FileType, statat};
    statat(rustix::fs::CWD, source, AtFlags::SYMLINK_NOFOLLOW).is_ok_and(
        |stat| FileType::from_raw_mode(stat.st_mode) == FileType::Symlink,
    )
}

/// True when a bind source is something other than a directory.
fn source_is_file(source: &CStr) -> bool {
    use rustix::fs::{AtFlags, FileType, statat};
    statat(rustix::fs::CWD, source, AtFlags::empty()).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    })
}

/// Opens one path component, confined to the directory it is relative to.
fn open_component(
    parent: BorrowedFd<'_>,
    name: &CStr,
    directory: bool,
) -> Result<OwnedFd> {
    open_component_as(parent, name, directory, false)
}

/// The same, optionally stopping at a symbolic link instead of following it.
///
/// With `nofollow` the descriptor names the link itself, which is what a mount
/// onto a link destination has to be moved onto.
fn open_component_as(
    parent: BorrowedFd<'_>,
    name: &CStr,
    directory: bool,
    nofollow: bool,
) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    let mut flags = OFlags::PATH | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    if nofollow {
        flags |= OFlags::NOFOLLOW;
    }
    openat2(
        parent,
        name,
        flags,
        Mode::empty(),
        // The kernel enforces the confinement, so there is no window between
        // resolving a path and using it for a container to widen.
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .context("mount: resolve path")
}

/// Treats a target that is already there as success.
///
/// Everything created here is a mount point being prepared, so a path the
/// image already ships is the wanted outcome rather than a conflict.
// Taken by value because the point is to consume the result and discard
// whatever the call produced; a reference would leave the caller holding a
// value it has already decided it does not want.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn ok_if_exists<T>(
    result: rustix::io::Result<T>,
    context: &'static str,
) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == crate::sys::error::EEXIST => Ok(()),
        Err(e) => Err(Error::from(e).describe(context)),
    }
}

/// Creates a missing path component unless the image provides one.
pub(crate) fn create_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    create: Create,
    context: &'static str,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};
    let made = match create {
        Create::Nothing => return Ok(()),
        Create::Directories => {
            mkdirat(parent, name, Mode::from_raw_mode(0o755))
        }
        // The final component is the one part of this path the image
        // controls: everything above it was resolved under `RESOLVE_BENEATH`
        // already. Without `O_NOFOLLOW` a symlink the image leaves there is
        // followed, and the file prepared as a mount destination is created
        // wherever it points, outside the container's root and with the
        // runtime's privileges rather than the container's.
        Create::File => openat(
            parent,
            name,
            OFlags::CREATE
                | OFlags::WRONLY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map(|_| ()),
    };
    // A destination that is already a symbolic link fails the open above
    // rather than being followed, and it is worth saying which of the two
    // things went wrong.
    if let Err(e) = &made {
        if e.raw_os_error() == crate::sys::error::ELOOP {
            return Err(Error::msg(
                "mount: the destination in the image is a symbolic link",
            ));
        }
    }
    ok_if_exists(made, context)
}

/// Opens a directory as a descriptor, for later confined resolution.
pub(crate) fn open_directory(
    path: &CStr,
    context: &'static str,
) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags};

    rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context(context)
}

/// Clones a mount tree named by a path.
pub(crate) fn clone_path(
    source: &CStr,
    recursive: bool,
    nofollow: bool,
    context: &'static str,
) -> Result<OwnedFd> {
    use rustix::mount::{OpenTreeFlags, open_tree};

    let mut flags =
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC;
    if recursive {
        flags |= OpenTreeFlags::AT_RECURSIVE;
    }
    if nofollow {
        flags |= OpenTreeFlags::AT_SYMLINK_NOFOLLOW;
    }
    open_tree(rustix::fs::CWD, source, flags).context(context)
}

/// `OPEN_TREE_NAMESPACE`: put the cloned tree in a mount namespace of its
/// own. Newer than the flags rustix names, so spelled out here.
const OPEN_TREE_NAMESPACE: u32 = 1 << 1;

/// Clones the rootfs into a mount namespace holding nothing else.
///
/// A mount namespace made at the clone starts as a copy of the host's whole
/// tree, which init then has to sever from the host, pivot out of and
/// detach, and which the kernel takes apart again when the container exits.
/// One made here holds the rootfs alone: init enters it and the container's
/// root is the root. Answers `None` on a kernel without the flag, and for a
/// runtime the kernel refuses, so the caller can build the namespace the
/// older way.
pub fn tree_namespace(rootfs: &CStr) -> Result<Option<OwnedFd>> {
    use rustix::mount::{OpenTreeFlags, open_tree};

    let flags = OpenTreeFlags::from_bits_retain(OPEN_TREE_NAMESPACE)
        | OpenTreeFlags::OPEN_TREE_CLOEXEC
        | OpenTreeFlags::AT_RECURSIVE;
    match open_tree(rustix::fs::CWD, rootfs, flags) {
        Ok(tree) => Ok(Some(tree)),
        // A kernel without the flag refuses it as invalid, and one without
        // the interface at all has no such call.
        Err(e) if matches!(e.raw_os_error(), EINVAL | ENOSYS | EPERM) => {
            Ok(None)
        }
        Err(e) => Err(Error::from(e)
            .describe("mount: clone the rootfs into a namespace of its own")),
    }
}

/// Makes every mount's detached object while the host is still reachable.
///
/// Sources are paths on the host, and the newer interface resolves them when
/// the object is made rather than when it is attached. Once init is in a
/// namespace holding the rootfs alone, no host path resolves, so each mount
/// is made here and attached there. A cgroup filesystem is the exception:
/// its superblock is rooted in the cgroup namespace of whoever makes it,
/// which init makes only once the driver has settled the cgroup, and it
/// needs nothing from the host.
///
/// A tree cloned out of the host's namespace is still a peer of the mount it
/// came from, so a mount the container later makes beneath it would appear
/// on the host. It is given what the copied tree of the older path is given
/// before any source is taken from it: the mode the configuration named for
/// the root, or private.
pub fn make_ahead(
    plan: &View<'_>,
    container: &Container,
    socket: BorrowedFd<'_>,
    cgroup_joined: &core::cell::Cell<bool>,
    out: &mut Vec<Made>,
) -> Result<()> {
    use crate::oci::lower::tables::ms;

    let (propagation, recursive) = if container.rootfs_propagation == 0 {
        (ms::PRIVATE, true)
    } else {
        (
            container.rootfs_propagation & !ms::REC,
            container.rootfs_propagation & ms::REC != 0,
        )
    };
    let sever = MountAttr {
        propagation,
        ..MountAttr::default()
    };
    out.clear();
    let mut index = 0i32;
    plan.mounts(|op| {
        let at = Source {
            index,
            socket,
            cgroup_joined,
            in_user_namespace: false,
            ahead: Ahead::Reachable,
        };
        index += 1;
        let kind = op.mount_kind().ok_or_else(|| {
            Error::msg("mount: unknown kind from a foreign plan")
        })?;
        let made = match kind {
            MountKind::Filesystem if is_cgroup(plan.text(op.fstype)?) => {
                Ok(Made::Later)
            }
            MountKind::Filesystem => {
                create_filesystem(plan, &op).map(Made::Mount)
            }
            MountKind::Bind | MountKind::RecursiveBind => {
                open_bind(plan, &op, at, kind == MountKind::RecursiveBind)
                    .and_then(|(tree, _)| {
                        mountattr::mount_setattr_fd(
                            tree.as_fd(),
                            recursive,
                            &sever,
                        )
                        .map_err(|e| e.describe("mount: sever a source"))?;
                        Ok(Made::Mount(tree))
                    })
            }
            MountKind::MaskFile | MountKind::MaskDirectory => Ok(Made::Later),
        };
        match made {
            Ok(made) => out.push(made),
            // The same allowance `establish` makes: a source the
            // configuration said may be absent is one to skip, not one
            // to refuse the container over.
            Err(_) if op.extra & mount_flag::OPTIONAL != 0 => {
                out.push(Made::Skipped);
            }
            Err(e) => return Err(e),
        }
        Ok(())
    })
}

/// What was made for a mount ahead of the change of mount namespace.
pub enum Made {
    /// Nothing yet: the mount is made in place, needing nothing of the host.
    Later,
    /// The detached mount or tree.
    Mount(OwnedFd),
    /// The source was absent and the configuration allowed for that.
    Skipped,
}

impl Made {
    /// What the mount itself is told.
    #[must_use]
    pub fn ahead(&self) -> Ahead<'_> {
        match self {
            Self::Later => Ahead::Later,
            Self::Mount(fd) => Ahead::Made(fd.as_fd()),
            Self::Skipped => Ahead::Skipped,
        }
    }
}

/// What a mount finds made for it, and whether the host is still in reach.
#[derive(Clone, Copy)]
pub enum Ahead<'a> {
    /// Nothing, and the host is reachable: the mount makes its own.
    Reachable,
    /// Nothing, and the host is out of reach: the mount is one that needs
    /// nothing from it.
    Later,
    /// The detached mount or tree, made while the host was reachable.
    Made(BorrowedFd<'a>),
    /// Nothing, because the source was absent and allowed to be.
    Skipped,
}

/// A detached mount, whichever side owns it.
enum Detached<'a> {
    Owned(OwnedFd),
    Borrowed(BorrowedFd<'a>),
}

impl Detached<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Owned(fd) => fd.as_fd(),
            Self::Borrowed(fd) => *fd,
        }
    }
}

/// Clones a bind source out of the host's tree, and says whether the driver
/// did it and mapped it on the way.
///
/// A mount this process cannot map is asked for before it is opened, not
/// after a failure that leaves one half made. One the container's root
/// cannot reach at all is asked for too: the identity the runtime was
/// started with still may, and that one is the driver's.
fn open_bind(
    plan: &View<'_>,
    op: &MountOp,
    at: Source<'_>,
    recursive: bool,
) -> Result<(OwnedFd, bool)> {
    let mapped_elsewhere = op.idmap_fd >= 0 && at.in_user_namespace;
    if mapped_elsewhere {
        return Ok((request_source(at)?, true));
    }
    let source = plan.c_str(op.source)?;
    let nofollow = op.extra & mount_flag::SRC_NOFOLLOW != 0;
    match clone_path(source, recursive, nofollow, "mount: clone source tree") {
        Ok(tree) => Ok((tree, false)),
        Err(e) if matches!(e.errno(), EACCES | EPERM) => {
            Ok((request_source(at)?, false))
        }
        Err(e) => Err(e),
    }
}

/// True when a detached tree is rooted at something other than a directory.
fn tree_is_file(tree: BorrowedFd<'_>) -> bool {
    use rustix::fs::{FileType, fstat};
    fstat(tree).is_ok_and(|stat| {
        FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    })
}

/// Makes the superblock and the detached mount a filesystem mount asks for.
fn create_filesystem(plan: &View<'_>, op: &MountOp) -> Result<OwnedFd> {
    use rustix::mount::{
        FsMountFlags, FsOpenFlags, fsconfig_create, fsconfig_set_flag,
        fsconfig_set_string, fsmount, fsopen,
    };

    let fstype = plan.text(op.fstype)?;
    let data = plan.text(op.data)?;
    let source = plan.text(op.source)?;

    let fs = fsopen(fstype, FsOpenFlags::FSOPEN_CLOEXEC)
        .context("mount: open filesystem")?;
    if !source.is_empty() && fstype != "tmpfs" {
        fsconfig_set_string(fs.as_fd(), "source", source)
            .context("mount: set source")?;
    }
    for option in data.split(',').filter(|o| !o.is_empty()) {
        // An option without a value is a flag, and a filesystem that
        // expects one rejects it outright if it arrives as a string with
        // an empty value. `devpts` and `newinstance` are the pair every
        // bundle hits.
        let Some((key, value)) = option.split_once('=') else {
            fsconfig_set_flag(fs.as_fd(), option).context("mount: set flag")?;
            continue;
        };
        fsconfig_set_string(fs.as_fd(), key, value)
            .context("mount: set option")?;
    }
    // The label is set as its own option rather than through `data`,
    // which is split on commas that an MCS label carries itself.
    let context = plan.text(op.context)?;
    if !context.is_empty() {
        fsconfig_set_string(fs.as_fd(), "context", context)
            .context("mount: set selinux context")?;
    }
    fsconfig_create(fs.as_fd()).context("mount: create superblock")?;

    // `fsmount` takes every attribute a new mount can carry, so the only
    // thing left for `mount_setattr` is an id mapping. A fresh superblock
    // has no attributes to clear, which is why the plan's clear set plays
    // no part here.
    let attrs = attr_flags(op.attr_set);
    fsmount(fs.as_fd(), FsMountFlags::FSMOUNT_CLOEXEC, attrs)
        .context("mount: materialise")
}

/// Asks the driver to open a mount's source and hand it over.
fn request_source(at: Source<'_>) -> Result<OwnedFd> {
    use crate::linux::sync::{self, Kind, Message};

    let request = Message::with_pid(Kind::OpenSource, at.index);
    sync::send(at.socket, &request)?;
    // Two, because the driver's word about the cgroup is sent when it
    // becomes true and can land between this request and its answer.
    // Whoever waits for it later finds it already in hand.
    for _ in 0..2 {
        let (message, source) = sync::receive_fd(at.socket)?;
        match message.kind {
            Kind::SourceOpened => {
                return source.ok_or_else(|| {
                    Error::msg("mount: the source carried no mount")
                });
            }
            Kind::CgroupJoined => at.cgroup_joined.set(true),
            _ => return Err(Error::msg("mount: the driver sent no source")),
        }
    }
    Err(Error::msg("mount: the driver sent no source"))
}

/// True for either cgroup filesystem.
fn is_cgroup(fstype: &str) -> bool {
    matches!(fstype, "cgroup" | "cgroup2")
}

/// Establishes one mount.
pub fn establish(
    plan: &View<'_>,
    resolver: &mut Resolver,
    op: &MountOp,
    idmap: Option<BorrowedFd<'_>>,
    at: Source<'_>,
) -> Result<()> {
    let kind = op
        .mount_kind()
        .ok_or_else(|| Error::msg("mount: unknown kind from a foreign plan"))?;
    let target = plan.raw(op.target)?;
    let mut mount = Mount {
        plan,
        resolver,
        op,
        kind,
        target,
        idmap,
        at,
    };
    let outcome = match kind {
        MountKind::MaskFile | MountKind::MaskDirectory => {
            Err(Error::msg("mount: masked paths are applied separately"))
        }
        // The probe decides once, for every mount, which interface is used.
        _ if !has_mount_api() => mount.legacy(),
        MountKind::Filesystem => mount.filesystem(),
        MountKind::Bind | MountKind::RecursiveBind => {
            mount.bind(kind == MountKind::RecursiveBind)
        }
    };

    let outcome = outcome.and_then(|()| {
        // The propagation mode goes on after the mount is in place: a mount
        // still detached from the tree has no peers to share with, and the
        // kernel refuses to make one shared.
        propagate(plan, resolver, op)
    });

    match outcome {
        Ok(()) => Ok(()),
        // A mount the configuration marked optional is one whose source may
        // legitimately be absent, such as a cgroup hierarchy the host does not
        // have. Refusing to start for that would be wrong.
        Err(_) if op.extra & mount_flag::OPTIONAL != 0 => Ok(()),
        Err(e) => Err(e),
    }
}

/// One mount being established.
///
/// The fields are what every step of establishing a mount needs, and they
/// travel together from the first path resolution to the final `move_mount`.
struct Mount<'a> {
    plan: &'a View<'a>,
    resolver: &'a mut Resolver,
    op: &'a MountOp,
    kind: MountKind,
    target: &'a [u8],
    idmap: Option<BorrowedFd<'a>>,
    at: Source<'a>,
}

/// What the image has at a mount's destination.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Existing {
    Directory,
    File,
    Nothing,
}

/// Where this mount sits in the plan, and who to ask for its source.
///
/// A bind source is a path on the host, which init reaches as the
/// container's root rather than as the runtime's own user. One that only
/// the runtime's user can reach is still the caller's to mount, so the
/// driver opens it and sends it over.
#[derive(Clone, Copy)]
pub struct Source<'a> {
    /// The mount's position in the plan, which names it to the driver.
    pub index: i32,
    /// The socket the driver is listening on.
    pub socket: BorrowedFd<'a>,
    /// Set when the driver's word that the container is in its cgroup has
    /// arrived. The driver sends it as soon as it is true, so it can land
    /// in the middle of anything else.
    pub cgroup_joined: &'a core::cell::Cell<bool>,
    /// True when this process is in a user namespace of the container's.
    ///
    /// Mapping a mount is a privilege over the source's filesystem, which
    /// such a namespace does not hold, so the driver does those.
    pub in_user_namespace: bool,
    /// What was made for this mount before the host went out of reach, if
    /// it did.
    pub ahead: Ahead<'a>,
}

impl Mount<'_> {
    /// Mounts a new superblock of the filesystem the plan names.
    fn filesystem(&mut self) -> Result<()> {
        let mount = match self.at.ahead {
            Ahead::Made(mount) => Detached::Borrowed(mount),
            Ahead::Skipped => return Ok(()),
            reach @ (Ahead::Reachable | Ahead::Later) => {
                match create_filesystem(self.plan, self.op) {
                    Ok(mount) => Detached::Owned(mount),
                    // A fresh cgroup superblock needs privilege in the user
                    // namespace that owns the cgroup namespace the mounter
                    // is in, so a container in a user namespace of its own
                    // that kept the host's cgroup namespace cannot have
                    // one. What it can have is the tree the host already
                    // mounted, under the flags the plan asked for, as long
                    // as the host's tree is still there to be reached.
                    Err(e)
                        if e.errno() == EPERM
                            && matches!(reach, Ahead::Reachable)
                            && is_cgroup(self.plan.text(self.op.fstype)?) =>
                    {
                        return self.bind_host_cgroups();
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        let mount = mount.as_fd();
        if let Some(userns) = self.idmap {
            let attr = MountAttr::default().idmap(userns);
            mountattr::mount_setattr_fd(mount, false, &attr)?;
        }
        if self.op.extra & mount_flag::TMPCOPYUP != 0 {
            self.copy_up(mount)?;
        }
        self.attach(mount)
    }

    /// Attaches the host's cgroup tree in place of a superblock the kernel
    /// refuses to create.
    ///
    /// Recursive, because the unified hierarchy carries its controllers in
    /// mounts below the root. The plan's attributes still apply, so a
    /// read-only cgroup mount stays read only.
    fn bind_host_cgroups(&mut self) -> Result<()> {
        let source = self.host_cgroup_path()?;
        let tree = clone_path(
            source.as_c_str(),
            true,
            false,
            "mount: clone the host cgroup tree",
        )?;
        self.apply_attributes(tree.as_fd(), true)?;
        self.attach(tree.as_fd())
    }

    /// Where the host keeps the tree this mount asked for.
    ///
    /// The unified hierarchy is one filesystem at a fixed place; a version
    /// one hierarchy is one per controller, named after it, which the
    /// destination's last component names as well.
    fn host_cgroup_path(&self) -> Result<PathBuf<256>> {
        const ROOT: &[u8] = b"/sys/fs/cgroup";

        let mut path = PathBuf::<256>::new();
        path.push_bytes(ROOT)?;
        if self.plan.text(self.op.fstype)? == "cgroup2" {
            return Ok(path);
        }
        let controller = crate::sys::path::split_last(self.target)
            .map_or(self.target, |(_, name)| name);
        if controller.is_empty() {
            return Err(Error::msg("mount: cgroup mount names no controller"));
        }
        path.push_bytes(b"/")?;
        path.push_bytes(controller)?;
        Ok(path)
    }

    /// Carries what the destination already holds into the new filesystem.
    ///
    /// The copy goes into the mount while it is still detached, because once
    /// it is attached the original is underneath it and out of reach. A
    /// destination that is not there yet has nothing to carry over.
    fn copy_up(&mut self, mount: BorrowedFd<'_>) -> Result<()> {
        use rustix::fs::{Mode, OFlags, openat};

        let existing =
            match self.resolver.open_directory(self.target, Create::Nothing) {
                Ok(directory) => openat(
                    directory,
                    c".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .context("mount: open the directory to copy up")?,
                Err(e) if e.is_not_found() => return Ok(()),
                Err(e) => return Err(e),
            };
        copyup::tree(existing.as_fd(), mount)
    }

    /// Recreates a symbolic link source at the destination.
    ///
    /// A bind of a link would have to resolve it, which puts whatever it
    /// points at into the container under the link's name. `copy-symlink`
    /// asks for the link instead, so nothing is mounted at all and the
    /// container gets a link of its own with the same target.
    fn copy_symlink(&mut self, source: &CStr) -> Result<()> {
        use rustix::fs::{readlinkat, symlinkat};

        let mut target = PathBuf::<{ crate::sys::path::PATH_MAX }>::new();
        let mut buffer = [0u8; crate::sys::path::PATH_MAX];
        let read = readlinkat(rustix::fs::CWD, source, &mut buffer[..])
            .context("mount: read symbolic link source")?;
        target.push_bytes(read.to_bytes())?;

        let Some((directory, name)) = crate::sys::path::split_last(self.target)
        else {
            return Err(Error::msg("mount: destination has no name"));
        };
        let parent = self
            .resolver
            .open_directory(directory, Create::Directories)?;
        let mut name_buf = PathBuf::<256>::new();
        name_buf.push_bytes(name)?;
        match symlinkat(target.as_c_str(), parent, name_buf.as_c_str()) {
            Ok(()) => Ok(()),
            // Something is there already. A link to the same place is the
            // outcome that was wanted and nothing needs doing. Anything else
            // is a destination the container asked for and would not get, so
            // it is reported rather than left as it stands.
            Err(e) if e.raw_os_error() == crate::sys::error::EEXIST => {
                let found =
                    readlinkat(parent, name_buf.as_c_str(), &mut buffer[..])
                        .map_err(|_| {
                            Error::msg("mount: the destination is not a link")
                        })?;
                if found.to_bytes() == target.as_bytes() {
                    Ok(())
                } else {
                    Err(Error::msg("mount: the destination is another link"))
                }
            }
            Err(e) => {
                Err(Error::from(e).describe("mount: create symbolic link"))
            }
        }
    }

    /// Clones the source out of the host's mount tree and attaches it.
    fn bind(&mut self, recursive: bool) -> Result<()> {
        let (tree, mapped) = match self.at.ahead {
            // Mapped by init itself, since a tree is made ahead only where
            // there is no user namespace to put the driver in charge of it.
            Ahead::Made(tree) => (Detached::Borrowed(tree), false),
            Ahead::Skipped => return Ok(()),
            // A source is a path on the host, and the host is gone: the
            // path would resolve inside the container and bind the wrong
            // thing under the right name.
            Ahead::Later => {
                return Err(Error::msg(
                    "mount: a bind source was not opened while the host \
                     was in reach",
                ));
            }
            Ahead::Reachable => {
                let source = self.plan.c_str(self.op.source)?;
                if self.op.extra & mount_flag::COPY_SYMLINK != 0
                    && source_is_symlink(source)
                {
                    return self.copy_symlink(source);
                }
                let (tree, mapped) =
                    open_bind(self.plan, self.op, self.at, recursive)?;
                (Detached::Owned(tree), mapped)
            }
        };
        self.apply_attributes(tree.as_fd(), !mapped)?;
        self.attach(tree.as_fd())
    }

    /// Applies flag and id-mapping changes to a detached mount.
    ///
    /// `map` is false for a mount the driver opened, which carries the
    /// mapping already. The kernel refuses a second one.
    fn apply_attributes(&self, mount: BorrowedFd<'_>, map: bool) -> Result<()> {
        let mut attr = MountAttr {
            attr_set: self.op.attr_set,
            attr_clr: self.op.attr_clr,
            propagation: 0,
            userns_fd: 0,
        };
        if let (true, Some(userns)) = (map, self.idmap) {
            attr = attr.idmap(userns);
        }
        if attr.is_empty() {
            return Ok(());
        }
        let recursive = self.op.extra & mount_flag::RECURSIVE != 0;
        mountattr::mount_setattr_fd(mount, recursive, &attr)
    }

    /// Looks at what the image has where this mount goes.
    ///
    /// A directory found here stays open in the resolver's cache, so the
    /// caller's own open of it costs nothing more.
    fn existing(&mut self) -> Result<Existing> {
        match self.resolver.open_directory(self.target, Create::Nothing) {
            Ok(_) => Ok(Existing::Directory),
            Err(e) if e.errno() == ENOENT => Ok(Existing::Nothing),
            // The last component is a file, or a component above it is;
            // the open of a file below tells the two apart.
            Err(e) if e.errno() == ENOTDIR => Ok(Existing::File),
            Err(e) => Err(e),
        }
    }

    /// Decides what to make where the image has nothing.
    ///
    /// A destination has to match what is being put on it: a bind of a file
    /// needs a file underneath, and a bind of a directory needs a directory.
    /// The configuration rarely says which, so the source decides. Asked
    /// only when something has to be made, since what the image ships is
    /// used as it is and the kernel refuses a mismatch in the move.
    fn wants_file(&self) -> Result<bool> {
        if self.op.extra & mount_flag::DEST_IS_FILE != 0 {
            return Ok(true);
        }
        if !matches!(self.kind, MountKind::Bind | MountKind::RecursiveBind) {
            return Ok(false);
        }
        match self.at.ahead {
            Ahead::Made(tree) => Ok(tree_is_file(tree)),
            _ => Ok(source_is_file(self.plan.c_str(self.op.source)?)),
        }
    }

    /// How to open the destination: what is there, or else what to make.
    fn creation(&mut self) -> Result<Create> {
        Ok(match self.existing()? {
            Existing::File => Create::Nothing,
            Existing::Nothing if self.wants_file()? => Create::File,
            Existing::Directory | Existing::Nothing => Create::Directories,
        })
    }

    /// Moves a detached mount to its destination inside the container.
    fn attach(&mut self, source: BorrowedFd<'_>) -> Result<()> {
        if self.op.extra & mount_flag::DEST_NOFOLLOW != 0 {
            let destination = self.resolver.open_nofollow(self.target)?;
            refuse_kernel_owned_destination(destination.as_fd())?;
            move_onto(source, destination.as_fd(), "mount: attach")?;
            self.resolver.invalidate(self.target);
            return Ok(());
        }
        match self.creation()? {
            Create::Directories => {
                let destination = self
                    .resolver
                    .open_directory(self.target, Create::Directories)?;
                move_onto(source, destination, "mount: attach")?;
            }
            create => {
                let destination = self.resolver.open(self.target, create)?;
                move_onto(source, destination.as_fd(), "mount: attach")?;
            }
        }
        // The destination now names a different filesystem, so anything
        // cached for it or below it refers to what is hidden underneath.
        self.resolver.invalidate(self.target);
        Ok(())
    }

    /// Establishes the mount through the older interface.
    ///
    /// Kept for kernels without the mount API. It resolves the destination the
    /// same way, so the confinement is the same; what it gives up is the
    /// ability to configure a mount before it is visible anywhere.
    fn legacy(&mut self) -> Result<()> {
        use rustix::mount::{MountFlags, mount};

        // `mount(2)` has nowhere to put a user namespace, so a mapping asked
        // for here cannot be honoured. Refusing says so; going ahead would
        // give the container the mount with every id unmapped.
        if self.idmap.is_some() {
            return Err(Error::msg(
                "mount: an id mapping needs the newer mount interface",
            ));
        }

        let create = self.creation()?;
        let destination = self.resolver.open(self.target, create)?;
        let mut path = PathBuf::<64>::new();
        path.push_str("/proc/self/fd/")?;
        path.push_u64(u64::from(destination.as_raw_fd().unsigned_abs()))?;

        let source = self.plan.c_str(self.op.source)?;
        let fstype = self.plan.c_str(self.op.fstype)?;
        let flags = MountFlags::from_bits_retain(
            u32::try_from(self.op.flags & 0xffff_ffff)
                .map_err(|_| Error::msg("mount: flags out of range"))?,
        );
        // This interface takes one option string, so the label joins the rest
        // of them. Quoted, because a label carries commas.
        let mut options = Path::new();
        options.push_bytes(self.plan.raw(self.op.data)?)?;
        let context = self.plan.raw(self.op.context)?;
        if !context.is_empty() {
            if !options.is_empty() {
                options.push_str(",")?;
            }
            options.push_str("context=\"")?;
            options.push_bytes(context)?;
            options.push_str("\"")?;
        }
        let data = if options.is_empty() {
            None
        } else {
            Some(options.as_c_str())
        };
        mount(source, path.as_c_str(), fstype, flags, data)
            .context("mount: legacy mount")
    }
}

/// Moves a detached mount onto an already-open destination.
///
/// Both ends are named by descriptor alone, so nothing is resolved by name
/// between opening the destination and mounting over it.
pub(crate) fn move_onto(
    source: BorrowedFd<'_>,
    destination: BorrowedFd<'_>,
    context: &'static str,
) -> Result<()> {
    use rustix::mount::{MoveMountFlags, move_mount};
    move_mount(
        source,
        "",
        destination,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
            | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .context(context)
}

/// Extracts the `MOUNT_ATTR_*` bits `fsmount` takes directly.
///
/// That is every attribute except the id mapping: the read-only, no-suid,
/// no-dev and no-exec bits, the access-time mode, and symbolic-link
/// following. Relative access time is the mode a new mount has when no other
/// is named, so it has no bit of its own.
fn attr_flags(attr_set: u64) -> rustix::mount::MountAttrFlags {
    use rustix::mount::MountAttrFlags as Attr;

    const PAIRS: [(u64, Attr); 8] = [
        (mountattr::ATTR_RDONLY, Attr::MOUNT_ATTR_RDONLY),
        (mountattr::ATTR_NOSUID, Attr::MOUNT_ATTR_NOSUID),
        (mountattr::ATTR_NODEV, Attr::MOUNT_ATTR_NODEV),
        (mountattr::ATTR_NOEXEC, Attr::MOUNT_ATTR_NOEXEC),
        (mountattr::ATTR_NOATIME, Attr::MOUNT_ATTR_NOATIME),
        (mountattr::ATTR_STRICTATIME, Attr::MOUNT_ATTR_STRICTATIME),
        (mountattr::ATTR_NODIRATIME, Attr::MOUNT_ATTR_NODIRATIME),
        (mountattr::ATTR_NOSYMFOLLOW, Attr::MOUNT_ATTR_NOSYMFOLLOW),
    ];

    let mut flags = Attr::empty();
    for (bit, flag) in PAIRS {
        if attr_set & bit != 0 {
            flags |= flag;
        }
    }
    flags
}
