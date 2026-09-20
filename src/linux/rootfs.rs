//! Building the container's filesystem view.
//!
//! The order here is not arbitrary and is worth stating once, because getting
//! it wrong produces a container that looks configured and is not:
//!
//! 1. Make the propagation of the whole tree private, so nothing the container
//!    mounts escapes into the host.
//! 2. Make the root a mount point in its own right, which `pivot_root` requires
//!    and which most bundles do not arrange themselves.
//! 3. Establish the configured mounts, in the order the configuration gave.
//! 4. Create the device nodes, including the ones the specification requires
//!    whether or not the bundle asked for them.
//! 5. Change root.
//! 6. Apply the masked and read-only paths, which name paths inside the new
//!    root and so can only be done now.
//! 7. Make the root itself read only, last, so that everything above could
//!    still write to it.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::{
    linux::mount::{
        Create, Resolver, clone_path, create_at, move_onto, ok_if_exists,
        open_directory,
    },
    oci::plan::{
        Container, Section, View,
        record::{DeviceOp, PathAction},
    },
    sys::{
        error::{Context, Error, Result},
        mountattr::{self, MountAttr},
        path::PathBuf,
    },
};

/// Clears the file creation mask for as long as it is held.
///
/// `mknod` takes the mask out of the mode it is given, so a device the
/// configuration asked to be 0666 arrives as 0644 under the usual 022. The
/// previous mask is put back on the way out, because the payload inherits it
/// and a container whose umask depended on how its devices were made would be
/// a surprising thing to debug.
struct NoUmask(rustix::fs::Mode);

impl NoUmask {
    fn enter() -> Self {
        Self(rustix::process::umask(rustix::fs::Mode::empty()))
    }
}

impl Drop for NoUmask {
    fn drop(&mut self) {
        let _ = rustix::process::umask(self.0);
    }
}

/// Symbolic links every container is expected to have under `/dev`.
///
/// Programs assume these exist, and a container without them fails in ways
/// that look like anything but a missing link.
const DEV_SYMLINKS: [(&str, &str); 4] = [
    ("/proc/self/fd", "/dev/fd"),
    ("/proc/self/fd/0", "/dev/stdin"),
    ("/proc/self/fd/1", "/dev/stdout"),
    ("/proc/self/fd/2", "/dev/stderr"),
];

/// Makes the mount tree private and turns the root into a mount point.
pub fn prepare(container: &Container, plan: &View<'_>) -> Result<()> {
    use rustix::mount::{MountFlags, MountPropagationFlags, mount_change};

    // Without this, a mount the container makes could propagate back into the
    // host's tree, which is the difference between an isolated filesystem and
    // a shared one.
    let propagation = if container.rootfs_propagation == 0 {
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC
    } else {
        propagation_flags(container.rootfs_propagation)
    };
    mount_change("/", propagation).context("rootfs: set propagation")?;

    // `pivot_root` refuses a new root that is not itself a mount point, and a
    // bundle's rootfs is usually a plain directory.
    let root = plan.c_str(container.rootfs)?;
    rustix::mount::mount(
        root,
        root,
        "",
        MountFlags::BIND | MountFlags::REC,
        None,
    )
    .context("rootfs: bind root onto itself")?;

    // A bind mount keeps the source mount's flags, so a bundle sitting on a
    // `nosuid,nodev` filesystem would give the container a root with those
    // set and one sitting elsewhere would not. That makes an image's setuid
    // binaries work or not work depending on where the bundle happens to be
    // unpacked, which is not something a caller can reason about. The flags
    // are cleared so that the root is the same either way.
    //
    // Best effort: in an unprivileged user namespace these flags are locked
    // and the kernel refuses to clear them. That is the one case where the
    // container has to live with what it inherited, and it is also the case
    // where the restriction is there on purpose.
    let relax = MountAttr::default()
        .clear(mountattr::ATTR_NOSUID | mountattr::ATTR_NODEV);
    let _ = mountattr::mount_setattr(rustix::fs::CWD, root, 0, &relax);
    Ok(())
}

/// Creates the device nodes and the links that go with them.
pub fn create_devices(plan: &View<'_>, resolver: &mut Resolver) -> Result<()> {
    let _mask = NoUmask::enter();
    plan.devices(|device| create_device(plan, resolver, &device))?;

    for (target, link) in DEV_SYMLINKS {
        link_at(resolver, target, link)?;
    }
    // `/dev/core` is not in the specification, but both of the runtimes
    // callers are migrating from make it, and it is only made when the kernel
    // was built with the file it points at.
    if resolver.open(b"/proc/kcore", Create::Nothing).is_ok() {
        link_at(resolver, "/proc/kcore", "/dev/core")?;
    }

    // The pseudo-terminal multiplexer is a link, not a node, because the node
    // belongs to the `devpts` instance mounted at `/dev/pts`. An image that
    // ships its own is replaced, because it would name the runtime's instance
    // rather than the container's. The link is made first and the image's own
    // removed only when it is in the way, which on the usual empty `/dev` is
    // never.
    let parent = resolver.open_directory(b"/dev", Create::Directories)?;
    let linked = rustix::fs::symlinkat(c"pts/ptmx", parent, c"ptmx");
    if let Err(e) = &linked {
        if e.raw_os_error() == crate::sys::error::EEXIST
            && rustix::fs::unlinkat(
                parent,
                c"ptmx",
                rustix::fs::AtFlags::empty(),
            )
            .is_ok()
        {
            return ok_if_exists(
                rustix::fs::symlinkat(c"pts/ptmx", parent, c"ptmx"),
                "rootfs: link /dev/ptmx",
            );
        }
    }
    ok_if_exists(linked, "rootfs: link /dev/ptmx")
}

/// Creates one of the links `/dev` is expected to carry.
///
/// An image may ship its own, which is fine: the point is that the path
/// resolves, not that we made it.
fn link_at(resolver: &mut Resolver, target: &str, link: &str) -> Result<()> {
    let Some((directory, name)) = crate::sys::path::split_last(link.as_bytes())
    else {
        return Ok(());
    };
    let parent = resolver.open_directory(directory, Create::Directories)?;
    let name_buf = PathBuf::<64>::from(name)?;
    let target_buf = PathBuf::<64>::from(target.as_bytes())?;
    ok_if_exists(
        rustix::fs::symlinkat(
            target_buf.as_c_str(),
            parent,
            name_buf.as_c_str(),
        ),
        "rootfs: create symlink",
    )
}

/// Creates one device node.
///
/// A container in a user namespace usually cannot create device nodes at all,
/// so the node is bound in from the host instead. That is not a fallback in
/// the sense of being worse: it is the only thing that works rootless, and the
/// resulting node has exactly the same identity.
fn create_device(
    plan: &View<'_>,
    resolver: &mut Resolver,
    device: &DeviceOp,
) -> Result<()> {
    use rustix::fs::{FileType, Mode, mknodat};

    let path = plan.raw(device.path)?;
    let Some((directory, name)) = crate::sys::path::split_last(path) else {
        return Err(Error::msg("device: path has no name"));
    };
    let parent = resolver.open_directory(directory, Create::Directories)?;
    let name_buf = PathBuf::<64>::from(name)?;
    let name = name_buf.as_c_str();

    let kind = match device.kind {
        b'b' => FileType::BlockDevice,
        b'c' | b'u' => FileType::CharacterDevice,
        b'p' => FileType::Fifo,
        _ => return Err(Error::msg("device: unknown type")),
    };
    let permissions = Mode::from_raw_mode(device.mode);
    let numbers = rustix::fs::makedev(device.major, device.minor);

    // Made first, and whatever the image shipped under the name removed only
    // when it is in the way: the numbers it carries may not be the ones the
    // configuration asks for. On the usual empty `/dev` nothing is.
    let mut made = mknodat(parent, name, kind, permissions, numbers);
    if made.is_err_and(|e| e.raw_os_error() == crate::sys::error::EEXIST) {
        rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty())
            .context("device: replace node")?;
        made = mknodat(parent, name, kind, permissions, numbers);
    }
    match made {
        Ok(()) => rustix::fs::chownat(
            parent,
            name,
            Some(rustix::fs::Uid::from_raw(device.uid)),
            Some(rustix::fs::Gid::from_raw(device.gid)),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .context("device: set ownership"),
        Err(e)
            if matches!(
                e.raw_os_error(),
                crate::sys::error::EPERM | crate::sys::error::EACCES
            ) =>
        {
            bind_host_device(parent, name, path)
        }
        Err(e) => Err(Error::from(e).describe("device: create node")),
    }
}

/// Binds the host's device node into the container.
fn bind_host_device(
    parent: BorrowedFd<'_>,
    name: &core::ffi::CStr,
    path: &[u8],
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, openat};

    // An empty regular file is enough to mount over; the node's identity comes
    // from the host side of the bind.
    create_at(parent, name, Create::File, "device: create target")?;

    let mut host = PathBuf::<256>::new();
    host.push_bytes(path)?;
    let tree =
        clone_path(host.as_c_str(), false, false, "device: clone host node")?;
    let destination =
        openat(parent, name, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .context("device: open target")?;
    move_onto(tree.as_fd(), destination.as_fd(), "device: bind host node")
}

/// Replaces the root filesystem with the container's.
///
/// `pivot_root(".", ".")` with the working directory already at the new root
/// is the form that needs no scratch directory: the old root ends up stacked
/// on the new one and is detached immediately afterwards.
pub fn pivot(root: BorrowedFd<'_>) -> Result<()> {
    use rustix::{
        mount::{UnmountFlags, unmount},
        process::{chdir, fchdir, pivot_root},
    };

    fchdir(root).context("rootfs: enter new root")?;
    pivot_root(c".", c".").context("rootfs: pivot")?;
    // The old root is now stacked on the new one at the same point. Detaching
    // rather than unmounting lets anything still using it finish, while making
    // it unreachable by name, which is all that matters here.
    unmount(c".", UnmountFlags::DETACH).context("rootfs: detach old root")?;
    chdir(c"/").context("rootfs: return to root")
}

/// Replaces the root filesystem without `pivot_root`.
///
/// Weaker, and only used when the caller explicitly asks, because a `chroot`
/// can be escaped by a process that holds a descriptor outside it.
pub fn chroot(root: BorrowedFd<'_>) -> Result<()> {
    use rustix::process::{chdir, fchdir};
    fchdir(root).context("rootfs: enter new root")?;
    rustix::process::chroot(c".").context("rootfs: chroot")?;
    chdir(c"/").context("rootfs: return to root")
}

/// Hides or restricts the paths the configuration names.
///
/// This runs after the root has changed, because the paths name places inside
/// the container.
pub fn apply_paths(plan: &View<'_>, resolver: &mut Resolver) -> Result<()> {
    plan.paths(|op| {
        let path = plan.raw(op.path)?;
        let action = op.path_action().ok_or_else(|| {
            Error::msg("paths: unknown action from a foreign plan")
        })?;

        // A path the image does not have needs nothing done to it, and
        // refusing to start because `/proc/scsi` is absent would be absurd.
        let Ok(target) = resolver.open(path, Create::Nothing) else {
            return Ok(());
        };

        match action {
            PathAction::Mask => mask(target.as_fd()),
            PathAction::ReadOnly => make_read_only(target.as_fd()),
        }
    })
}

/// Hides a path.
///
/// A file is covered with `/dev/null` and a directory with an empty read-only
/// filesystem, which is the only way to hide a directory's contents without
/// removing them.
fn mask(target: BorrowedFd<'_>) -> Result<()> {
    use rustix::{
        fs::{FileType, statat},
        mount::{
            FsMountFlags, FsOpenFlags, MountAttrFlags, fsconfig_create,
            fsconfig_set_string, fsmount, fsopen,
        },
    };

    let stat = statat(target, c"", rustix::fs::AtFlags::EMPTY_PATH)
        .context("paths: inspect")?;
    let is_directory =
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory;

    let source = if is_directory {
        let fs = fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC)
            .context("paths: open tmpfs")?;
        fsconfig_set_string(fs.as_fd(), "size", "0")
            .context("paths: size tmpfs")?;
        fsconfig_set_string(fs.as_fd(), "mode", "0755")
            .context("paths: mode tmpfs")?;
        fsconfig_create(fs.as_fd()).context("paths: create tmpfs")?;
        fsmount(
            fs.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::MOUNT_ATTR_RDONLY
                | MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC,
        )
        .context("paths: materialise tmpfs")?
    } else {
        let tree =
            clone_path(c"/dev/null", false, false, "paths: clone /dev/null")?;
        // Read only, so that a masked path cannot be written to at all rather
        // than having writes quietly swallowed. `nodev` is deliberately not
        // set: it would stop the character device being opened as one, and
        // the mask would stop working.
        let attr = MountAttr::default()
            .set(mountattr::ATTR_RDONLY | mountattr::ATTR_NOSUID);
        mountattr::mount_setattr_fd(tree.as_fd(), false, &attr)
            .context("paths: seal the mask")?;
        tree
    };

    move_onto(source.as_fd(), target, "paths: mask")
}

/// Makes a path read only by binding it onto itself with the attribute set.
fn make_read_only(target: BorrowedFd<'_>) -> Result<()> {
    use rustix::mount::{OpenTreeFlags, open_tree};

    let tree = open_tree(
        target,
        c"",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH
            | OpenTreeFlags::AT_RECURSIVE,
    )
    .context("paths: clone for read only")?;
    let attr = MountAttr::default().set(mountattr::ATTR_RDONLY);
    mountattr::mount_setattr_fd(tree.as_fd(), true, &attr)?;
    move_onto(tree.as_fd(), target, "paths: make read only")
}

/// Makes the container's root read only.
///
/// Last of everything, so that creating devices and applying mounts could
/// still write to it.
pub fn seal_root() -> Result<()> {
    use rustix::mount::{MountFlags, mount_remount};

    // Changing the attribute on the mount that is already the root, rather
    // than mounting a read-only copy over it. Covering the root would look
    // right and do nothing: a process resolves an absolute path starting from
    // the root it is pinned to, without crossing a mount point to get there,
    // so it would keep reaching the writable mount underneath.
    let attr = MountAttr::default().set(mountattr::ATTR_RDONLY);
    match mountattr::mount_setattr(rustix::fs::CWD, c"/", 0, &attr) {
        Ok(()) => Ok(()),
        // Kernels without `mount_setattr` get the older interface, which
        // reaches the same state without doing it atomically.
        Err(e) if e.is_unsupported() => {
            mount_remount("/", MountFlags::BIND | MountFlags::RDONLY, "")
                .context("rootfs: seal by remount")
        }
        Err(e) => Err(e),
    }
}

/// Writes the kernel parameters the configuration names.
///
/// The names arrive already converted from the dotted form into path
/// components, so nothing here parses anything.
pub fn apply_sysctls(plan: &View<'_>) -> Result<()> {
    use rustix::fs::{Mode, OFlags};

    // A container without `/proc` mounted cannot have sysctls applied, and a
    // configuration that asks for both will have mounted it first.
    if plan.count(Section::Sysctls) == 0 {
        return Ok(());
    }
    let base = open_directory(c"/proc/sys", "sysctl: open /proc/sys")?;

    plan.sysctls(|op| {
        let name = plan.c_str(op.key)?;
        let value = plan.raw(op.value)?;
        let file = rustix::fs::openat(
            base.as_fd(),
            name,
            OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("sysctl: open parameter")?;
        let written =
            rustix::io::write(&file, value).context("sysctl: write")?;
        if written == value.len() {
            Ok(())
        } else {
            Err(Error::msg("sysctl: short write"))
        }
    })
}

/// Sets the names the UTS namespace carries.
pub fn apply_names(plan: &View<'_>, container: &Container) -> Result<()> {
    if !container.hostname.is_empty() {
        let name = plan.raw(container.hostname)?;
        rustix::system::sethostname(name).context("uts: set hostname")?;
    }
    if !container.domainname.is_empty() {
        let name = plan.raw(container.domainname)?;
        rustix::system::setdomainname(name).context("uts: set domain name")?;
    }
    Ok(())
}

/// Converts a propagation bit into the flags `mount_change` takes.
fn propagation_flags(value: u64) -> rustix::mount::MountPropagationFlags {
    use rustix::mount::MountPropagationFlags as Flags;

    use crate::oci::lower::tables::ms;

    let mut flags = match value & !ms::REC {
        v if v == ms::SHARED => Flags::SHARED,
        v if v == ms::SLAVE => Flags::DOWNSTREAM,
        v if v == ms::UNBINDABLE => Flags::UNBINDABLE,
        _ => Flags::PRIVATE,
    };
    if value & ms::REC != 0 {
        flags |= Flags::REC;
    }
    flags
}

/// Opens the container root so it can be pivoted into.
pub fn open_root(plan: &View<'_>, container: &Container) -> Result<OwnedFd> {
    let path = plan.c_str(container.rootfs)?;
    open_directory(path, "rootfs: open")
}
