//! Building the container's filesystem view.
//!
//! The order here is not arbitrary and is worth stating once, because getting
//! it wrong produces a container that looks configured and is not:
//!
//! 1. Give the whole tree the propagation the configuration asked for, which is
//!    private unless it said otherwise, and then make the mount the rootfs sits
//!    on private whatever it said. Nothing the container mounts or unmounts may
//!    reach the host unless the configuration asked for that.
//! 2. Make the root a mount point in its own right, which `pivot_root` requires
//!    and which most bundles do not arrange themselves. Where the kernel can
//!    clone the rootfs straight into a namespace of its own, steps 1, 2 and 5
//!    collapse into entering that namespace: the root is the root from the
//!    first moment, and nothing of the host is there to leave behind.
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
    linux::{
        mount::{
            Create, Resolver, clone_path, create_at, move_onto, ok_if_exists,
            open_directory,
        },
        sync::{self, Kind, Message},
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
pub struct NoUmask(rustix::fs::Mode);

impl NoUmask {
    #[must_use]
    pub fn enter() -> Self {
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

/// Sets the tree's propagation and turns the root into a mount point.
pub fn prepare(container: &Container, plan: &View<'_>) -> Result<()> {
    use rustix::mount::{MountFlags, MountPropagationFlags, mount_change};

    // The namespace init was made in is a copy of the host's, and every mount
    // in the copy is still a peer of the one it was copied from. Left that
    // way, whatever the container mounts under one of them appears on the
    // host as well, and whatever it unmounts disappears from the host. The
    // detach of the old root after the pivot is exactly such an unmount, of
    // the whole tree at once: with the peers still in place it takes the
    // host's `/proc`, `/sys`, `/dev` and `/tmp` down with it.
    //
    // So the whole tree is changed, recursively, before anything else. The
    // default is private, which severs every relationship. A configuration
    // that names a mode gets that mode instead; asking for `shared` is asking
    // to keep the host as a peer, and the two places that would then carry a
    // change back out, the detach of the old root and the move on the chroot
    // path, cut the link themselves first.
    let propagation = if container.rootfs_propagation == 0 {
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC
    } else {
        propagation_flags(container.rootfs_propagation)
    };
    mount_change("/", propagation).context("rootfs: set propagation")?;

    // The mount the rootfs sits on is made private whatever the configuration
    // said, and only that one. `pivot_root` refuses a new root whose parent
    // mount is shared, and the self-bind below would otherwise land on the
    // host too. Private rather than slave because a slave still receives
    // mounts from its master, and a bundle directory the host mounts things
    // under is not a place the container should watch.
    //
    // A rootfs the mount table has no entry for is left to the recursive
    // change above, which has already covered whichever mount it is on. So
    // is every rootfs when the configuration named no mode: the recursive
    // change was to private, which is what this one asks for, and finding
    // the mount would cost a read and a parse of the whole mount table to
    // repeat it.
    if container.rootfs_propagation != 0 {
        if let Some(parent) = parent_mount_of(plan.text(container.rootfs)?) {
            mount_change(&parent, MountPropagationFlags::PRIVATE)
                .context("rootfs: detach the bundle's mount from its peers")?;
        }
    }

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

/// Enters a mount namespace holding the rootfs alone, and makes it the
/// container's.
///
/// The driver made the namespace from the rootfs, so its root is the
/// container's root and nothing of the host is in it: there is no tree to
/// pivot out of and none to detach afterwards. What is left is what
/// [`prepare`] does for a copied tree: sever the peers the clone still has,
/// and clear the flags the bundle's mount happened to carry.
pub fn enter_tree(tree: BorrowedFd<'_>) -> Result<()> {
    use rustix::mount::{MountPropagationFlags, mount_change};

    crate::sys::process::setns(tree, crate::sys::clone::CLONE_NEWNS)
        .context("rootfs: enter the container's mount namespace")?;
    // The clone is still a peer of the mount it was taken from, so anything
    // mounted here would appear on the host as well. Private severs that.
    // The mode the configuration asked for goes on once the tree is built,
    // as it does after a pivot.
    mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .context("rootfs: sever the root from the host")?;
    // As in `prepare`: best effort, and for the same reason.
    let relax = MountAttr::default()
        .clear(mountattr::ATTR_NOSUID | mountattr::ATTR_NODEV);
    let _ = mountattr::mount_setattr(rustix::fs::CWD, c"/", 0, &relax);
    Ok(())
}

/// Creates the device nodes and the links that go with them.
pub fn create_devices(
    plan: &View<'_>,
    resolver: &mut Resolver,
    socket: BorrowedFd<'_>,
) -> Result<()> {
    let _mask = NoUmask::enter();
    let mut index = 0i32;
    plan.devices(|device| {
        let at = index;
        index += 1;
        create_device(plan, resolver, &device, at, socket)
    })?;

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
    index: i32,
    socket: BorrowedFd<'_>,
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
            // The host's own node is the first choice: same device, and it
            // costs nothing but a bind. A node the host does not have is
            // one only the driver can make, and only that case asks it.
            match bind_host_device(parent, name, path) {
                Ok(()) => Ok(()),
                Err(e) if e.errno() == crate::sys::error::ENOENT => {
                    request_device(socket, parent, index)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(Error::from(e).describe("device: create node")),
    }
}

/// Asks the driver for a device node this process cannot create.
///
/// Creating a character or block device is a privilege of the initial user
/// namespace, which a container in one of its own does not hold however
/// complete its mapping is. The directory goes with the request, so the
/// driver never resolves a path inside the container.
fn request_device(
    socket: BorrowedFd<'_>,
    parent: BorrowedFd<'_>,
    index: i32,
) -> Result<()> {
    let request = Message::with_pid(Kind::MakeDevice, index);
    sync::send_fd(socket, &request, parent)?;
    sync::expect(socket, Kind::DeviceMade)?;
    Ok(())
}

/// Binds the host's device node into the container.
fn bind_host_device(
    parent: BorrowedFd<'_>,
    name: &core::ffi::CStr,
    path: &[u8],
) -> Result<()> {
    use rustix::fs::{Mode, OFlags, openat};

    // The host side comes first, so a host with no such node leaves the
    // destination untouched for whoever tries next.
    let mut host = PathBuf::<256>::new();
    host.push_bytes(path)?;
    let tree =
        clone_path(host.as_c_str(), false, false, "device: clone host node")?;
    // A bound node must not carry what a made one would not: no way to
    // gain privilege, and nothing to execute.
    let restrict = MountAttr::default()
        .set(mountattr::ATTR_NOSUID | mountattr::ATTR_NOEXEC);
    mountattr::mount_setattr_fd(tree.as_fd(), false, &restrict)
        .context("device: restrict the bound node")?;

    // An empty regular file is enough to mount over; the node's identity comes
    // from the host side of the bind.
    create_at(parent, name, Create::File, "device: create target")?;
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
        mount::{MountPropagationFlags, UnmountFlags, mount_change, unmount},
        process::{chdir, fchdir, pivot_root},
    };

    // A descriptor for the old root, taken now because afterwards no path
    // names it. Once it is stacked on the new root, a lookup of `.` or `/`
    // stops at the new root and never climbs onto what sits above it; only
    // `umount` climbs, which is why the sequence below could detach the old
    // root by name but could not change its propagation by name.
    let old = open_directory(c"/", "rootfs: open the old root")?;
    fchdir(root).context("rootfs: enter new root")?;
    pivot_root(c".", c".").context("rootfs: pivot")?;

    // The old root's tree is detached rather than unmounted, so that anything
    // still using it can finish, but an unmount of either kind propagates to
    // the peers of every mount in the tree. When the configuration kept the
    // tree shared with the host, those peers are the host's own mounts, and
    // detaching the old root would take the host's `/proc`, `/sys` and the
    // rest down with it. Making the old tree a slave first keeps it receiving
    // what the host mounts, which is what a shared configuration wanted, and
    // stops anything travelling the other way. With the default private tree
    // it changes nothing. The new root is no longer part of that tree, so
    // the container's own mounts keep whatever mode they were given.
    fchdir(&old).context("rootfs: enter the old root")?;
    mount_change(
        ".",
        MountPropagationFlags::DOWNSTREAM | MountPropagationFlags::REC,
    )
    .context("rootfs: sever the old root from the host")?;
    unmount(c".", UnmountFlags::DETACH).context("rootfs: detach old root")?;
    chdir(c"/").context("rootfs: return to root")
}

/// Replaces the root filesystem without `pivot_root`.
///
/// Weaker, and only used when the caller explicitly asks, because a `chroot`
/// can be escaped by a process that holds a descriptor outside it.
///
/// The new root is moved over the old one before the `chroot` rather than
/// simply being changed into. A `chroot` on its own leaves the old root as
/// the parent of the container's, with the host's `/proc`, `/sys` and every
/// other mount the runtime inherited still hanging off it; moving the new
/// root puts it in that place instead, so the container's root is nobody's
/// child and the old tree cannot be walked to from inside.
///
/// That is the same sequence a system uses to leave its initial filesystem
/// behind, and it is what this path can do. It is still not `pivot_root`:
/// the mounts that were in the namespace remain in it, unreachable by name
/// but present, and the kernel decides whether a process may mount a fresh
/// `proc` by looking for a fully visible one in the namespace rather than
/// by looking at paths. A container with both this option and the privilege
/// to mount can therefore still reach the host's process table. That is the
/// cost of asking for the weaker root change, and the reason the option is
/// opt-in.
pub fn chroot(root: BorrowedFd<'_>) -> Result<()> {
    use rustix::{
        mount::{MountPropagationFlags, mount_change, mount_move},
        process::{chdir, fchdir},
    };

    fchdir(root).context("rootfs: enter new root")?;
    // A mount moved onto a shared mount is mounted onto its peers as well,
    // and when the configuration kept the tree shared with the host the peer
    // of the old root is the host's root. The old root is made a slave
    // first, for the same reason the pivot path does it before detaching:
    // what the host mounts still arrives, and nothing goes back. Only the
    // one mount, because the move lands on it alone and the new root still
    // hangs beneath it, carrying the modes the configuration gave it.
    mount_change("/", MountPropagationFlags::DOWNSTREAM)
        .context("rootfs: sever the old root from the host")?;
    // The classic call rather than the newer interface: this path exists for
    // hosts the newer one is not available on, and the working directory
    // follows the mount it names, so `.` is still the new root afterwards.
    mount_move(c".", c"/")
        .context("rootfs: move the new root over the old one")?;
    rustix::process::chroot(c".").context("rootfs: chroot")?;
    chdir(c"/").context("rootfs: return to root")
}

/// Applies the propagation the configuration asked the container's root to
/// have.
///
/// Runs after the root has changed, and only then. Before that point the
/// rootfs is still attached to the host's tree, and anything but private
/// would send the container's own setup back out along it. Afterwards the
/// root has no peers left, so making it shared starts a peer group of the
/// container's own, which is what asking for it means.
pub fn apply_propagation(container: &Container) -> Result<()> {
    use rustix::mount::mount_change;

    if container.rootfs_propagation == 0 {
        return Ok(());
    }
    mount_change("/", propagation_flags(container.rootfs_propagation))
        .context("rootfs: set the propagation the container asked for")
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
        let tree = clone_null()?;
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

/// Clones the container's null device, having checked that it is one.
///
/// Every masked file is covered by a read-only bind of `/dev/null`, taken
/// from inside the container because that is where the mask is going. The
/// image controls what is at that path: a symbolic link there would be
/// followed, and a file of the image's own would be bound in place of the
/// device. Either way the path the configuration asked to have hidden would
/// instead show something the image chose, mounted by the runtime.
///
/// So the path is opened without following a link and checked to be the
/// character device the kernel numbers one and three, and the bind is taken
/// from that descriptor rather than from the name a second time.
fn clone_null() -> Result<OwnedFd> {
    use rustix::{
        fs::{FileType, Mode, OFlags, fstat, major, minor, open},
        mount::{OpenTreeFlags, open_tree},
    };

    /// The kernel's numbers for the null device.
    const NULL_DEVICE: (u32, u32) = (1, 3);

    let device = open(
        c"/dev/null",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("paths: open the null device")?;
    let stat = fstat(&device).context("paths: inspect the null device")?;
    let is_null = FileType::from_raw_mode(stat.st_mode)
        == FileType::CharacterDevice
        && (major(stat.st_rdev), minor(stat.st_rdev)) == NULL_DEVICE;
    if !is_null {
        return Err(Error::msg(
            "paths: /dev/null in the image is not the null device",
        ));
    }

    open_tree(
        device.as_fd(),
        c"",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    )
    .context("paths: clone the null device")
}

/// The mount point the given path sits on, from the kernel's mount table.
///
/// The longest mount point that is a prefix of the path is the mount the
/// path belongs to, because a nested mount is always a longer prefix than
/// the one it hides. The comparison is by whole components, so `/var` does
/// not match a path under `/variable`.
fn parent_mount_of(path: &str) -> Option<String> {
    // Procfs reports no size for the table, so the buffer is sized for a
    // busy host's up front; a read loop that starts from nothing spends a
    // call per doubling.
    let mut bytes = Vec::with_capacity(64 * 1024);
    crate::file::read(std::path::Path::new("/proc/self/mountinfo"), &mut bytes)
        .ok()?;
    let table = std::str::from_utf8(&bytes).ok()?;
    let mut best: Option<&str> = None;
    for line in table.lines() {
        // The mount point is the fifth field, and the fields before it
        // never contain a space.
        let Some(point) = line.split_ascii_whitespace().nth(4) else {
            continue;
        };
        if !covers(point, path) {
            continue;
        }
        if best.is_none_or(|found| point.len() > found.len()) {
            best = Some(point);
        }
    }
    best.map(str::to_owned)
}

/// Whether `point` is `path` or a directory containing it.
fn covers(point: &str, path: &str) -> bool {
    if point == "/" {
        return true;
    }
    let Some(rest) = path.strip_prefix(point) else {
        return false;
    };
    rest.is_empty() || rest.starts_with('/')
}
