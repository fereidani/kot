//! The sealed runtime image.
//!
//! The container init process is this same binary, re-executed from an image
//! that cannot be written. That is the defence against the class of attack
//! where a container's entrypoint resolves to the runtime itself: the
//! entrypoint may well end up pointing at us, but there is then nothing there
//! to overwrite.
//!
//! Two images serve. The first is a reference rather than a copy: a private
//! read-only overlay filesystem whose top layer is the directory the binary
//! lives in, mounted nowhere and reachable only through the descriptor this
//! module hands out. A file opened through it has an inode of the overlay's
//! own, so there is no way from it back to the file on disk. A read-only bind
//! mount cannot promise that much: it shares its inode with the mount it was
//! taken from, and a write needs only the inode. Making the reference costs a
//! handful of calls and no copying.
//!
//! The second is the copy the reference replaces: the whole binary moved into
//! a memory file and sealed against every change. A kernel without overlayfs,
//! a runtime without the privilege to mount one, or a binary the overlay
//! cannot reach falls back to it, at the cost of a megabyte copied per
//! container.

use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

use anyhow::{Context as _, Result, bail};

/// Seals that make a memory file permanently read only.
///
/// All four are needed: preventing writes is not enough on its own if the file
/// can still be grown, shrunk, or have its seals removed.
const SEALS: rustix::fs::SealFlags = rustix::fs::SealFlags::from_bits_retain(
    rustix::fs::SealFlags::SEAL.bits()
        | rustix::fs::SealFlags::SHRINK.bits()
        | rustix::fs::SealFlags::GROW.bits()
        | rustix::fs::SealFlags::WRITE.bits(),
);

/// The name the sealed memory file carries, which shows up in `/proc` and
/// makes it obvious what a container's `exe` link is pointing at.
const NAME: &str = "kot-sealed";

/// Returns a descriptor for an image that cannot be written.
///
/// `scratch` is a directory the runtime owns. The overlay needs it as a
/// second layer, because the kernel refuses an overlay of one layer with
/// nothing to write to. Nothing in it is ever looked at: the binary's own
/// directory sits above it, and the one name asked for is found there.
///
/// When the runtime is already running from a sealed memory file, which
/// happens when an administrator arranged one or when a previous stage did
/// the work, the existing one is reused rather than made again.
pub fn sealed(scratch: &Path) -> Result<OwnedFd> {
    let exe = rustix::fs::readlink(c"/proc/self/exe", Vec::new())
        .context("finding the runtime binary")?;
    let exe = exe.as_bytes();
    if exe.starts_with(b"/memfd:") {
        let current = open_self()?;
        if is_sealed(current.as_fd()) {
            return Ok(current);
        }
        return copy_into_memfd(current.as_fd());
    }

    match reference(exe, scratch) {
        Ok(image) => Ok(image),
        Err(error) => {
            crate::log::debug(&format!(
                "copying the runtime binary instead of referring to it: \
                 {error:#}"
            ));
            copy_into_memfd(open_self()?.as_fd())
        }
    }
}

/// Opens the binary through a private read-only overlay of its directory.
///
/// The path is the one `/proc/self/exe` reports. A binary replaced on disk
/// since the runtime started reports its old name with a suffix, which the
/// overlay then does not find, and the caller copies instead.
fn reference(exe: &[u8], scratch: &Path) -> Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt as _;

    use rustix::{
        fs::{Mode, OFlags, openat},
        mount::{
            FsMountFlags, FsOpenFlags, MountAttrFlags, fsconfig_create,
            fsconfig_set_string, fsmount, fsopen,
        },
    };

    let Some((directory, name)) =
        crate::sys::path::split_last(exe).filter(|(_, name)| !name.is_empty())
    else {
        bail!("the runtime binary has no directory to overlay");
    };
    let name = std::ffi::CString::new(name)
        .context("the runtime binary's name is not a path")?;

    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
        .context("opening an overlay filesystem")?;
    fsconfig_set_string(
        fs.as_fd(),
        "lowerdir",
        layers(directory, scratch.as_os_str().as_bytes()).as_slice(),
    )
    .context("setting the overlay's layers")?;
    // The two layers may sit on different filesystems, which the kernel
    // reports as a reason it cannot keep inode numbers unique across them.
    // One file is looked up and nothing is listed, so uniqueness is not
    // wanted, and the report would only be noise in the kernel log.
    let _ = fsconfig_set_string(fs.as_fd(), "xino", "off");
    fsconfig_create(fs.as_fd()).context("creating the overlay")?;

    // Read only is the point. No device nodes and no set-user-id bits are
    // what an executable image never needs, and denying them costs nothing.
    let mount = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NODEV,
    )
    .context("materialising the overlay")?;
    // The descriptor keeps the detached mount alive for as long as it is
    // open, and the process executed from it keeps the file for its life.
    openat(
        mount.as_fd(),
        name.as_c_str(),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening the runtime binary through the overlay")
}

/// Renders two layers as the option the kernel parses.
///
/// Layers are separated by a colon, so a colon or a backslash inside a path
/// has to be escaped with a backslash. The top layer comes first.
fn layers(top: &[u8], below: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(top.len() + below.len() + 8);
    escape_into(top, &mut out);
    out.push(b':');
    escape_into(below, &mut out);
    out
}

fn escape_into(path: &[u8], out: &mut Vec<u8>) {
    for &byte in path {
        if byte == b':' || byte == b'\\' {
            out.push(b'\\');
        }
        out.push(byte);
    }
}

/// Opens the running binary.
fn open_self() -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, open};
    open(
        c"/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening the runtime binary")
}

/// True when a descriptor names a memory file with every seal applied.
fn is_sealed(fd: BorrowedFd<'_>) -> bool {
    rustix::fs::fcntl_get_seals(fd).is_ok_and(|seals| seals.contains(SEALS))
}

/// Copies the binary into a sealed memory file.
fn copy_into_memfd(source: BorrowedFd<'_>) -> Result<OwnedFd> {
    use rustix::fs::{MemfdFlags, fcntl_add_seals, memfd_create, seek};

    let length = rustix::fs::fstat(source)
        .context("measuring the runtime binary")?
        .st_size;
    let length = u64::try_from(length).unwrap_or(0);
    if length == 0 {
        bail!("the runtime binary reports a length of zero");
    }

    let target =
        memfd_create(NAME, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
            .context("creating the sealed image")?;

    // The kernel moves the bytes from the binary's page cache into the memory
    // file without them passing through this process. `copy_file_range` will
    // not do it, because the two sit on different filesystems, but `sendfile`
    // has no such restriction.
    let mut copied = 0u64;
    match stream(target.as_fd(), source, length, &mut copied) {
        Ok(()) => {}
        // A source filesystem that cannot be spliced from is rare and not
        // worth failing to start a container over. Only refused before the
        // first byte moves, because a failure partway means the memory file
        // already holds a prefix that a second attempt would write again.
        Err(e) if copied == 0 && unsupported(&e) => {
            copy_through_buffer(target.as_fd(), source, length)?;
        }
        Err(e) => return Err(e),
    }

    seek(target.as_fd(), rustix::fs::SeekFrom::Start(0))
        .context("rewinding the sealed image")?;
    fcntl_add_seals(target.as_fd(), SEALS)
        .context("sealing the runtime image")?;
    debug_assert!(is_sealed(target.as_fd()), "the image is sealed");
    Ok(target)
}

/// Copies `length` bytes from `source` to `target` inside the kernel.
///
/// `offset` is left holding what was moved, so a caller can tell a source the
/// kernel refused outright from one that failed partway through.
fn stream(
    target: BorrowedFd<'_>,
    source: BorrowedFd<'_>,
    length: u64,
    offset: &mut u64,
) -> Result<()> {
    // Bounded by the file's length. `sendfile` advances `offset` by what it
    // moved, and a transfer of nothing means the file shrank underneath us
    // rather than that another attempt would help.
    while *offset < length {
        let want = usize::try_from(length - *offset).unwrap_or(usize::MAX);
        let moved = rustix::fs::sendfile(target, source, Some(offset), want)
            .context("copying the runtime binary")?;
        if moved == 0 {
            bail!("the runtime binary was truncated while being copied");
        }
    }
    Ok(())
}

/// True when a failure means the kernel will not splice from this source.
fn unsupported(error: &anyhow::Error) -> bool {
    error.downcast_ref::<rustix::io::Errno>().is_some_and(|e| {
        matches!(
            e.raw_os_error(),
            crate::sys::error::EINVAL
                | crate::sys::error::ENOSYS
                | crate::sys::error::EOPNOTSUPP
        )
    })
}

/// Copies through a buffer, for a source the kernel will not splice from.
fn copy_through_buffer(
    target: BorrowedFd<'_>,
    source: BorrowedFd<'_>,
    length: u64,
) -> Result<()> {
    let mut buffer = vec![0u8; 256 * 1024];
    let mut remaining = length;
    // Bounded by the file's length: each iteration moves at least one byte or
    // fails.
    while remaining > 0 {
        let read = rustix::io::read(source, &mut buffer)
            .context("reading the runtime binary")?;
        if read == 0 {
            bail!("the runtime binary was truncated while being copied");
        }
        let mut written = 0usize;
        while written < read {
            let rest = buffer.get(written..read).unwrap_or(&[]);
            let moved = rustix::io::write(target, rest)
                .context("writing the sealed image")?;
            if moved == 0 {
                bail!("the sealed image could not be written");
            }
            written += moved;
        }
        remaining = remaining.saturating_sub(read as u64);
    }
    Ok(())
}

/// Writes a plan into a sealed memory file.
///
/// The plan crosses into init as bytes, and sealing it means init is reading
/// something that provably has not changed since the driver wrote it.
pub fn seal_plan(arena: &[u8]) -> Result<OwnedFd> {
    use rustix::fs::{MemfdFlags, fcntl_add_seals, memfd_create};

    let plan = memfd_create(
        "kot-plan",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .context("creating the plan")?;

    let mut written = 0usize;
    // Bounded by the arena's length; each iteration writes at least one byte
    // or fails.
    while written < arena.len() {
        let chunk = arena.get(written..).unwrap_or(&[]);
        let moved = rustix::io::write(plan.as_fd(), chunk)
            .context("writing the plan")?;
        if moved == 0 {
            bail!("the plan could not be written");
        }
        written += moved;
    }
    fcntl_add_seals(plan.as_fd(), SEALS).context("sealing the plan")?;
    Ok(plan)
}
