//! Copying a directory tree into a freshly made filesystem.
//!
//! A `tmpcopyup` mount asks for the contents a directory already has to be
//! carried into the tmpfs about to cover it, so that a container sees what the
//! image shipped rather than an empty directory. The copy has to happen while
//! the new filesystem is still detached, because once it is attached the
//! original is underneath it and no longer reachable by name.
//!
//! Everything here runs in the container init process, so nothing allocates.
//! The walk is recursive with a fixed depth bound, and each level holds one
//! directory buffer, which is what bounds the stack: [`MAX_DEPTH`] levels of
//! [`DIRENTS`] bytes, plus the single [`CHUNK`] buffer a file copy uses at the
//! bottom.

use core::{ffi::CStr, mem::MaybeUninit};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::sys::{
    error::{Context, Error, Result},
    path::PathBuf,
};

/// Directory levels the copy will descend before refusing.
///
/// A tree this deep under a mount point is not something an image ships; the
/// bound is here so the recursion below has a proof of termination, and a
/// deeper tree is refused rather than half copied.
const MAX_DEPTH: u32 = 16;

/// Bytes of directory entries read at a time, one buffer per level.
const DIRENTS: usize = 1024;

/// Bytes moved per read and write when copying a file's contents.
const CHUNK: usize = 8192;

/// Copies everything under `from` into `to`.
///
/// Both are directories. Regular files, directories and symbolic links are
/// carried over with their mode and ownership; anything else is refused,
/// because a device node or socket that quietly failed to appear would look to
/// the container like an image that never had it.
pub fn tree(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> Result<()> {
    directory(from, to, MAX_DEPTH)
}

/// Copies one directory's entries, recursing into those that are directories.
fn directory(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    depth: u32,
) -> Result<()> {
    use rustix::fs::RawDir;

    let Some(depth) = depth.checked_sub(1) else {
        return Err(Error::msg("copy: the directory tree is too deep"));
    };

    let mut buffer = [MaybeUninit::uninit(); DIRENTS];
    let mut entries = RawDir::new(from, &mut buffer);
    // Bounded by the directory's own length: every turn consumes one entry.
    while let Some(entry) = entries.next() {
        let entry = entry.context("copy: read directory")?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        one(from, to, name, depth)?;
    }
    Ok(())
}

/// Copies a single entry, whatever kind it turns out to be.
fn one(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    name: &CStr,
    depth: u32,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, Mode, statat};

    let stat = statat(from, name, AtFlags::SYMLINK_NOFOLLOW)
        .context("copy: inspect entry")?;
    let mode = Mode::from_raw_mode(stat.st_mode);
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => {
            let (source, target) = descend(from, to, name, mode)?;
            directory(source.as_fd(), target.as_fd(), depth)?;
        }
        FileType::RegularFile => file(from, to, name, mode)?,
        FileType::Symlink => link(from, to, name)?,
        _ => return Err(Error::msg("copy: entry is not a file or directory")),
    }
    own(to, name, &stat);
    Ok(())
}

/// Makes the directory on the far side and opens both halves.
fn descend(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    name: &CStr,
    mode: rustix::fs::Mode,
) -> Result<(OwnedFd, OwnedFd)> {
    use rustix::fs::{Mode, OFlags, chmodat, mkdirat, openat};

    use crate::linux::mount::ok_if_exists;

    ok_if_exists(mkdirat(to, name, mode), "copy: create directory")?;
    // `mkdirat` takes the mode through the umask, so the mode is asserted
    // afterwards to get exactly what the original carried.
    chmodat(to, name, mode, rustix::fs::AtFlags::empty())
        .context("copy: set directory mode")?;

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let source = openat(from, name, flags, Mode::empty())
        .context("copy: open source")?;
    let target =
        openat(to, name, flags, Mode::empty()).context("copy: open target")?;
    Ok((source, target))
}

/// Copies one regular file's contents.
fn file(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
    name: &CStr,
    mode: rustix::fs::Mode,
) -> Result<()> {
    use rustix::{
        fs::{Mode, OFlags, openat},
        io::{read, write},
    };

    let source =
        openat(from, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .context("copy: open file")?;
    let target = openat(
        to,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        mode,
    )
    .context("copy: create file")?;

    let mut buffer = [0u8; CHUNK];
    // Bounded by the file's length: every turn either ends the loop or moves
    // at least one byte, and a file cannot grow while the container is still
    // being built.
    loop {
        let filled = read(&source, &mut buffer).context("copy: read file")?;
        if filled == 0 {
            break;
        }
        let mut written = 0usize;
        while written < filled {
            let chunk = buffer.get(written..filled).unwrap_or(&[]);
            let moved = write(&target, chunk).context("copy: write file")?;
            if moved == 0 {
                return Err(Error::msg("copy: file write made no progress"));
            }
            written += moved;
        }
    }
    Ok(())
}

/// Recreates one symbolic link, target and all.
fn link(from: BorrowedFd<'_>, to: BorrowedFd<'_>, name: &CStr) -> Result<()> {
    use rustix::fs::{readlinkat, symlinkat};

    use crate::sys::path::PATH_MAX;

    let mut raw = [0u8; PATH_MAX];
    let read = readlinkat(from, name, &mut raw[..])
        .context("copy: read symbolic link")?;
    let mut target = PathBuf::<PATH_MAX>::new();
    target.push_bytes(read.to_bytes())?;
    symlinkat(target.as_c_str(), to, name).context("copy: create symbolic link")
}

/// Gives a copied entry the ownership the original had.
///
/// Best effort: a container whose user namespace does not map the original
/// owner cannot reproduce it, and refusing there would make `tmpcopyup`
/// unusable for every rootless container.
fn own(to: BorrowedFd<'_>, name: &CStr, stat: &rustix::fs::Stat) {
    use rustix::{
        fs::{AtFlags, chownat},
        process::{Gid, Uid},
    };

    let uid = Uid::from_raw(stat.st_uid);
    let gid = Gid::from_raw(stat.st_gid);
    let _ = chownat(to, name, Some(uid), Some(gid), AtFlags::SYMLINK_NOFOLLOW);
}
