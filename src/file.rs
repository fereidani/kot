//! Reading a whole file with the fewest calls.
//!
//! The standard library's whole-file read costs six calls on this target: the
//! C library adds an `fcntl` after every `open`, and the read loop ends with
//! a probe that returns nothing. The configuration and the state record are
//! read on every command the runtime has, so this does the same in four.

use std::{io, path::Path};

use rustix::fs::{Mode, OFlags};

/// Reads the file at `path` into `out`, replacing what was there.
///
/// The size from `fstat` says how much to ask for, and asking for one byte
/// more than that proves the end was reached without a second read: a regular
/// file answers a request it cannot fill with what it has. A file that grew in
/// between, or one whose size is not known in advance, is read on until it
/// stops.
pub fn read(path: &Path, out: &mut Vec<u8>) -> io::Result<()> {
    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let size = rustix::fs::fstat(&file)?.st_size;
    let size = usize::try_from(size).unwrap_or(0);

    out.clear();
    out.reserve(size.saturating_add(1));
    // Bounded: every pass either ends the loop or adds at least one byte,
    // and the cap stops a file that grows as fast as it is read.
    for _ in 0..4096u32 {
        let read =
            rustix::io::read(&file, rustix::buffer::spare_capacity(out))?;
        if read == 0 || out.len() < out.capacity() {
            return Ok(());
        }
        out.reserve(4096);
    }
    Err(io::Error::new(
        io::ErrorKind::FileTooLarge,
        "the file kept growing while it was read",
    ))
}

/// Reads at most `limit` bytes of the file at `path` into `out`.
///
/// For a file whose size is the container's decision. The cap bounds what
/// the runtime holds for it; a longer file is not an error, since the
/// answer is either in the part that was read or not there at all.
pub fn read_capped(
    path: &Path,
    limit: usize,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    // A name the container chose may not be a file at all: a fifo blocks
    // until somebody writes to it, and a device has side effects of its
    // own. So the open does not wait, and what it opened has to be an
    // ordinary file before a byte is read.
    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
    )?;
    let stat = rustix::fs::fstat(&file)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode)
        != rustix::fs::FileType::RegularFile
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    out.clear();
    out.reserve(limit.min(1 << 16).saturating_add(1));
    // Bounded: every pass either ends the loop or fills the spare capacity,
    // and the capacity never grows past the cap.
    for _ in 0..4096u32 {
        let read =
            rustix::io::read(&file, rustix::buffer::spare_capacity(out))?;
        if read == 0 || out.len() >= limit {
            out.truncate(limit);
            return Ok(());
        }
        if out.len() == out.capacity() {
            out.reserve((limit - out.len()).min(1 << 16));
        }
    }
    Ok(())
}
