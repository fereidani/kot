//! The container's pseudo-terminal.
//!
//! The terminal is created inside the container, from the container's own
//! `devpts` instance, so that the pseudo-terminal numbering a container sees
//! is its own. That means init creates it rather than the driver, and hands
//! the controlling end back over a socket.
//!
//! Which socket is the caller's choice. `--console-socket` names one, and
//! that is how `conmon` and the containerd shim take over a container's
//! terminal. A foreground run has no such socket, so the driver makes a pair
//! and relays between its own end and the caller's standard streams.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::sys::{
    error::{Context, Error, Result},
    path::PathBuf,
    pty,
};

/// Creates a pseudo-terminal from the container's own multiplexer.
///
/// Returns the controlling end, which is sent to whatever asked for it, and
/// the container end, which becomes the payload's standard streams.
pub fn open() -> Result<(OwnedFd, OwnedFd)> {
    use rustix::{
        fs::{Mode, OFlags, open},
        pty::{grantpt, unlockpt},
    };

    // Opened by path, because only the path resolves to the container's
    // `devpts` instance. Going through `posix_openpt` would find the
    // runtime's.
    let controller = open(
        c"/dev/ptmx",
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("terminal: open the multiplexer")?;
    grantpt(controller.as_fd()).context("terminal: grant")?;
    unlockpt(controller.as_fd()).context("terminal: unlock")?;

    // Rendered here instead of through `ptsname`, which answers with an owned
    // string: the name is a number under a fixed prefix, and this half of the
    // runtime does not allocate.
    let mut name = PathBuf::<32>::new();
    name.push_bytes(b"/dev/pts/")?;
    name.push_u64(u64::from(pty::number(controller.as_fd())?))?;
    let follower = open(
        name.as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY,
        Mode::empty(),
    )
    .context("terminal: open the container end")?;
    Ok((controller, follower))
}

/// Sends the controlling end over a socket.
///
/// The message carries a name alongside the descriptor because the protocol
/// the runtime's callers implement expects to find one; the name itself is not
/// used for anything.
pub fn send(socket: BorrowedFd<'_>, controller: BorrowedFd<'_>) -> Result<()> {
    use rustix::net::{
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg,
    };

    let fds = [controller];
    let mut space = [core::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut buffer = SendAncillaryBuffer::new(&mut space);
    if !buffer.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(Error::msg("terminal: message does not fit"));
    }
    let payload = [std::io::IoSlice::new(b"terminal")];
    sendmsg(socket, &payload, &mut buffer, SendFlags::empty())
        .context("terminal: send the controlling end")?;
    Ok(())
}

/// Makes a terminal the process's controlling terminal and its standard
/// streams.
///
/// The order matters: a process has to lead its own session before it can take
/// a controlling terminal, and it has to have one before the payload can be
/// signalled from the keyboard.
pub fn adopt(follower: BorrowedFd<'_>) -> Result<()> {
    use rustix::{
        process::{ioctl_tiocsctty, setsid},
        termios::isatty,
    };

    if !isatty(follower) {
        return Err(Error::msg("terminal: not a terminal"));
    }
    // A process that already leads a session cannot start another, which is
    // the normal case for the container's first process and not an error.
    let _ = setsid();
    ioctl_tiocsctty(follower).context("terminal: take control")?;

    let raw = follower.as_raw_fd();
    for target in 0..3 {
        // SAFETY: `raw` names a descriptor this process owns, and standard
        // input, output and error are this process's to replace.
        unsafe { crate::sys::process::dup3(raw, target, 0) }?;
    }
    Ok(())
}

/// Gives the container's end of the terminal to the user the payload runs
/// as.
///
/// A terminal device is created owned by whoever opened it, which here is
/// init while it is still privileged. A payload running as anybody else
/// would then find its own standard input and output owned by somebody it
/// is not, and a mode that grants nothing to others: it could not read a
/// keystroke or print a line. This runs before privilege is dropped, which
/// is the only moment it can.
pub fn own(follower: BorrowedFd<'_>, uid: u32, gid: u32) -> Result<()> {
    use rustix::{
        fs::fchown,
        process::{Gid, Uid},
    };

    fchown(follower, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .context("terminal: give the container end to its user")
}

/// Sets a terminal's size.
pub fn resize(terminal: BorrowedFd<'_>, rows: u32, columns: u32) -> Result<()> {
    if rows == 0 && columns == 0 {
        return Ok(());
    }
    let mut size = rustix::termios::tcgetwinsize(terminal)
        .context("terminal: read size")?;
    size.ws_row = u16::try_from(rows).unwrap_or(size.ws_row);
    size.ws_col = u16::try_from(columns).unwrap_or(size.ws_col);
    rustix::termios::tcsetwinsize(terminal, size).context("terminal: set size")
}
