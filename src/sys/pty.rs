//! The pseudo-terminal interfaces the safe wrappers do not cover.
//!
//! `rustix::pty::ptsname` answers with an owned `CString`, which is a heap
//! allocation on the container's init path. The kernel's own answer is a
//! number, and the name is that number under a fixed prefix, so asking for
//! the number directly leaves the caller to render the name into a buffer it
//! already has.

use std::os::fd::BorrowedFd;

use crate::sys::error::{Error, Result};

/// `TIOCGPTN`, which reads the number of the terminal behind a multiplexer.
const PTY_NUMBER: rustix::ioctl::Opcode =
    rustix::ioctl::opcode::read::<u32>(b'T', 0x30);

/// The number of the pseudo-terminal `controller` opened.
///
/// The controller is a descriptor for `/dev/ptmx`; the terminal it made is
/// `/dev/pts/<number>` within the same `devpts` instance.
pub fn number(controller: BorrowedFd<'_>) -> Result<u32> {
    use rustix::ioctl::{Getter, ioctl};

    // SAFETY: `TIOCGPTN` on a multiplexer descriptor writes one `u32` and
    // reads nothing, exactly as this getter declares. A descriptor that is not
    // a multiplexer fails the call rather than writing anything.
    let number = unsafe { ioctl(controller, Getter::<PTY_NUMBER, u32>::new()) };
    number.map_err(|e| Error::from(e).describe("terminal: terminal number"))
}
