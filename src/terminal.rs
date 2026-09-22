//! The driver's side of the container's terminal.
//!
//! With `--console-socket` the runtime connects to whatever the caller named
//! and the container's terminal goes there; the runtime is out of the way from
//! that point on. Without one, and in the foreground, the runtime becomes the
//! terminal's other end itself: it makes a socket pair, receives the
//! controlling end from init over it, puts the caller's terminal into raw mode
//! so that keystrokes reach the container unprocessed, and copies in both
//! directions until the container exits.
//!
//! The copying is an ordinary read and write through a small buffer. A
//! terminal carries what a person types and what the container prints, so
//! the traffic is tiny and the call count is what matters rather than the
//! copy; moving the bytes inside the kernel instead would save nothing here
//! and would still need the buffer for the end-of-file and resize handling
//! around it.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use anyhow::{Context as _, Result, bail};

/// Connects to the socket a caller asked the terminal to be sent to.
pub fn connect(path: &str) -> Result<OwnedFd> {
    use rustix::net::{
        AddressFamily, SocketFlags, SocketType, connect, socket_with,
    };

    let address =
        rustix::net::SocketAddrUnix::new(path).with_context(|| {
            format!("the console socket path {path} is not usable")
        })?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("creating the console socket")?;
    connect(socket.as_fd(), &address)
        .with_context(|| format!("connecting to the console socket {path}"))?;
    Ok(socket)
}

/// A socket pair the runtime uses as its own console socket.
pub struct Pair {
    /// The end handed to the container.
    pub container: OwnedFd,
    /// The end the runtime receives the terminal on.
    pub runtime: OwnedFd,
}

/// Makes the pair a foreground run needs.
pub fn pair() -> Result<Pair> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    let (runtime, container) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("creating a console socket pair")?;
    Ok(Pair { container, runtime })
}

/// Receives the controlling end of the container's terminal.
pub fn receive(socket: BorrowedFd<'_>) -> Result<OwnedFd> {
    use rustix::net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg,
    };

    let mut payload = [0u8; 64];
    let mut space = [core::mem::MaybeUninit::<u8>::uninit(); 128];
    let mut buffer = RecvAncillaryBuffer::new(&mut space);
    let mut slices = [std::io::IoSliceMut::new(&mut payload)];
    recvmsg(socket, &mut slices, &mut buffer, RecvFlags::empty())
        .context("receiving the container's terminal")?;

    for message in buffer.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = message {
            if let Some(fd) = fds.next() {
                return Ok(fd);
            }
        }
    }
    bail!("the container did not send a terminal")
}

/// The caller's terminal settings, restored when this is dropped.
///
/// Raw mode has to be undone whatever happens, including when the container
/// fails, or the caller is left with a shell that does not echo.
pub struct RawMode {
    saved: Option<(OwnedFd, rustix::termios::Termios)>,
}

impl RawMode {
    /// Puts standard input into raw mode, if it is a terminal.
    pub fn enter() -> Result<Self> {
        use rustix::termios::{OptionalActions, isatty, tcgetattr, tcsetattr};

        let stdin = rustix::stdio::stdin();
        if !isatty(stdin) {
            return Ok(Self { saved: None });
        }
        let original = tcgetattr(stdin).context("reading terminal settings")?;
        let mut raw = original.clone();
        raw.make_raw();
        tcsetattr(stdin, OptionalActions::Now, &raw)
            .context("setting the terminal to raw mode")?;

        let keep = rustix::io::dup(stdin).context("keeping the terminal")?;
        Ok(Self {
            saved: Some((keep, original)),
        })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        use rustix::termios::{OptionalActions, tcsetattr};
        if let Some((fd, original)) = self.saved.as_ref() {
            let _ = tcsetattr(fd.as_fd(), OptionalActions::Now, original);
        }
    }
}

/// Copies between the container's terminal and the caller's streams until the
/// container's process exits.
///
/// Returns once the terminal reports end of file, which happens when the last
/// process holding the container end closes it.
pub fn relay(
    terminal: BorrowedFd<'_>,
    forwarding: Option<&crate::signals::Forwarding>,
) -> Result<()> {
    use rustix::event::{PollFd, PollFlags, poll};

    let stdin = rustix::stdio::stdin();
    let stdout = rustix::stdio::stdout();
    inherit_size(terminal, stdin);
    let mut buffer = [0u8; 8192];
    let mut input_open =
        rustix::termios::isatty(stdin) || rustix::fs::fstat(stdin).is_ok();

    // Bounded by the container's lifetime. The cap is generous enough that a
    // long-lived interactive session is unaffected and still stops a runaway.
    for _ in 0..u32::MAX {
        // Built on the stack each turn, so the loop does not allocate and
        // no result from the previous turn can be read as this turn's. An
        // entry that is not being watched is polled for nothing rather
        // than left out, so each index means one thing throughout.
        let signals = forwarding.map(super::signals::Forwarding::fd);
        let nothing = PollFlags::empty();
        let watch = |wanted: bool| if wanted { PollFlags::IN } else { nothing };
        let mut fds = [
            PollFd::new(&terminal, PollFlags::IN),
            PollFd::new(&stdin, watch(input_open)),
            PollFd::new(
                signals.as_ref().unwrap_or(&terminal),
                watch(signals.is_some()),
            ),
        ];
        poll(&mut fds, None).context("waiting on the terminal")?;

        // A signal for the container arrived while this was waiting. A
        // window change is the one the runtime answers itself: the container
        // sees the new size through the terminal rather than through the
        // signal.
        let signalled = signals.is_some()
            && fds.get(2).is_some_and(|fd| !fd.revents().is_empty());
        if signalled {
            if let Some(forwarding) = forwarding {
                if forwarding.deliver().map_err(|e| anyhow::anyhow!("{e}"))? {
                    inherit_size(terminal, stdin);
                }
            }
        }

        let terminal_ready =
            fds.first().is_some_and(|fd| !fd.revents().is_empty());
        let input_ready = input_open
            && fds
                .get(1)
                .is_some_and(|fd| fd.revents().contains(PollFlags::IN));

        if terminal_ready {
            match rustix::io::read(terminal, &mut buffer) {
                // The container closed its end, which is how this ends.
                Ok(0) => return Ok(()),
                Ok(n) => {
                    write_all(stdout, buffer.get(..n).unwrap_or(&[]))?;
                }
                Err(e) if is_retryable(e) => {}
                // The terminal hanging up is the container going away.
                Err(_) => return Ok(()),
            }
        }
        if input_ready {
            match rustix::io::read(stdin, &mut buffer) {
                Ok(0) => input_open = false,
                Ok(n) => {
                    write_all(terminal, buffer.get(..n).unwrap_or(&[]))?;
                }
                Err(e) if is_retryable(e) => {}
                Err(_) => input_open = false,
            }
        }
    }
    Ok(())
}

fn write_all(target: BorrowedFd<'_>, mut data: &[u8]) -> Result<()> {
    // Bounded: each iteration writes at least one byte or fails.
    while !data.is_empty() {
        match rustix::io::write(target, data) {
            Ok(0) => bail!("the terminal stopped accepting output"),
            Ok(n) => data = data.get(n..).unwrap_or(&[]),
            Err(e) if is_retryable(e) => {}
            Err(e) => {
                return Err(
                    anyhow::Error::new(e).context("copying to the terminal")
                );
            }
        }
    }
    Ok(())
}

fn is_retryable(error: rustix::io::Errno) -> bool {
    matches!(
        error.raw_os_error(),
        crate::sys::error::EINTR | crate::sys::error::EAGAIN
    )
}

/// Gives the container's terminal the size of the one the caller is at.
///
/// A configuration may state `consoleSize`, and where it does that is the
/// answer. Where it does not, a new pseudo-terminal has no size at all, and
/// a program that asks how wide its terminal is gets zero: full-screen
/// programs draw into a window they think has no rows, and anything wrapping
/// its output wraps at the wrong place. The caller's own terminal is the
/// only size worth guessing, and it is the size the caller is looking at.
///
/// Best effort: a caller whose input is a pipe has no size to lend, and a
/// container without one is no worse off than before.
fn inherit_size(terminal: BorrowedFd<'_>, stdin: BorrowedFd<'_>) {
    use rustix::termios::{tcgetwinsize, tcsetwinsize};

    let Ok(size) = tcgetwinsize(stdin) else {
        return;
    };
    if size.ws_row == 0 && size.ws_col == 0 {
        return;
    }
    // Only where nothing has set one: a size the configuration asked for is
    // already in place and is not this function's to overwrite.
    if let Ok(current) = tcgetwinsize(terminal) {
        if current.ws_row != 0 || current.ws_col != 0 {
            return;
        }
    }
    let _ = tcsetwinsize(terminal, size);
}
