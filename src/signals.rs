//! Passing the caller's signals on to a container in the foreground.
//!
//! A signal sent to a runtime in the foreground is meant for the container
//! behind it: unforwarded, a `SIGTERM` kills the runtime and leaves the
//! container running with nothing left to reach it through.
//!
//! The signals are blocked and read from a descriptor rather than caught,
//! so nothing here runs in a handler. The same descriptor goes into the
//! `poll` that waits for the container, so forwarding costs no wakeups.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::sys::{error::Result, signalfd};

/// The signals a container is given.
///
/// Everything a supervisor or a person at a terminal sends. A fault the
/// kernel raises is about the runtime rather than the container, and
/// blocking one is undefined besides; `SIGCHLD` is how the container's exit
/// is noticed; `SIGKILL` and `SIGSTOP` cannot be blocked at all.
///
/// The job control signals stay out too: taking `SIGTSTP` off this process
/// and passing it on would leave a shell waiting for a job that stopped
/// nothing, since the runtime would still be running.
const FORWARDED: [u32; 14] = [
    1,  // HUP
    2,  // INT
    3,  // QUIT
    6,  // ABRT
    10, // USR1
    12, // USR2
    13, // PIPE
    14, // ALRM
    15, // TERM
    24, // XCPU
    25, // XFSZ
    28, // WINCH
    29, // IO
    30, // PWR
];

/// Signals blocked and read from a descriptor for as long as this is held.
pub struct Forwarding {
    /// The container's init process, in the runtime's own namespace.
    pid: i32,
    /// The descriptor the blocked signals arrive on.
    fd: OwnedFd,
    /// The blocked set as it was before, to put back.
    previous: u64,
}

impl Forwarding {
    /// Blocks the forwarded signals and opens the descriptor they arrive on.
    pub fn install(pid: i32) -> Result<Self> {
        let mut mask = 0u64;
        for signal in FORWARDED {
            mask |= signalfd::bit(signal);
        }
        let previous = signalfd::block(mask)?;
        match signalfd::open(mask) {
            Ok(fd) => Ok(Self { pid, fd, previous }),
            Err(e) => {
                let _ = signalfd::restore(previous);
                Err(e)
            }
        }
    }

    /// The descriptor to watch alongside the container.
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Sends every signal that has arrived to the container.
    ///
    /// Answers with true when one of them was a window change, which the
    /// caller relaying a terminal has more to do about than forwarding.
    pub fn deliver(&self) -> Result<bool> {
        /// Window change, the one signal that means something to the runtime
        /// as well as to the container.
        const SIGWINCH: u32 = 28;

        let mut resized = false;
        let pid = self.pid;
        signalfd::drain(self.fd.as_fd(), |signal| {
            resized |= signal == SIGWINCH;
            // A container that has already exited is not an error here: the
            // wait that follows is what reports how it ended.
            let _ = send(pid, signal);
        })?;
        Ok(resized)
    }
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        let _ = signalfd::restore(self.previous);
    }
}

/// Sends one signal to the container's init process.
fn send(pid: i32, signal: u32) -> core::result::Result<(), rustix::io::Errno> {
    use rustix::process::{Pid, Signal, kill_process};

    let Some(pid) = Pid::from_raw(pid) else {
        return Err(rustix::io::Errno::SRCH);
    };
    let number = i32::try_from(signal).unwrap_or(0);
    let Some(signal) = Signal::from_named_raw(number) else {
        return Err(rustix::io::Errno::INVAL);
    };
    kill_process(pid, signal)
}

/// Waits for the container, forwarding whatever arrives meanwhile.
///
/// The container's exit and an incoming signal are both waited for in one
/// `poll`, so neither costs a timeout and neither is noticed late.
pub fn wait(pid: i32, forwarding: &Forwarding) -> anyhow::Result<i32> {
    use rustix::{
        event::{PollFd, PollFlags, poll},
        process::{Pid, PidfdFlags, pidfd_open},
    };

    let Some(target) = Pid::from_raw(pid) else {
        anyhow::bail!("there is no process to wait for");
    };
    let child = pidfd_open(target, PidfdFlags::empty())
        .map_err(|e| anyhow::anyhow!("opening the container process: {e}"))?;

    // Bounded by the container's lifetime: every turn either returns or
    // consumes a signal, and the cap is far above what a caller sends by
    // hand.
    for _ in 0..u32::MAX {
        let mut fds = [
            PollFd::new(&child, PollFlags::IN),
            PollFd::new(&forwarding.fd, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == crate::sys::error::EINTR => continue,
            Err(e) => {
                anyhow::bail!("waiting for the container: {e}");
            }
        }
        if fds.get(1).is_some_and(|fd| !fd.revents().is_empty()) {
            forwarding.deliver().map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        if fds.first().is_some_and(|fd| !fd.revents().is_empty()) {
            return crate::wait_for_process(pid);
        }
    }
    anyhow::bail!("gave up waiting for the container")
}
