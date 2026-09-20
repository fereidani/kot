//! The handoff from the driver to the container init process.
//!
//! Init runs from a sealed image, so it starts with nothing but its arguments
//! and its file descriptors. Everything it needs arrives through those two
//! channels:
//!
//! - The plan, as a sealed memory file it maps read only.
//! - A sequenced-packet socket it reports progress and failures on.
//! - Whatever else the container needs: the start fifo, a console socket, one
//!   descriptor per namespace to join, and one per id-mapped mount.
//!
//! Descriptors are handed over by number rather than by `SCM_RIGHTS`, because
//! the clone that creates init copies the driver's descriptor table. The child
//! renumbers what it was given into a fixed block and closes the rest, so
//! init's view is the same every time regardless of what the caller's table
//! looked like.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use crate::sys::error::{Context, Error, Result};

/// Where the runtime's own descriptors start.
///
/// Above anything a caller can hand down through `--preserve-fds`, which the
/// specification caps well below this, so the two blocks never collide and the
/// renumbering below never has to move a target out of the way.
pub const BASE: RawFd = 64;

/// Descriptors init is given, in the order they are renumbered into.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    /// The sequenced-packet socket back to the driver.
    Sync,
    /// The plan, as a sealed memory file.
    Plan,
    /// The fifo whose open unblocks the payload, for the create and start
    /// split.
    StartFifo,
    /// A socket the pseudo-terminal's controlling end is sent over.
    ConsoleSocket,
    /// First namespace to join. Later ones follow in order, and the
    /// id-mapping namespaces follow those.
    Namespaces,
}

impl Slot {
    /// The descriptor number this slot occupies.
    #[must_use]
    pub const fn fd(self) -> RawFd {
        BASE + match self {
            Self::Sync => 0,
            Self::Plan => 1,
            Self::StartFifo => 2,
            Self::ConsoleSocket => 3,
            Self::Namespaces => 4,
        }
    }

    /// The descriptor of the `index`th namespace to join.
    #[must_use]
    pub const fn namespace(index: usize) -> RawFd {
        Self::Namespaces.fd() + index as RawFd
    }

    /// The descriptor of the `index`th id-mapping namespace.
    ///
    /// These sit above the namespaces to join, so a caller has to say how many
    /// of those there were. Init learns the count from its arguments.
    #[must_use]
    pub const fn idmap(namespaces: usize, index: usize) -> RawFd {
        Self::namespace(namespaces) + index as RawFd
    }
}

/// What the driver hands to init.
#[derive(Default)]
pub struct Handoff {
    /// Init's end of the sync socket.
    pub sync: Option<OwnedFd>,
    /// The sealed plan.
    pub plan: Option<OwnedFd>,
    /// The start fifo, when the container was created rather than run.
    pub start_fifo: Option<OwnedFd>,
    /// The console socket, when the caller asked for one.
    pub console_socket: Option<OwnedFd>,
    /// Namespaces to join, in the order the plan names them.
    pub namespaces: Vec<OwnedFd>,
    /// User namespaces carrying the id mapping of a mount, in the order the
    /// plan's mount records name them.
    pub idmaps: Vec<OwnedFd>,
}

impl Handoff {
    /// Renumbers everything into the fixed block and clears the close-on-exec
    /// flag, so the descriptors survive into the sealed image.
    ///
    /// Runs in the child, between the clone and the re-execution. It must not
    /// allocate and must not fail in a way that leaves a half-renumbered
    /// table, which is why every move is checked and the closing pass runs
    /// last.
    pub fn install(&self) -> Result<()> {
        let moves = [
            (self.sync.as_ref(), Slot::Sync.fd()),
            (self.plan.as_ref(), Slot::Plan.fd()),
            (self.start_fifo.as_ref(), Slot::StartFifo.fd()),
            (self.console_socket.as_ref(), Slot::ConsoleSocket.fd()),
        ];
        for (source, target) in moves {
            let Some(source) = source else { continue };
            move_to(source.as_raw_fd(), target)?;
        }
        for (index, namespace) in self.namespaces.iter().enumerate() {
            move_to(namespace.as_raw_fd(), Slot::namespace(index))?;
        }
        let joined = self.namespaces.len();
        for (index, idmap) in self.idmaps.iter().enumerate() {
            move_to(idmap.as_raw_fd(), Slot::idmap(joined, index))?;
        }
        Ok(())
    }

    /// The highest descriptor number in use after [`Handoff::install`].
    #[must_use]
    pub fn highest(&self) -> RawFd {
        // The last descriptor sits one below the next free number, so taking
        // the number of the one after it would leave one above the sweep and
        // hand it to init unasked.
        Slot::idmap(self.namespaces.len(), self.idmaps.len())
            .saturating_sub(1)
            .max(Slot::ConsoleSocket.fd())
    }
}

/// Moves `source` to `target`, leaving it without the close-on-exec flag.
///
/// `dup3` with no flags clears close-on-exec on the copy, which is exactly
/// what is wanted: these descriptors have to survive the re-execution into the
/// sealed image.
fn move_to(source: RawFd, target: RawFd) -> Result<()> {
    if source == target {
        use rustix::io::{FdFlags, fcntl_setfd};
        // SAFETY: `target` names a descriptor this process owns, and the
        // borrow does not outlive the call.
        let fd = unsafe { BorrowedFd::borrow_raw(target) };
        return fcntl_setfd(fd, FdFlags::empty())
            .context("handoff: clear close-on-exec");
    }
    // SAFETY: `source` names a descriptor this process owns. Anything at
    // `target` belongs to the same table and is deliberately replaced; the
    // caller arranged the block to be free of anything it still needs.
    unsafe { crate::sys::process::dup3(source, target, 0) }
}

/// Closes every descriptor above `highest` that is not one the caller asked to
/// preserve.
///
/// The payload must start with exactly standard input, output and error, plus
/// whatever `--preserve-fds` named. Anything else the runtime happened to hold
/// would be a descriptor the container did not ask for and should not have.
pub fn close_above(highest: RawFd) -> Result<()> {
    crate::sys::process::close_range(highest.unsigned_abs() + 1, u32::MAX, 0)
}

/// The descriptor the payload's program is parked on before the sweep.
///
/// It sits immediately above whatever the caller asked to preserve and carries
/// the close-on-exec flag, so it is gone by the time the payload runs.
///
/// A count that does not fit below the runtime's own block is refused. The
/// payload's descriptors run from three to the slot, and the runtime
/// renumbers its own onto [`BASE`] and above, so a count that reaches that
/// far would have the two overlap: the renumbering would replace a
/// descriptor the payload was promised and the sweep would close the rest,
/// all while the container started as though nothing were wrong.
pub fn program_slot(preserved: usize) -> Result<RawFd> {
    RawFd::try_from(preserved)
        .ok()
        .and_then(|preserved| preserved.checked_add(3))
        .filter(|slot| *slot < BASE)
        .ok_or_else(|| Error::msg("handoff: too many preserved descriptors"))
}

/// Closes the runtime's own block, leaving only the payload's descriptors.
///
/// The program being executed has to survive this: `execveat` needs a
/// descriptor, and closing it first leaves nothing to execute. It is parked at
/// [`program_slot`] beforehand, which is why the sweep starts one above.
pub fn close_runtime_block(preserved: usize) -> Result<()> {
    let first = program_slot(preserved)?
        .checked_add(1)
        .ok_or_else(|| Error::msg("handoff: too many preserved descriptors"))?;
    crate::sys::process::close_range(first.unsigned_abs(), u32::MAX, 0)
}

/// Moves the payload's program onto [`program_slot`], keeping close-on-exec.
///
/// Takes ownership because the original number is about to be swept away, and
/// dropping the wrapper afterwards would close a descriptor already gone.
pub fn park_program(program: OwnedFd, preserved: usize) -> Result<RawFd> {
    use std::os::fd::IntoRawFd;

    /// `O_CLOEXEC`, so the descriptor does not reach the payload.
    const CLOEXEC: u32 = 0o2_000_000;

    let slot = program_slot(preserved)?;
    let raw = program.into_raw_fd();
    if raw == slot {
        // The program already landed on the slot, which is the common case
        // because the sweep above left everything from three upwards free.
        // `dup3` refuses a copy onto itself, so there is nothing to do: the
        // descriptor was opened close-on-exec to begin with.
        return Ok(slot);
    }
    // SAFETY: `raw` names a descriptor this process owns, and `slot` is above
    // the preserved block, so nothing the caller still needs sits at it.
    unsafe { crate::sys::process::dup3(raw, slot, CLOEXEC) }?;
    // The original number is deliberately left open: the sweep that follows
    // closes it, and closing it here would only do the same thing one syscall
    // sooner.
    Ok(slot)
}

/// Parses the arguments the driver passes to the sealed image.
///
/// Init takes no configuration on its command line beyond how many namespaces
/// it was given, because everything else is in the plan.
#[derive(Clone, Copy, Debug, Default)]
pub struct InitArgs {
    /// How many namespace descriptors follow the fixed block.
    pub namespaces: usize,
    /// How many id-mapping namespaces follow those.
    pub idmaps: usize,
    /// How many descriptors the caller asked to preserve.
    pub preserved: usize,
    /// True when a console socket was handed over.
    pub has_console_socket: bool,
    /// True when a start fifo was handed over.
    pub has_start_fifo: bool,
    /// True when the container is meant to outlive the runtime process that
    /// created it, as it is under `create` and a detached `run`.
    ///
    /// It decides whether init asks the kernel to kill it when its parent goes
    /// away. A foreground run needs that to keep an abandoned container from
    /// lingering; a detached one would be killed by it the moment the command
    /// returned.
    pub detached: bool,
}

impl InitArgs {
    /// Renders the arguments as one token, which keeps the command line short
    /// and the parsing trivial.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.namespaces,
            self.preserved,
            u8::from(self.has_console_socket),
            u8::from(self.has_start_fifo),
            u8::from(self.detached),
            self.idmaps
        )
    }

    /// Reads arguments back.
    pub fn decode(text: &str) -> Result<Self> {
        let mut parts = text.split(':');
        let (Some(ns), Some(preserved), Some(console), Some(fifo)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::msg("init: malformed arguments"));
        };
        let detached = parts.next().unwrap_or("0");
        let idmaps = parts.next().unwrap_or("0");
        let number = |value: &str| -> Result<usize> {
            value.parse().map_err(|_| Error::msg("init: bad number"))
        };
        Ok(Self {
            namespaces: number(ns)?,
            idmaps: number(idmaps)?,
            preserved: number(preserved)?,
            has_console_socket: number(console)? != 0,
            has_start_fifo: number(fifo)? != 0,
            detached: number(detached)? != 0,
        })
    }
}
