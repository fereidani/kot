//! The message protocol between the driver and the container init process.
//!
//! Messages are a fixed-size record over a sequenced-packet socket, so a read
//! either returns a whole message or nothing, and neither side has to frame
//! anything. Fixed size also means init can report a failure without
//! allocating, which matters because by the time it fails it may be inside a
//! user namespace with a filesystem it cannot reach.

use std::os::fd::{BorrowedFd, OwnedFd};

use crate::sys::error::{Context, Error, Result};

/// Longest failure description a message carries.
///
/// A description is a static string chosen by the code that failed, and may
/// carry a name with it, such as the program that could not be run. The
/// length is one byte on the wire, so this cannot grow past 255.
pub const CONTEXT_MAX: usize = 224;

/// What a message means.
///
/// The discriminants are the numbers that go on the wire, so a new message
/// takes the next free one and leaves this list alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Kind {
    /// Init is running and has entered the namespaces it was told to join.
    ///
    /// Carries the process id the driver should record, which differs from the
    /// cloned child when a second fork was needed for a pid namespace.
    Ready = 1,
    /// The driver has written the id maps.
    IdMapsWritten = 3,
    /// The driver has put init into the container's cgroup, so init may make
    /// a cgroup namespace that is rooted there.
    CgroupJoined = 4,
    /// Init has applied the whole plan and is about to wait for the start
    /// signal.
    Prepared = 5,
    /// The driver has run the hooks that belong before the payload starts.
    Proceed = 6,
    /// Init has installed a seccomp filter with a notify listener and is
    /// handing the listener descriptor over for delivery.
    SeccompListener = 7,
    /// Init has applied everything the configuration asked for and has only
    /// the payload left to execute.
    Configured = 9,
    /// Init has built the container's filesystem and has not yet changed the
    /// root, which is where the hooks that run inside the container belong.
    Mounted = 10,
    /// The driver has run the hooks that belong at this point.
    HooksRun = 11,
    /// Init cannot create a device node itself and asks the driver to make
    /// it, handing over the directory it belongs in.
    ///
    /// Carries the device's position in the plan, which the driver reads the
    /// rest of the description from.
    MakeDevice = 12,
    /// The driver has created the device node init asked for.
    DeviceMade = 13,
    /// Init cannot reach a mount's source and asks the driver, which still
    /// has the identity the runtime was started with, to open it.
    ///
    /// Carries the mount's position in the plan.
    OpenSource = 14,
    /// The driver has opened the source, which comes with this message.
    SourceOpened = 15,
    /// Init could not do what it was asked.
    Failed = 8,
}

impl Kind {
    const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Ready),
            3 => Some(Self::IdMapsWritten),
            4 => Some(Self::CgroupJoined),
            5 => Some(Self::Prepared),
            6 => Some(Self::Proceed),
            7 => Some(Self::SeccompListener),
            8 => Some(Self::Failed),
            9 => Some(Self::Configured),
            10 => Some(Self::Mounted),
            11 => Some(Self::HooksRun),
            12 => Some(Self::MakeDevice),
            13 => Some(Self::DeviceMade),
            14 => Some(Self::OpenSource),
            15 => Some(Self::SourceOpened),
            _ => None,
        }
    }
}

/// One message.
#[derive(Clone, Copy)]
pub struct Message {
    /// What the message means.
    pub kind: Kind,
    /// A process id, or an index into the plan, for the messages that carry
    /// one.
    pub pid: i32,
    /// The errno of a failure, or zero.
    pub errno: i32,
    /// Description of a failure, as bytes.
    context: [u8; CONTEXT_MAX],
    /// How much of `context` is used.
    context_len: u8,
}

/// Bytes one message occupies on the wire.
pub const WIRE_SIZE: usize = 4 + 4 + 4 + 1 + 3 + CONTEXT_MAX;

/// How many messages the driver can have sent that init has not read. The
/// protocol is one exchange at a time, so this is a bound on a bug rather
/// than on ordinary traffic.
const MAX_UNREAD: usize = 4;

impl Message {
    /// A message with no payload.
    #[must_use]
    pub const fn new(kind: Kind) -> Self {
        Self {
            kind,
            pid: 0,
            errno: 0,
            context: [0u8; CONTEXT_MAX],
            context_len: 0,
        }
    }

    /// A message carrying a process id.
    #[must_use]
    pub const fn with_pid(kind: Kind, pid: i32) -> Self {
        let mut message = Self::new(kind);
        message.pid = pid;
        message
    }

    /// A message reporting a failure.
    #[must_use]
    pub fn failure(error: Error) -> Self {
        let mut message = Self::new(Kind::Failed);
        message.errno = error.errno();
        let bytes = error.context().as_bytes();
        let len = bytes.len().min(CONTEXT_MAX);
        if let (Some(dst), Some(src)) =
            (message.context.get_mut(..len), bytes.get(..len))
        {
            dst.copy_from_slice(src);
        }
        #[allow(clippy::cast_possible_truncation)]
        {
            message.context_len = len as u8;
        }
        message
    }

    /// A message reporting a failure that names what it was about.
    ///
    /// The name goes on the message rather than in the error, which carries
    /// a static description alone. One that does not fit is left out, since
    /// a truncated path reads as a different one, and so is one that is not
    /// text, which would cost the description with it.
    #[must_use]
    pub fn failure_named(error: Error, name: &[u8]) -> Self {
        let mut message = Self::failure(error);
        if core::str::from_utf8(name).is_err() {
            return message;
        }
        let at = usize::from(message.context_len);
        let quoted = name.len() + 3;
        let Some(room) = message.context.get_mut(at..at + quoted) else {
            return message;
        };
        let (open, rest) = room.split_at_mut(2);
        open.copy_from_slice(b" `");
        let (middle, close) = rest.split_at_mut(name.len());
        middle.copy_from_slice(name);
        close.copy_from_slice(b"`");
        #[allow(clippy::cast_possible_truncation)]
        {
            message.context_len = (at + quoted) as u8;
        }
        message
    }

    /// The failure description, when there is one.
    #[must_use]
    pub fn context(&self) -> &str {
        let len = usize::from(self.context_len);
        self.context
            .get(..len)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("")
    }

    /// Encodes the message into a buffer.
    pub fn encode(&self, out: &mut [u8; WIRE_SIZE]) {
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            if let Some(slot) = out.get_mut(at..at + bytes.len()) {
                slot.copy_from_slice(bytes);
            }
            at += bytes.len();
        };
        put(&(self.kind as u32).to_le_bytes());
        put(&self.pid.to_le_bytes());
        put(&self.errno.to_le_bytes());
        put(&[self.context_len, 0, 0, 0]);
        put(&self.context);
    }

    /// Decodes a message.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < WIRE_SIZE {
            return Err(Error::msg("sync: short message"));
        }
        let word = |at: usize| -> u32 {
            let mut bytes = [0u8; 4];
            if let Some(slice) = raw.get(at..at + 4) {
                bytes.copy_from_slice(slice);
            }
            u32::from_le_bytes(bytes)
        };
        let kind = Kind::from_u32(word(0))
            .ok_or_else(|| Error::msg("sync: unknown message"))?;
        #[allow(clippy::cast_possible_wrap)]
        let (pid, errno) = (word(4) as i32, word(8) as i32);
        let context_len = raw.get(12).copied().unwrap_or(0);
        let mut context = [0u8; CONTEXT_MAX];
        let len = usize::from(context_len).min(CONTEXT_MAX);
        if let (Some(dst), Some(src)) =
            (context.get_mut(..len), raw.get(16..16 + len))
        {
            dst.copy_from_slice(src);
        }
        Ok(Self {
            kind,
            pid,
            errno,
            context,
            context_len,
        })
    }

    /// Turns a failure message back into an error.
    ///
    /// The description crossed the socket as bytes, so it cannot become a
    /// `&'static str` again and the error carries a general one instead. The
    /// specific text is reported by [`expect`], which is the only place a
    /// failure message is read.
    #[must_use]
    pub fn into_error(self) -> Error {
        Error::new(self.errno, "container init failed")
    }
}

/// Sends a message.
pub fn send(socket: BorrowedFd<'_>, message: &Message) -> Result<()> {
    let mut raw = [0u8; WIRE_SIZE];
    message.encode(&mut raw);
    let written = rustix::io::write(socket, &raw).context("sync: write")?;
    sent_all(written, raw.len())
}

/// Sends a message with a descriptor attached.
///
/// The descriptor crosses as ancillary data, so the receiver ends up with its
/// own reference to the same open file, not a number that means nothing
/// outside this process.
pub fn send_fd(
    socket: BorrowedFd<'_>,
    message: &Message,
    fd: BorrowedFd<'_>,
) -> Result<()> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, sendmsg};

    let mut raw = [0u8; WIRE_SIZE];
    message.encode(&mut raw);
    let mut space = [core::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut buffer = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    if !buffer.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(Error::msg("sync: no room for the descriptor"));
    }
    let slices = [std::io::IoSlice::new(&raw)];
    let sent = sendmsg(
        socket,
        &slices,
        &mut buffer,
        rustix::net::SendFlags::empty(),
    )
    .context("sync: send descriptor")?;
    sent_all(sent, raw.len())
}

/// Receives a message and the descriptor attached to it.
pub fn receive_fd(
    socket: BorrowedFd<'_>,
) -> Result<(Message, Option<OwnedFd>)> {
    use rustix::net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        recvmsg,
    };

    let mut raw = [0u8; WIRE_SIZE];
    let mut space = [core::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut buffer = RecvAncillaryBuffer::new(&mut space);
    let mut slices = [std::io::IoSliceMut::new(&mut raw)];
    let received =
        match recvmsg(socket, &mut slices, &mut buffer, RecvFlags::empty()) {
            Ok(received) => received,
            // A peer that closed while a message it never read was still in its
            // queue leaves this end with a reset to report, and the kernel
            // reports it ahead of anything already received. Reading again is
            // what reaches that: the first read took the reset away with it.
            Err(rustix::io::Errno::CONNRESET) => {
                recvmsg(socket, &mut slices, &mut buffer, RecvFlags::empty())
                    .context("sync: receive descriptor")?
            }
            Err(e) => {
                return Err(Error::from(e).describe("sync: receive descriptor"));
            }
        };
    if received.bytes == 0 {
        return Err(Error::msg("sync: peer closed without reporting"));
    }
    // A packet longer than this protocol's is not one of its messages, and
    // the part that did fit would decode as though it were whole.
    if received.flags.contains(ReturnFlags::TRUNC) {
        return Err(Error::msg("sync: oversized message"));
    }
    let mut passed = None;
    for message in buffer.drain() {
        if let RecvAncillaryMessage::ScmRights(mut fds) = message {
            passed = fds.next();
        }
    }
    Ok((decode_whole(&raw, received.bytes)?, passed))
}

/// Receives a message.
///
/// A closed socket means the other side died without reporting, which is a
/// failure in its own right and has to be distinguishable from a message.
pub fn receive(socket: BorrowedFd<'_>) -> Result<Message> {
    use rustix::net::{RecvFlags, recv};

    let mut raw = [0u8; WIRE_SIZE];
    // `TRUNC` asks for the packet's own length, not the part that fitted, so a
    // packet longer than a message is seen for what it is instead of arriving
    // as a whole one.
    let (_, len) = match recv(socket, &mut raw[..], RecvFlags::TRUNC) {
        Ok(answer) => answer,
        // As in `receive_fd`: the reset is reported ahead of a message that
        // has already arrived, and reading again reaches the message.
        Err(rustix::io::Errno::CONNRESET) => {
            recv(socket, &mut raw[..], RecvFlags::TRUNC)
                .context("sync: read")?
        }
        Err(e) => return Err(Error::from(e).describe("sync: read")),
    };
    if len == 0 {
        return Err(Error::msg("sync: peer closed without reporting"));
    }
    decode_whole(&raw, len)
}

/// Decodes a message only when exactly one whole one arrived.
///
/// The buffer starts zeroed, so a packet cut short would otherwise decode as
/// itself padded with zeros: a truncated context reads as a shorter one and a
/// lost kind reads as no kind at all. A packet longer than a message is not
/// one either, and the part of it that fitted would decode as though it were
/// all of it. The socket keeps message boundaries, so the length is the
/// whole test.
fn decode_whole(raw: &[u8; WIRE_SIZE], received: usize) -> Result<Message> {
    if received != WIRE_SIZE {
        return Err(Error::msg("sync: short message"));
    }
    Message::decode(raw)
}

/// Empties anything the peer has already sent.
///
/// The driver sends its half of a handshake without waiting for init to be
/// ready for it, so a failure part way through can leave a message unread.
/// Closing a socket that still holds one resets the connection, and the
/// driver's next read fails with that instead of returning the reason init
/// is about to send. Draining first keeps the reason.
///
/// Non-blocking and bounded, because this runs while reporting a failure:
/// there is nothing to wait for and nothing worth failing over.
pub fn drain(socket: BorrowedFd<'_>) {
    use rustix::net::{RecvFlags, recv};

    let mut raw = [0u8; WIRE_SIZE];
    for _ in 0..MAX_UNREAD {
        match recv(socket, &mut raw[..], RecvFlags::DONTWAIT) {
            Ok((0, _)) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Receives a message and turns a failure into an error.
pub fn expect(socket: BorrowedFd<'_>, want: Kind) -> Result<Message> {
    let message = receive(socket)?;
    if message.kind == Kind::Failed {
        // The description init chose is the difference between knowing which
        // step failed and being told only that one did. This error type
        // cannot carry it, so the driver reads the message itself and keeps
        // both halves; what is left here is for init, which never receives a
        // failure because it is the only side that sends one.
        return Err(message.into_error());
    }
    if message.kind != want {
        return Err(Error::msg("sync: unexpected message"));
    }
    Ok(message)
}

/// Creates the socket pair the driver and init talk over.
pub fn pair() -> Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("sync: socketpair")
}

/// Checks that a whole packet left the process.
fn sent_all(written: usize, expected: usize) -> Result<()> {
    if written == expected {
        Ok(())
    } else {
        Err(Error::msg("sync: short write"))
    }
}
