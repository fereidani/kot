//! A D-Bus client sized for talking to systemd, and nothing else.
//!
//! This replaces `libsystemd`, which is the largest shared library other
//! runtimes link against and the reason they cannot be statically linked. The
//! runtime needs five methods, so the client implements those and stops.
//!
//! Where possible it connects to systemd's private socket rather than the
//! system bus. That skips the message broker, skips the `Hello` round trip
//! that assigns a bus name, and works when the broker is not running at all.
//!
//! The connection is non-blocking, so a request can be sent and left to land
//! while the caller gets on with something else and collects the reply later.
//! systemd's latency becomes background work rather than a stall.

pub mod marshal;
pub mod message;
pub mod systemd;

use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

use crate::{
    cgroup::dbus::{
        marshal::{MAX_MESSAGE, Writer},
        message::{Header, Target},
    },
    sys::error::{Error, Result},
};

/// systemd's private control socket, which bypasses the message broker.
const PRIVATE_SOCKET: &str = "/run/systemd/private";
/// The system bus, used when the private socket is not reachable.
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

/// A connection to systemd.
pub struct Connection {
    socket: UnixStream,
    /// Serial of the next outgoing message.
    serial: u32,
    /// Bytes received but not yet parsed into a complete message.
    inbox: Vec<u8>,
    /// Scratch buffer for outgoing messages.
    outbox: Vec<u8>,
    /// True when talking to the broker, which needs a destination on every
    /// call and a bus name of its own.
    brokered: bool,
}

impl Connection {
    /// Opens a connection, preferring the private socket.
    ///
    /// `bus_address` overrides the socket path, which is how a session bus
    /// reaches a user manager for rootless containers.
    pub fn open(bus_address: Option<&str>) -> Result<Self> {
        if let Some(path) = bus_address {
            return Self::connect(path, true);
        }
        match Self::connect(PRIVATE_SOCKET, false) {
            Ok(connection) => Ok(connection),
            Err(private) => {
                Self::connect(SYSTEM_BUS_SOCKET, true).map_err(|bus| {
                    if private.is_not_found() { bus } else { private }
                })
            }
        }
    }

    fn connect(path: &str, brokered: bool) -> Result<Self> {
        let socket = UnixStream::connect(Path::new(path))
            .map_err(|e| from_io(&e, "dbus: connect"))?;
        let mut connection = Self {
            socket,
            serial: 1,
            inbox: Vec::with_capacity(4096),
            outbox: Vec::with_capacity(4096),
            brokered,
        };
        connection.authenticate()?;
        if brokered {
            connection.hello()?;
        }
        connection
            .socket
            .set_nonblocking(true)
            .map_err(|e| from_io(&e, "dbus: set nonblocking"))?;
        Ok(connection)
    }

    /// Performs the `EXTERNAL` authentication handshake.
    ///
    /// The peer derives the caller's identity from the socket credentials, so
    /// the only thing sent is which user to expect. Both the private socket
    /// and the broker accept this.
    fn authenticate(&mut self) -> Result<()> {
        let uid = rustix::process::getuid().as_raw();
        let mut greeting = Vec::with_capacity(64);
        greeting.push(0u8);
        greeting.extend_from_slice(b"AUTH EXTERNAL ");
        let mut digits = [0u8; 20];
        let hex = hex_uid(uid, &mut digits);
        greeting.extend_from_slice(hex);
        // No `NEGOTIATE_UNIX_FD`: nothing the runtime asks systemd for passes
        // a descriptor, and skipping it means the peer sends exactly one
        // reply line, so the handshake cannot leave unread text in front of
        // the first binary message.
        greeting.extend_from_slice(b"\r\nBEGIN\r\n");
        self.socket
            .write_all(&greeting)
            .map_err(|e| from_io(&e, "dbus: auth write"))?;

        // The peer answers with one or two lines before `BEGIN` takes effect.
        // Read until the terminator of the last one, bounded so a peer that
        // never finishes cannot hang the runtime.
        let mut reply = [0u8; 256];
        let mut filled = 0usize;
        for _ in 0..8 {
            let n = self
                .socket
                .read(reply.get_mut(filled..).unwrap_or(&mut []))
                .map_err(|e| from_io(&e, "dbus: auth read"))?;
            if n == 0 {
                return Err(Error::msg("dbus: peer closed during auth"));
            }
            filled += n;
            let seen = reply.get(..filled).unwrap_or(&[]);
            if contains(seen, b"\r\n") && contains(seen, b"OK ") {
                return Ok(());
            }
            if contains(seen, b"REJECTED") || contains(seen, b"ERROR") {
                return Err(Error::msg("dbus: authentication rejected"));
            }
        }
        Err(Error::msg("dbus: authentication did not complete"))
    }

    /// Asks the broker for a bus name. Not needed on the private socket.
    fn hello(&mut self) -> Result<()> {
        let serial = self.call(
            Target {
                destination: Some("org.freedesktop.DBus"),
                path: "/org/freedesktop/DBus",
                interface: "org.freedesktop.DBus",
                member: "Hello",
            },
            "",
            |_| Ok(()),
        )?;
        self.wait_for_reply(serial, 5_000)?;
        Ok(())
    }

    /// True when this connection goes through the message broker, and so
    /// needs a destination on every call.
    #[must_use]
    pub const fn is_brokered(&self) -> bool {
        self.brokered
    }

    /// Sends a method call and returns its serial, without waiting.
    ///
    /// Not waiting is the point: the driver fires the call that creates a
    /// cgroup and then goes on preparing mounts and emitting the seccomp
    /// filter while systemd works.
    pub fn call<F>(
        &mut self,
        target: Target<'_>,
        signature: &str,
        body: F,
    ) -> Result<u32>
    where
        F: FnOnce(&mut Writer<'_>) -> Result<()>,
    {
        let serial = self.serial;
        self.serial = self.serial.wrapping_add(1).max(1);
        let target = Target {
            destination: if self.brokered {
                target.destination
            } else {
                None
            },
            ..target
        };
        // The scratch buffer is moved out and put back so that building the
        // message does not borrow the connection it is about to be sent on.
        let mut outbox = core::mem::take(&mut self.outbox);
        let built =
            message::build_call(&mut outbox, serial, target, signature, body);
        let outcome = built.and_then(|()| {
            self.socket
                .write_all(&outbox)
                .map_err(|e| from_io(&e, "dbus: write"))
        });
        self.outbox = outbox;
        outcome.map(|()| serial)
    }

    /// Reads whatever the peer has sent, without blocking.
    ///
    /// Returns false when nothing was available.
    pub fn poll(&mut self) -> Result<bool> {
        let mut chunk = [0u8; 4096];
        match self.socket.read(&mut chunk) {
            Ok(0) => Err(Error::msg("dbus: peer closed")),
            Ok(n) => {
                if self.inbox.len() + n > MAX_MESSAGE {
                    return Err(Error::msg("dbus: inbox overflow"));
                }
                self.inbox.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => Ok(false),
            Err(e) => Err(from_io(&e, "dbus: read")),
        }
    }

    /// Takes the next complete message out of the inbox, if there is one.
    ///
    /// The message is handed to `visit` along with its parsed header, then
    /// discarded, which keeps the borrow local and the inbox compact.
    pub fn take_message<T>(
        &mut self,
        visit: impl FnOnce(&Header<'_>, &[u8]) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(total) = message::message_length(&self.inbox)? else {
            return Ok(None);
        };
        if self.inbox.len() < total {
            return Ok(None);
        }
        let outcome = {
            let Some(raw) = self.inbox.get(..total) else {
                return Err(Error::msg("dbus: short message"));
            };
            let header = message::parse_header(raw)?;
            let Some(body) =
                raw.get(header.body_at..header.body_at + header.body_len)
            else {
                return Err(Error::msg("dbus: short body"));
            };
            visit(&header, body)?
        };
        self.inbox.drain(..total);
        Ok(Some(outcome))
    }

    /// Blocks until the reply to `serial` arrives or `timeout_ms` elapses.
    ///
    /// Used only where there is genuinely nothing else to do, such as the
    /// initial `Hello`. The container start path sends without waiting and
    /// collects the reply through [`Connection::poll`] instead.
    pub fn wait_for_reply(
        &mut self,
        serial: u32,
        timeout_ms: u32,
    ) -> Result<()> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(u64::from(timeout_ms));
        // Bounded by the deadline check below; the iteration cap is a second
        // guard so a peer that spins cannot wedge the runtime.
        for _ in 0..10_000 {
            if let Some(outcome) = self.find_reply(serial)? {
                return outcome;
            }
            let remaining =
                deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::msg("dbus: reply timed out"));
            }
            let mut fds = [PollFd::new(&self.socket, PollFlags::IN)];
            let spec = Timespec {
                tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
                tv_nsec: i64::from(remaining.subsec_nanos()),
            };
            poll(&mut fds, Some(&spec))
                .map_err(|e| Error::new(e.raw_os_error(), "dbus: poll"))?;
            self.poll()?;
        }
        Err(Error::msg("dbus: reply did not arrive"))
    }

    /// Scans buffered messages for the reply to `serial`.
    fn find_reply(&mut self, serial: u32) -> Result<Option<Result<()>>> {
        // Bounded: each iteration removes one message from the inbox.
        for _ in 0..1024 {
            let outcome = self.take_message(|header, _| {
                if header.reply_serial != Some(serial) {
                    return Ok(None);
                }
                if header.kind == message::ERROR {
                    return Ok(Some(Err(Error::msg("dbus: call failed"))));
                }
                Ok(Some(Ok(())))
            })?;
            match outcome {
                None => return Ok(None),
                Some(None) => {}
                Some(Some(result)) => return Ok(Some(result)),
            }
        }
        Ok(None)
    }
}

/// Formats a uid as the lowercase hex of its decimal spelling, the form the
/// `EXTERNAL` mechanism asks for.
///
/// Every byte of a decimal spelling is an ASCII digit, and the hex of one of
/// those is always `3` followed by the digit itself, so no general encoder is
/// needed.
fn hex_uid(uid: u32, out: &mut [u8; 20]) -> &[u8] {
    // Ten digits is the width of a u32, so the loop cannot outrun the buffer.
    let mut decimal = [0u8; 10];
    let mut first = decimal.len();
    let mut value = uid;
    for slot in decimal.iter_mut().rev() {
        *slot = b'0' + u8::try_from(value % 10).unwrap_or(0);
        first -= 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut written = 0usize;
    for (digit, pair) in decimal.iter().skip(first).zip(out.chunks_exact_mut(2))
    {
        pair.copy_from_slice(&[b'3', *digit]);
        written += 2;
    }
    out.get(..written).unwrap_or(&[])
}

/// True when `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Converts a standard I/O error into the runtime's error type.
fn from_io(error: &std::io::Error, context: &'static str) -> Error {
    Error::new(error.raw_os_error().unwrap_or(0), context)
}
