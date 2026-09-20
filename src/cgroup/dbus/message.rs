//! D-Bus message headers: building calls and parsing what comes back.

use crate::{
    cgroup::dbus::marshal::{ENDIAN, MAX_MESSAGE, Reader, Writer},
    sys::error::{Error, Result},
};

/// Message type: a method call.
pub const METHOD_CALL: u8 = 1;
/// Message type: an error reply.
pub const ERROR: u8 = 3;

/// Header field: object path.
const FIELD_PATH: u8 = 1;
/// Header field: interface name.
const FIELD_INTERFACE: u8 = 2;
/// Header field: member name.
const FIELD_MEMBER: u8 = 3;
/// Header field: error name.
const FIELD_ERROR_NAME: u8 = 4;
/// Header field: serial of the message being replied to.
const FIELD_REPLY_SERIAL: u8 = 5;
/// Header field: destination bus name.
const FIELD_DESTINATION: u8 = 6;
/// Header field: body signature.
const FIELD_SIGNATURE: u8 = 8;

/// Fixed part of a D-Bus header, before the field array.
const HEADER_PREFIX: usize = 12;

/// Where to send a method call.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// Bus name, or `None` on a direct peer connection where there is no bus
    /// to route through.
    pub destination: Option<&'a str>,
    /// Object path.
    pub path: &'a str,
    /// Interface name.
    pub interface: &'a str,
    /// Member name.
    pub member: &'a str,
}

/// Builds a method call into `buf`, calling `body` to write the arguments.
pub fn build_call<F>(
    buf: &mut Vec<u8>,
    serial: u32,
    target: Target<'_>,
    signature: &str,
    body: F,
) -> Result<()>
where
    F: FnOnce(&mut Writer<'_>) -> Result<()>,
{
    buf.clear();
    let mut w = Writer::new(buf);
    w.byte(ENDIAN);
    w.byte(METHOD_CALL);
    // No flags: every call the runtime makes wants its reply.
    w.byte(0);
    w.byte(1);
    w.u32(0); // body length, filled in below
    w.u32(serial);

    let fields = w.begin_array(8);
    write_field_string(&mut w, FIELD_PATH, "o", target.path)?;
    write_field_string(&mut w, FIELD_INTERFACE, "s", target.interface)?;
    write_field_string(&mut w, FIELD_MEMBER, "s", target.member)?;
    if let Some(destination) = target.destination {
        write_field_string(&mut w, FIELD_DESTINATION, "s", destination)?;
    }
    if !signature.is_empty() {
        // The variant's type here really is `g`, and its value is the body
        // signature, so this one does write two signatures.
        w.align(8);
        w.byte(FIELD_SIGNATURE);
        w.signature("g")?;
        w.signature(signature)?;
    }
    w.end_array(fields)?;

    // The body always starts on an eight byte boundary.
    w.align(8);
    let body_start = buf.len();
    let mut body_writer = Writer::with_base(buf, body_start);
    body(&mut body_writer)?;

    let body_len = u32::try_from(buf.len() - body_start)
        .map_err(|_| Error::msg("dbus: body too long"))?;
    let Some(slot) = buf.get_mut(4..8) else {
        return Err(Error::msg("dbus: header truncated"));
    };
    slot.copy_from_slice(&body_len.to_le_bytes());
    Ok(())
}

/// Writes one header field: a byte code followed by a variant.
///
/// A variant is its own type signature followed by the value, so the
/// signature written here is the type of `value`, not the literal `g` that
/// describes a signature. Writing `g` first was a real bug: systemd accepted
/// the connection and then silently dropped every message.
fn write_field_string(
    w: &mut Writer<'_>,
    code: u8,
    signature: &str,
    value: &str,
) -> Result<()> {
    w.align(8);
    w.byte(code);
    w.signature(signature)?;
    w.string(value)
}

/// The parts of a received message the runtime looks at.
#[derive(Clone, Copy, Debug, Default)]
pub struct Header<'a> {
    /// Message type.
    pub kind: u8,
    /// Serial of this message.
    pub serial: u32,
    /// Serial this message replies to, when it is a reply.
    pub reply_serial: Option<u32>,
    /// Member name, for signals.
    pub member: Option<&'a str>,
    /// Interface name, for signals.
    pub interface: Option<&'a str>,
    /// Error name, when the message is an error reply.
    pub error_name: Option<&'a str>,
    /// Body signature.
    pub signature: Option<&'a str>,
    /// Offset at which the body starts.
    pub body_at: usize,
    /// Length of the body.
    pub body_len: usize,
}

/// Length of a complete message, given at least its first sixteen bytes.
///
/// Returns `None` when `buf` is too short to tell yet.
pub fn message_length(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 16 {
        return Ok(None);
    }
    if buf.first() != Some(&ENDIAN) {
        return Err(Error::msg("dbus: unexpected byte order"));
    }
    let mut r = Reader::new(buf);
    r.seek(4)?;
    let body_len = r.u32()? as usize;
    r.u32()?; // serial
    let fields_len = r.u32()? as usize;
    let header_len = HEADER_PREFIX + 4 + fields_len;
    let padded = header_len.next_multiple_of(8);
    let total = padded + body_len;
    if total > MAX_MESSAGE {
        return Err(Error::msg("dbus: message too large"));
    }
    Ok(Some(total))
}

/// Parses the header of a complete message.
pub fn parse_header(buf: &[u8]) -> Result<Header<'_>> {
    let mut r = Reader::new(buf);
    if r.byte()? != ENDIAN {
        return Err(Error::msg("dbus: unexpected byte order"));
    }
    let kind = r.byte()?;
    r.byte()?; // flags
    r.byte()?; // protocol version
    let body_len = r.u32()? as usize;
    let serial = r.u32()?;

    let fields_len = r.u32()? as usize;
    let fields_end = r.position() + fields_len;
    let mut header = Header {
        kind,
        serial,
        ..Header::default()
    };

    // Each field is a struct of a byte code and a variant, aligned to eight.
    // A bounded loop: every iteration consumes at least the four bytes a
    // minimal field occupies, so it cannot run longer than the field array.
    while r.position() < fields_end {
        r.align(8)?;
        if r.position() >= fields_end {
            break;
        }
        let code = r.byte()?;
        let variant = r.signature()?;
        match (code, variant) {
            (FIELD_PATH | FIELD_DESTINATION, _) => {
                r.string()?;
            }
            (FIELD_INTERFACE, "s") => header.interface = Some(r.string()?),
            (FIELD_MEMBER, "s") => header.member = Some(r.string()?),
            (FIELD_ERROR_NAME, "s") => header.error_name = Some(r.string()?),
            (FIELD_REPLY_SERIAL, "u") => header.reply_serial = Some(r.u32()?),
            (FIELD_SIGNATURE, "g") => header.signature = Some(r.signature()?),
            _ => r.skip(variant)?,
        }
    }

    r.seek(fields_end)?;
    r.align(8)?;
    header.body_at = r.position();
    header.body_len = body_len;
    if header.body_at + body_len > buf.len() {
        return Err(Error::msg("dbus: body past end of message"));
    }
    Ok(header)
}
