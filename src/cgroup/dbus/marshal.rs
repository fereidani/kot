//! The D-Bus wire format, reduced to what talking to systemd needs.
//!
//! D-Bus marshalling is positional and alignment sensitive: every basic type
//! is written at a multiple of its own size, structures and the header field
//! array align to eight, and an array is a byte count followed by padding to
//! the element's alignment. Getting any of that wrong produces a message the
//! peer silently drops, so the writer below tracks alignment itself rather
//! than leaving it to call sites.

use crate::sys::error::{Error, Result};

/// Little endian, which every supported target uses natively.
pub const ENDIAN: u8 = b'l';

/// Largest message the runtime will build or accept.
///
/// The protocol allows 128 MB. Nothing systemd sends in reply to the handful
/// of methods used here comes near that, and accepting an arbitrary length
/// from a socket is how a parser becomes a memory exhaustion bug.
pub const MAX_MESSAGE: usize = 1 << 20;

/// Deepest container nesting the reader will follow.
///
/// The specification allows 32 arrays inside 32 structs, so 64 is every
/// message that can legitimately arrive. Anything deeper is a peer trying to
/// choose this process's stack depth for it.
const MAX_DEPTH: u32 = 64;

/// Where an array's length field and body begin, so the length can be
/// back-filled once the elements are written.
#[derive(Clone, Copy, Debug)]
pub struct ArrayMark {
    len_at: usize,
    body_at: usize,
}

/// Appends values to a message body, keeping D-Bus alignment.
pub struct Writer<'a> {
    buf: &'a mut Vec<u8>,
    /// Offset the alignment is measured from, which is the start of the
    /// message rather than the start of the buffer.
    base: usize,
}

impl<'a> Writer<'a> {
    /// Wraps `buf`, treating its current length as the message origin.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        let base = buf.len();
        Self { buf, base }
    }

    /// Wraps `buf` with an explicit origin, for writing a body that will be
    /// concatenated after a header.
    pub const fn with_base(buf: &'a mut Vec<u8>, base: usize) -> Self {
        Self { buf, base }
    }

    /// Bytes written so far, measured from the origin.
    #[must_use]
    pub fn position(&self) -> usize {
        self.buf.len() - self.base
    }

    /// Pads to the next multiple of `alignment`.
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(
            alignment.is_power_of_two() && alignment <= 8,
            "D-Bus alignments are 1, 2, 4 or 8"
        );
        let padding = padding_to(self.position(), alignment);
        let end = self.buf.len() + padding;
        self.buf.resize(end, 0);
    }

    /// Writes a single byte.
    pub fn byte(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Writes a 32-bit unsigned integer.
    pub fn u32(&mut self, value: u32) {
        self.align(4);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 64-bit unsigned integer.
    pub fn u64(&mut self, value: u64) {
        self.align(8);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a boolean, which travels as a 32-bit value.
    pub fn bool(&mut self, value: bool) {
        self.u32(u32::from(value));
    }

    /// Writes a string or object path: length, bytes, terminator.
    pub fn string(&mut self, value: &str) -> Result<()> {
        let len = u32::try_from(value.len())
            .map_err(|_| Error::msg("dbus: string too long"))?;
        self.u32(len);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// Writes a signature: a one-byte length, bytes, terminator.
    pub fn signature(&mut self, value: &str) -> Result<()> {
        let len = u8::try_from(value.len())
            .map_err(|_| Error::msg("dbus: signature too long"))?;
        self.buf.push(len);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// Begins an array.
    ///
    /// The length field covers the elements only and cannot be known until
    /// they are written, so it is back-filled by [`Writer::end_array`].
    pub fn begin_array(&mut self, element_alignment: usize) -> ArrayMark {
        self.align(4);
        let len_at = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_le_bytes());
        self.align(element_alignment);
        ArrayMark {
            len_at,
            body_at: self.buf.len(),
        }
    }

    /// Completes an array, filling in its length.
    pub fn end_array(&mut self, mark: ArrayMark) -> Result<()> {
        let len = u32::try_from(self.buf.len() - mark.body_at)
            .map_err(|_| Error::msg("dbus: array too long"))?;
        let Some(slot) = self.buf.get_mut(mark.len_at..mark.len_at + 4) else {
            return Err(Error::msg("dbus: array length out of range"));
        };
        slot.copy_from_slice(&len.to_le_bytes());
        Ok(())
    }

    /// Writes a variant holding a string.
    pub fn variant_string(&mut self, value: &str) -> Result<()> {
        self.signature("s")?;
        self.string(value)
    }

    /// Writes a variant holding a boolean.
    pub fn variant_bool(&mut self, value: bool) -> Result<()> {
        self.signature("b")?;
        self.bool(value);
        Ok(())
    }

    /// Writes a variant holding a 64-bit unsigned integer.
    pub fn variant_u64(&mut self, value: u64) -> Result<()> {
        self.signature("t")?;
        self.u64(value);
        Ok(())
    }

    /// Writes a variant holding a 32-bit unsigned integer.
    pub fn variant_u32(&mut self, value: u32) -> Result<()> {
        self.signature("u")?;
        self.u32(value);
        Ok(())
    }

    /// Writes a variant holding a 64-bit signed integer.
    #[allow(clippy::cast_sign_loss)]
    pub fn variant_i64(&mut self, value: i64) -> Result<()> {
        self.signature("x")?;
        // The wire carries the bits, which is what the cast keeps.
        self.u64(value as u64);
        Ok(())
    }

    /// Writes a variant holding a 32-bit signed integer.
    #[allow(clippy::cast_sign_loss)]
    pub fn variant_i32(&mut self, value: i32) -> Result<()> {
        self.signature("i")?;
        // As above.
        self.u32(value as u32);
        Ok(())
    }

    /// Writes a variant holding an array of 32-bit unsigned integers.
    pub fn variant_u32_array(&mut self, values: &[u32]) -> Result<()> {
        self.signature("au")?;
        let start = self.begin_array(4);
        for &value in values {
            self.u32(value);
        }
        self.end_array(start)
    }
}

/// Reads values out of a received message.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Wraps a complete message.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    /// Current offset, which alignment is measured against.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.at
    }

    /// Moves to `offset`, failing when it is past the end.
    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset > self.buf.len() {
            return Err(Error::msg("dbus: seek past end"));
        }
        self.at = offset;
        Ok(())
    }

    /// Skips padding to the next multiple of `alignment`.
    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let padded = self
            .at
            .checked_add(padding_to(self.at, alignment))
            .ok_or_else(|| Error::msg("dbus: alignment overflow"))?;
        if padded > self.buf.len() {
            return Err(Error::msg("dbus: padding past end"));
        }
        self.at = padded;
        Ok(())
    }

    /// Reads a single byte.
    pub fn byte(&mut self) -> Result<u8> {
        let Some(value) = self.take(1, "dbus: truncated byte")?.first() else {
            return Err(Error::msg("dbus: truncated byte"));
        };
        Ok(*value)
    }

    /// Reads a 32-bit unsigned integer.
    pub fn u32(&mut self) -> Result<u32> {
        self.align(4)?;
        let bytes = self.take(4, "dbus: truncated u32")?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(raw))
    }

    /// Reads a string or object path.
    pub fn string(&mut self) -> Result<&'a str> {
        let len = self.u32()? as usize;
        let bytes = self.take(len, "dbus: truncated string")?;
        self.terminator("dbus: unterminated string")?;
        core::str::from_utf8(bytes)
            .map_err(|_| Error::msg("dbus: string is not UTF-8"))
    }

    /// Reads a signature.
    pub fn signature(&mut self) -> Result<&'a str> {
        let len = self.byte()? as usize;
        let bytes = self.take(len, "dbus: truncated signature")?;
        self.terminator("dbus: unterminated signature")?;
        core::str::from_utf8(bytes)
            .map_err(|_| Error::msg("dbus: signature is not UTF-8"))
    }

    /// Steps over the byte that ends a string or a signature.
    ///
    /// The length already said where the value ends, so the terminator
    /// carries no information; reading it is how a value whose length ran
    /// past the end of the body is caught, and a byte that is not zero means
    /// the length and the body disagree.
    fn terminator(&mut self, error: &'static str) -> Result<()> {
        match self.buf.get(self.at) {
            Some(0) => {
                self.at += 1;
                Ok(())
            }
            _ => Err(Error::msg(error)),
        }
    }

    /// Takes a fixed run of bytes, leaving any terminator for the caller.
    fn take(&mut self, len: usize, error: &'static str) -> Result<&'a [u8]> {
        let bytes = self
            .buf
            .get(self.at..self.at + len)
            .ok_or_else(|| Error::msg(error))?;
        self.at += len;
        Ok(bytes)
    }

    /// Skips a value of the given single complete type.
    ///
    /// Only the shapes systemd sends are handled; anything else is reported
    /// rather than guessed at, because guessing would desynchronise the
    /// reader and make every later field wrong.
    pub fn skip(&mut self, signature: &str) -> Result<()> {
        let mut chars = signature.chars();
        self.skip_one(&mut chars, 0)
    }

    fn skip_one(
        &mut self,
        chars: &mut core::str::Chars<'_>,
        depth: u32,
    ) -> Result<()> {
        // A variant carries its own signature in the body, so without this
        // the peer chooses how deep the recursion goes and the only limit is
        // the message size. The specification caps nesting well below this.
        if depth > MAX_DEPTH {
            return Err(Error::msg("dbus: nested too deeply"));
        }
        let Some(code) = chars.next() else {
            return Ok(());
        };
        match code {
            'y' => {
                self.byte()?;
            }
            'b' | 'i' | 'u' => {
                self.u32()?;
            }
            'n' | 'q' => {
                self.align(2)?;
                self.at += 2;
            }
            'x' | 't' | 'd' => {
                self.align(8)?;
                self.at += 8;
            }
            's' | 'o' => {
                self.string()?;
            }
            'g' => {
                self.signature()?;
            }
            'v' => {
                let inner = self.signature()?.to_owned();
                self.skip_one(&mut inner.chars(), depth + 1)?;
            }
            'a' => {
                let len = self.u32()? as usize;
                let element = chars.clone().next().unwrap_or('y');
                self.align(alignment_of(element))?;
                self.at += len;
                // Consume the element type from the signature.
                skip_type(chars, depth + 1)?;
            }
            '(' => {
                self.align(8)?;
                loop {
                    let mut peek = chars.clone();
                    match peek.next() {
                        Some(')') => {
                            *chars = peek;
                            break;
                        }
                        None => {
                            return Err(Error::msg("dbus: unclosed struct"));
                        }
                        Some(_) => self.skip_one(chars, depth + 1)?,
                    }
                }
            }
            _ => return Err(Error::msg("dbus: unsupported type code")),
        }
        if self.at > self.buf.len() {
            return Err(Error::msg("dbus: value past end"));
        }
        Ok(())
    }
}

/// Advances past one complete type in a signature.
fn skip_type(chars: &mut core::str::Chars<'_>, depth: u32) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::msg("dbus: nested too deeply"));
    }
    let Some(code) = chars.next() else {
        return Ok(());
    };
    match code {
        'a' => skip_type(chars, depth + 1),
        '(' => loop {
            match chars.clone().next() {
                Some(')') => {
                    chars.next();
                    return Ok(());
                }
                None => return Err(Error::msg("dbus: unclosed struct")),
                Some(_) => skip_type(chars, depth + 1)?,
            }
        },
        _ => Ok(()),
    }
}

/// Alignment of a basic type code.
const fn alignment_of(code: char) -> usize {
    match code {
        'y' | 'g' | 'v' => 1,
        'n' | 'q' => 2,
        'x' | 't' | 'd' | '(' | '{' => 8,
        _ => 4,
    }
}

/// Bytes of padding needed before a value with the given alignment.
///
/// Nothing needs padding to a boundary of one, and an alignment of zero is not
/// a boundary at all. Answering zero for both keeps a caller that names an
/// alignment this protocol does not use from dividing by it: every alignment
/// D-Bus defines is one, two, four or eight.
const fn padding_to(offset: usize, alignment: usize) -> usize {
    if alignment < 2 {
        return 0;
    }
    (alignment - offset % alignment) % alignment
}
