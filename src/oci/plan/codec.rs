//! Reading and writing the plan arena.
//!
//! Every value in the arena is encoded explicitly, little endian, rather than
//! reinterpreted from raw bytes. That costs a few instructions per field and
//! buys two things worth more than those instructions: no `unsafe` anywhere
//! in the plan, and a decoder that validates what it reads instead of
//! trusting it. The plan crosses a process boundary, so trusting it would be
//! trusting whatever produced the memory file.

use crate::sys::error::{Error, Result};

/// A run of bytes inside the arena's string section.
///
/// Strings are stored once and referenced by offset, so a path that appears in
/// several records costs one copy.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Str {
    /// Offset from the start of the string section.
    pub at: u32,
    /// Length in bytes, not counting the terminator.
    pub len: u32,
}

impl Str {
    /// Number of bytes a `Str` occupies when encoded.
    pub const SIZE: usize = 8;

    /// The empty string.
    pub const EMPTY: Self = Self { at: 0, len: 0 };

    /// True when the reference names no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Appends encoded values to a buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// An empty writer with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Discards the contents, keeping the buffer for reuse.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Takes the encoded bytes, leaving the writer empty.
    #[must_use]
    pub fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }

    /// Appends an unsigned byte.
    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Appends a boolean as one byte.
    pub fn bool(&mut self, value: bool) {
        self.buf.push(u8::from(value));
    }

    /// Appends a 32-bit unsigned value.
    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a 32-bit signed value.
    pub fn i32(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a 64-bit unsigned value.
    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a 64-bit signed value.
    ///
    /// Signed because a clock offset can move a clock backwards as well as
    /// forwards.
    pub fn i64(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a string reference.
    pub fn str(&mut self, value: Str) {
        self.u32(value.at);
        self.u32(value.len);
    }

    /// Appends raw bytes.
    pub fn bytes(&mut self, value: &[u8]) {
        self.buf.extend_from_slice(value);
    }

    /// Pads to the next multiple of `alignment`.
    pub fn align(&mut self, alignment: usize) {
        debug_assert!(
            alignment.is_power_of_two(),
            "alignment is a power of two"
        );
        // Nothing needs padding to a boundary of one, and zero is not a
        // boundary; either way there is nothing to add, and saying so keeps
        // the division below from being by zero.
        if alignment < 2 {
            return;
        }
        while self.buf.len() % alignment != 0 {
            self.buf.push(0);
        }
    }
}

/// Reads encoded values out of a buffer.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Wraps a buffer.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    /// Wraps a buffer, starting at `offset`.
    pub fn at(buf: &'a [u8], offset: usize) -> Result<Self> {
        if offset > buf.len() {
            return Err(Error::msg("plan: offset past end"));
        }
        Ok(Self { buf, at: offset })
    }

    /// Reads an unsigned byte.
    pub fn u8(&mut self) -> Result<u8> {
        let value = *self
            .buf
            .get(self.at)
            .ok_or_else(|| Error::msg("plan: truncated"))?;
        self.at += 1;
        Ok(value)
    }

    /// Reads a boolean.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }

    /// Reads a 32-bit unsigned value.
    pub fn u32(&mut self) -> Result<u32> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    /// Reads a 32-bit signed value.
    pub fn i32(&mut self) -> Result<i32> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(i32::from_le_bytes(raw))
    }

    /// Reads a 64-bit unsigned value.
    pub fn u64(&mut self) -> Result<u64> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    /// Reads a 64-bit signed value.
    pub fn i64(&mut self) -> Result<i64> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    /// Reads a string reference.
    pub fn str(&mut self) -> Result<Str> {
        Ok(Str {
            at: self.u32()?,
            len: self.u32()?,
        })
    }

    /// Reads `len` raw bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| Error::msg("plan: length overflow"))?;
        let slice = self
            .buf
            .get(self.at..end)
            .ok_or_else(|| Error::msg("plan: truncated"))?;
        self.at = end;
        Ok(slice)
    }
}
