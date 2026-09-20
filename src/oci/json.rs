//! A pull parser for `config.json`.
//!
//! The parser reads from a memory mapping of the file and hands back `&str`
//! that borrows it, so a configuration is never copied into a document tree
//! and then copied again into typed values. Strings that contain escapes are
//! the one exception: those are unescaped into the arena, which is rare in
//! practice because the fields that carry escapes are Windows paths.
//!
//! Null is treated as absent rather than as a value. Tooling emits `null` for
//! optional fields it did not set, and every runtime has to accept that, so
//! [`Parser::next_key`] skips such fields before the caller ever sees them.

use bumpalo::Bump;

use crate::sys::error::{Error, Result};

/// Deepest nesting the parser will follow.
///
/// An OCI configuration nests about six levels. The limit exists so that a
/// hostile file cannot drive the recursion in [`Parser::skip_value`] into the
/// stack, and it is generous enough that no real configuration reaches it.
pub const MAX_DEPTH: u32 = 64;

/// What kind of value comes next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// An object, starting with `{`.
    Object,
    /// An array, starting with `[`.
    Array,
    /// A string, starting with a quote.
    String,
    /// A number.
    Number,
    /// `true` or `false`.
    Bool,
    /// `null`.
    Null,
}

/// A pull parser over a JSON document.
pub struct Parser<'a> {
    input: &'a [u8],
    arena: &'a Bump,
    at: usize,
    depth: u32,
}

impl<'a> Parser<'a> {
    /// Wraps `input`, allocating unescaped strings from `arena`.
    #[must_use]
    pub const fn new(input: &'a [u8], arena: &'a Bump) -> Self {
        Self {
            input,
            arena,
            at: 0,
            depth: 0,
        }
    }

    /// Fails unless the whole document has been consumed.
    pub fn finish(&mut self) -> Result<()> {
        self.skip_whitespace();
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(Error::msg("json: trailing content"))
        }
    }

    /// The kind of the next value, without consuming it.
    pub fn peek(&mut self) -> Result<Kind> {
        self.skip_whitespace();
        match self.current() {
            Some(b'{') => Ok(Kind::Object),
            Some(b'[') => Ok(Kind::Array),
            Some(b'"') => Ok(Kind::String),
            Some(b't' | b'f') => Ok(Kind::Bool),
            Some(b'n') => Ok(Kind::Null),
            Some(b'-' | b'0'..=b'9') => Ok(Kind::Number),
            Some(_) => Err(Error::msg("json: unexpected character")),
            None => Err(Error::msg("json: unexpected end of input")),
        }
    }

    /// Consumes the opening brace of an object.
    pub fn enter_object(&mut self) -> Result<()> {
        self.enter(b'{')
    }

    /// Consumes the opening bracket of an array.
    pub fn enter_array(&mut self) -> Result<()> {
        self.enter(b'[')
    }

    fn enter(&mut self, open: u8) -> Result<()> {
        self.skip_whitespace();
        if self.current() != Some(open) {
            return Err(Error::msg("json: expected an object or array"));
        }
        self.at += 1;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::msg("json: nesting too deep"));
        }
        Ok(())
    }

    /// Returns the next key in the current object, or `None` at its end.
    ///
    /// Fields whose value is `null` are skipped, because tooling writes `null`
    /// for an optional field it did not set and the OCI configuration treats
    /// that the same as leaving the field out.
    pub fn next_key(&mut self) -> Result<Option<&'a str>> {
        // Bounded by the input length: every iteration consumes at least the
        // four bytes of a `null` value plus its key.
        for _ in 0..u32::MAX {
            self.skip_whitespace();
            match self.current() {
                Some(b'}') => {
                    self.at += 1;
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(None);
                }
                Some(b',') => {
                    self.at += 1;
                    continue;
                }
                Some(b'"') => {}
                Some(_) => return Err(Error::msg("json: expected a key")),
                None => return Err(Error::msg("json: unterminated object")),
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.current() != Some(b':') {
                return Err(Error::msg("json: expected a colon"));
            }
            self.at += 1;
            if self.peek()? == Kind::Null {
                self.skip_value()?;
                continue;
            }
            return Ok(Some(key));
        }
        Err(Error::msg("json: object too long"))
    }

    /// Advances to the next array element.
    ///
    /// Returns false once the array is exhausted, having consumed its closing
    /// bracket.
    pub fn next_element(&mut self) -> Result<bool> {
        self.skip_whitespace();
        match self.current() {
            Some(b']') => {
                self.at += 1;
                self.depth = self.depth.saturating_sub(1);
                Ok(false)
            }
            Some(b',') => {
                self.at += 1;
                self.skip_whitespace();
                if self.current() == Some(b']') {
                    self.at += 1;
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(false);
                }
                Ok(true)
            }
            Some(_) => Ok(true),
            None => Err(Error::msg("json: unterminated array")),
        }
    }

    /// Reads a string.
    pub fn string(&mut self) -> Result<&'a str> {
        self.skip_whitespace();
        if self.current() != Some(b'"') {
            return Err(Error::msg("json: expected a string"));
        }
        let start = self.at + 1;
        let mut at = start;
        let mut escaped = false;
        while let Some(&byte) = self.input.get(at) {
            match byte {
                b'"' => {
                    let raw = self
                        .input
                        .get(start..at)
                        .ok_or_else(|| Error::msg("json: string range"))?;
                    self.at = at + 1;
                    return if escaped {
                        self.unescape(raw)
                    } else {
                        core::str::from_utf8(raw).map_err(|_| {
                            Error::msg("json: string is not UTF-8")
                        })
                    };
                }
                b'\\' => {
                    escaped = true;
                    at += 2;
                }
                // Control characters are not permitted unescaped.
                0x00..=0x1f => {
                    return Err(Error::msg("json: control character"));
                }
                _ => at += 1,
            }
        }
        Err(Error::msg("json: unterminated string"))
    }

    /// Reads a signed integer.
    ///
    /// Fractions and exponents are rejected rather than rounded: every number
    /// in an OCI configuration is an exact quantity, and silently truncating
    /// a memory limit would be worse than refusing the file.
    pub fn i64(&mut self) -> Result<i64> {
        self.skip_whitespace();
        let negative = self.current() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let start = self.at;
        let mut value: i128 = 0;
        while let Some(&byte) = self.input.get(self.at) {
            if !byte.is_ascii_digit() {
                break;
            }
            value = value * 10 + i128::from(byte - b'0');
            if value > i128::from(u64::MAX) {
                return Err(Error::msg("json: number out of range"));
            }
            self.at += 1;
        }
        if self.at == start {
            return Err(Error::msg("json: expected a number"));
        }
        if matches!(self.current(), Some(b'.' | b'e' | b'E')) {
            return Err(Error::msg("json: expected an integer"));
        }
        let signed = if negative { -value } else { value };
        i64::try_from(signed).map_err(|_| Error::msg("json: number too large"))
    }

    /// Reads an unsigned integer.
    pub fn u64(&mut self) -> Result<u64> {
        self.skip_whitespace();
        if self.current() == Some(b'-') {
            return Err(Error::msg("json: expected a non-negative number"));
        }
        let start = self.at;
        let mut value: u64 = 0;
        while let Some(&byte) = self.input.get(self.at) {
            if !byte.is_ascii_digit() {
                break;
            }
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| Error::msg("json: number out of range"))?;
            self.at += 1;
        }
        if self.at == start {
            return Err(Error::msg("json: expected a number"));
        }
        if matches!(self.current(), Some(b'.' | b'e' | b'E')) {
            return Err(Error::msg("json: expected an integer"));
        }
        Ok(value)
    }

    /// Reads an unsigned integer that has to fit in 32 bits.
    pub fn u32(&mut self) -> Result<u32> {
        let value = self.u64()?;
        u32::try_from(value)
            .map_err(|_| Error::msg("json: value exceeds 32 bits"))
    }

    /// Reads a boolean.
    pub fn bool(&mut self) -> Result<bool> {
        self.skip_whitespace();
        if self.consume(b"true") {
            Ok(true)
        } else if self.consume(b"false") {
            Ok(false)
        } else {
            Err(Error::msg("json: expected a boolean"))
        }
    }

    /// Consumes and discards the next value, whatever it is.
    pub fn skip_value(&mut self) -> Result<()> {
        match self.peek()? {
            Kind::Object => {
                self.enter_object()?;
                while self.next_key()?.is_some() {
                    self.skip_value()?;
                }
                Ok(())
            }
            Kind::Array => {
                self.enter_array()?;
                while self.next_element()? {
                    self.skip_value()?;
                }
                Ok(())
            }
            Kind::String => self.string().map(|_| ()),
            Kind::Number => self.skip_number(),
            Kind::Bool => self.bool().map(|_| ()),
            Kind::Null => {
                if self.consume(b"null") {
                    Ok(())
                } else {
                    Err(Error::msg("json: expected null"))
                }
            }
        }
    }

    /// Consumes a number without interpreting it.
    ///
    /// A field this parser reads is an exact quantity, so [`i64`] refuses a
    /// fraction or an exponent rather than rounding one. A number under a key
    /// nothing reads has no such requirement: it only has to be a number, and
    /// refusing a fraction there would fail a file over a field this runtime
    /// does not even look at.
    ///
    /// What the grammar does say still holds, so a malformed number is a
    /// malformed document wherever it appears.
    ///
    /// [`i64`]: Self::i64
    fn skip_number(&mut self) -> Result<()> {
        let malformed = || Error::msg("json: malformed number");
        self.take(b'-');
        // A leading zero stands alone: `01` is two tokens, not a number.
        if !self.take(b'0') && self.digits() == 0 {
            return Err(malformed());
        }
        if self.take(b'.') && self.digits() == 0 {
            return Err(malformed());
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            if self.digits() == 0 {
                return Err(malformed());
            }
        }
        Ok(())
    }

    /// Consumes `byte` if it is next, and says whether it was.
    fn take(&mut self, byte: u8) -> bool {
        if self.current() == Some(byte) {
            self.at += 1;
            return true;
        }
        false
    }

    /// Consumes a run of digits and returns how many there were.
    fn digits(&mut self) -> usize {
        let start = self.at;
        while self.current().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        self.at - start
    }

    /// Reads an array of strings into `out`, replacing its contents.
    pub fn string_array(&mut self, out: &mut Vec<&'a str>) -> Result<()> {
        out.clear();
        self.enter_array()?;
        while self.next_element()? {
            out.push(self.string()?);
        }
        Ok(())
    }

    /// Reads an array of unsigned integers into `out`, replacing its
    /// contents.
    pub fn u32_array(&mut self, out: &mut Vec<u32>) -> Result<()> {
        out.clear();
        self.enter_array()?;
        while self.next_element()? {
            out.push(self.u32()?);
        }
        Ok(())
    }

    /// Reads an object of string to string into `out`, replacing its
    /// contents.
    pub fn string_map(
        &mut self,
        out: &mut Vec<(&'a str, &'a str)>,
    ) -> Result<()> {
        out.clear();
        self.enter_object()?;
        while let Some(key) = self.next_key()? {
            let value = self.string()?;
            out.push((key, value));
        }
        Ok(())
    }

    /// Reads one object into `value`, calling `field` for each of its keys.
    ///
    /// The callback either reads the key's value or skips it, and either way
    /// leaves the parser positioned on the next key.
    pub fn object<T>(
        &mut self,
        mut value: T,
        mut field: impl FnMut(&mut Self, &'a str, &mut T) -> Result<()>,
    ) -> Result<T> {
        self.enter_object()?;
        while let Some(key) = self.next_key()? {
            field(self, key, &mut value)?;
        }
        Ok(value)
    }

    /// Reads an array of objects into `out`, replacing its contents.
    pub fn object_array<T: Default>(
        &mut self,
        out: &mut Vec<T>,
        mut field: impl FnMut(&mut Self, &'a str, &mut T) -> Result<()>,
    ) -> Result<()> {
        out.clear();
        self.enter_array()?;
        while self.next_element()? {
            let item = self.object(T::default(), &mut field)?;
            out.push(item);
        }
        Ok(())
    }

    /// Reads an object whose values are objects into `out`, replacing its
    /// contents.
    ///
    /// Each entry keeps the key it was found under.
    pub fn object_map<T: Default>(
        &mut self,
        out: &mut Vec<(&'a str, T)>,
        mut field: impl FnMut(&mut Self, &'a str, &mut T) -> Result<()>,
    ) -> Result<()> {
        out.clear();
        self.enter_object()?;
        while let Some(name) = self.next_key()? {
            let item = self.object(T::default(), &mut field)?;
            out.push((name, item));
        }
        Ok(())
    }

    fn current(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn consume(&mut self, literal: &[u8]) -> bool {
        if self.input.get(self.at..self.at + literal.len()) == Some(literal) {
            self.at += literal.len();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(&byte) = self.input.get(self.at) {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    /// Expands escapes into the arena.
    fn unescape(&self, raw: &[u8]) -> Result<&'a str> {
        let mut out = bumpalo::collections::String::with_capacity_in(
            raw.len(),
            self.arena,
        );
        let mut at = 0usize;
        // Bounded by the input's length: every iteration consumes at least
        // one byte, either a run or an escape.
        while at < raw.len() {
            let rest = raw.get(at..).unwrap_or(&[]);
            // The run up to the next escape is copied whole. Copying it a
            // byte at a time would read each byte of a multi-byte character
            // as a character of its own and re-encode it, so a literal `e`
            // with an acute accent would come out as two characters.
            let run =
                rest.iter().position(|&b| b == b'\\').unwrap_or(rest.len());
            if run > 0 {
                let text = rest
                    .get(..run)
                    .and_then(|bytes| core::str::from_utf8(bytes).ok())
                    .ok_or_else(|| Error::msg("json: string is not utf-8"))?;
                out.push_str(text);
                at += run;
                continue;
            }
            at += 1;
            let escape = raw
                .get(at)
                .copied()
                .ok_or_else(|| Error::msg("json: truncated escape"))?;
            at += 1;
            match escape {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{08}'),
                b'f' => out.push('\u{0c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let (ch, used) = decode_unicode_escape(raw, at)?;
                    out.push(ch);
                    at += used;
                }
                _ => return Err(Error::msg("json: unknown escape")),
            }
        }
        Ok(out.into_bump_str())
    }
}

/// Decodes a `\u` escape, following a surrogate pair when there is one.
///
/// Returns the character and how many bytes after the `u` were consumed.
fn decode_unicode_escape(raw: &[u8], at: usize) -> Result<(char, usize)> {
    let high = hex4(raw, at)?;
    if !(0xd800..0xdc00).contains(&high) {
        let ch = char::from_u32(high)
            .ok_or_else(|| Error::msg("json: invalid code point"))?;
        return Ok((ch, 4));
    }
    // A high surrogate must be followed by `\u` and a low surrogate.
    if raw.get(at + 4) != Some(&b'\\') || raw.get(at + 5) != Some(&b'u') {
        return Err(Error::msg("json: lone surrogate"));
    }
    let low = hex4(raw, at + 6)?;
    if !(0xdc00..0xe000).contains(&low) {
        return Err(Error::msg("json: invalid surrogate pair"));
    }
    let combined = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
    let ch = char::from_u32(combined)
        .ok_or_else(|| Error::msg("json: invalid code point"))?;
    Ok((ch, 10))
}

/// Reads four hexadecimal digits.
fn hex4(raw: &[u8], at: usize) -> Result<u32> {
    let mut value = 0u32;
    for offset in 0..4 {
        let byte = raw
            .get(at + offset)
            .copied()
            .ok_or_else(|| Error::msg("json: truncated escape"))?;
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return Err(Error::msg("json: bad hexadecimal digit")),
        };
        value = (value << 4) | digit;
    }
    Ok(value)
}
