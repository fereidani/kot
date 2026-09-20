//! Allocation-free path construction.
//!
//! The container init process may not allocate, but it still has to build
//! paths: cgroup files, `/proc` entries, mount destinations. [`PathBuf`] is a
//! fixed-capacity buffer that produces a `&CStr` without touching the heap.

use core::ffi::CStr;

use crate::sys::error::{EINVAL, ENAMETOOLONG, Error, Result};

/// The kernel's maximum path length, including the terminating NUL.
pub const PATH_MAX: usize = 4096;

/// The empty path, for calls that use `AT_EMPTY_PATH`.
pub const EMPTY: &CStr = c"";

/// A path buffer of the kernel's maximum size.
///
/// The generic form has a default, but a default on a const parameter does not
/// apply in expression position, so `Path::new()` is the spelling that works
/// without an annotation at every call site.
pub type Path = PathBuf<PATH_MAX>;

/// A fixed-capacity, NUL-terminated path buffer.
///
/// `N` counts the terminating NUL, so a buffer of `N` holds `N - 1` bytes of
/// path. An operation that would exceed the capacity fails with
/// `ENAMETOOLONG` rather than truncating, because a silently truncated path
/// would name the wrong file.
#[derive(Clone)]
pub struct PathBuf<const N: usize = PATH_MAX> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for PathBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PathBuf<N> {
    /// Rejects a capacity too small to hold a terminated path.
    ///
    /// Checked once per instantiation, at compile time, rather than per call
    /// under a debug assertion: every method here writes the terminator at the
    /// front of an empty buffer, so a zero-length one would be an
    /// out-of-bounds write that a release build would not have caught.
    const CAPACITY: () =
        assert!(N >= 2, "a path buffer must hold at least one byte");

    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        let () = Self::CAPACITY;
        Self {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// A buffer holding `path`.
    pub fn from(path: &[u8]) -> Result<Self> {
        let mut p = Self::new();
        p.push_bytes(path)?;
        Ok(p)
    }

    /// The path as a NUL-terminated string.
    #[must_use]
    pub fn as_c_str(&self) -> &CStr {
        // The buffer is zeroed on construction and every mutation keeps a NUL
        // at `len`, so a terminator is always present.
        self.buf
            .get(..=self.len)
            .map_or(EMPTY, |b| CStr::from_bytes_until_nul(b).unwrap_or(EMPTY))
    }

    /// The path without its terminating NUL.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Number of bytes currently held, excluding the terminator.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when nothing has been pushed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discards the contents, keeping the allocation, which there is none of.
    pub const fn clear(&mut self) {
        self.len = 0;
        self.buf[0] = 0;
    }

    /// Truncates to `len` bytes. Longer values are ignored.
    pub const fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
            self.buf[len] = 0;
        }
    }

    /// Appends raw bytes, rejecting any embedded NUL.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.contains(&0) {
            return Err(Error::new(EINVAL, "path: embedded NUL"));
        }
        let end = self.len + bytes.len();
        if end + 1 > N {
            return Err(Error::new(ENAMETOOLONG, "path: too long"));
        }
        let Some(dst) = self.buf.get_mut(self.len..end) else {
            return Err(Error::msg("path: capacity"));
        };
        dst.copy_from_slice(bytes);
        self.len = end;
        if let Some(t) = self.buf.get_mut(end) {
            *t = 0;
        }
        Ok(())
    }

    /// Appends a string.
    pub fn push_str(&mut self, s: &str) -> Result<()> {
        self.push_bytes(s.as_bytes())
    }

    /// Appends a path component, inserting a separator when one is needed.
    ///
    /// An absolute `component` replaces the buffer, matching the behaviour
    /// callers expect from path joining.
    pub fn join(&mut self, component: &[u8]) -> Result<()> {
        if component.first() == Some(&b'/') {
            self.clear();
            return self.push_bytes(component);
        }
        if component.is_empty() {
            return Ok(());
        }
        if !self.is_empty() && self.buf.get(self.len - 1) != Some(&b'/') {
            self.push_bytes(b"/")?;
        }
        self.push_bytes(component)
    }

    /// Appends a decimal integer.
    #[allow(clippy::cast_possible_truncation)]
    pub fn push_u64(&mut self, mut value: u64) -> Result<()> {
        // `u64::MAX` is 20 digits, so the loop always stops on `value` rather
        // than on the end of the buffer.
        let mut digits = [0u8; 20];
        let mut first = digits.len();
        for slot in digits.iter_mut().rev() {
            *slot = b'0' + (value % 10) as u8;
            first -= 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push_bytes(digits.get(first..).unwrap_or(&[]))
    }

    /// Appends a signed decimal integer.
    pub fn push_i64(&mut self, value: i64) -> Result<()> {
        if value < 0 {
            self.push_bytes(b"-")?;
        }
        self.push_u64(value.unsigned_abs())
    }

    /// Runs `f` with the buffer temporarily extended by `component`, then
    /// restores the previous length.
    ///
    /// For walking a set of paths that share a prefix without rebuilding the
    /// prefix for each one.
    pub fn scoped<T>(
        &mut self,
        component: &[u8],
        f: impl FnOnce(&CStr) -> Result<T>,
    ) -> Result<T> {
        let saved = self.len;
        let outcome = self.join(component).and_then(|()| f(self.as_c_str()));
        self.truncate(saved);
        outcome
    }
}

impl<const N: usize> core::fmt::Display for PathBuf<N> {
    /// Writes the path, replacing anything that is not UTF-8.
    ///
    /// Written out rather than deferred to `String::from_utf8_lossy`, which
    /// allocates a replacement string for exactly the paths a container can
    /// choose: a name with one stray byte in it would put an allocation on a
    /// path this module promises has none.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;

        let mut rest = self.as_bytes();
        // Bounded by the buffer: every turn either writes the whole of what
        // is left and returns, or consumes at least one byte.
        while !rest.is_empty() {
            let error = match core::str::from_utf8(rest) {
                Ok(text) => return f.write_str(text),
                Err(error) => error,
            };
            let valid = error.valid_up_to();
            let good = rest.get(..valid).unwrap_or_default();
            f.write_str(core::str::from_utf8(good).unwrap_or_default())?;
            f.write_char(char::REPLACEMENT_CHARACTER)?;
            // A sequence that is merely cut short ends the buffer, so the
            // rest of it is the one thing replaced.
            let bad = error.error_len().unwrap_or(rest.len() - valid);
            rest = rest.get(valid + bad..).unwrap_or_default();
        }
        Ok(())
    }
}

impl<const N: usize> core::fmt::Debug for PathBuf<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

/// Splits a path into its leading directory and its final component.
///
/// Returns `None` when there is no separator, so the whole path is the final
/// component.
#[must_use]
pub fn split_last(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let idx = path.iter().rposition(|&b| b == b'/')?;
    let dir = path.get(..idx).unwrap_or(&[]);
    let base = path.get(idx + 1..).unwrap_or(&[]);
    Some((if dir.is_empty() { b"/" } else { dir }, base))
}

/// Iterates the non-empty components of a path, ignoring leading and repeated
/// separators.
pub fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty())
}
