//! Writing the JSON the runtime's callers parse.
//!
//! Small and hand written, because the shapes are fixed and few: the state
//! record, the features report, and the generated specification. A serialiser
//! that could produce anything would be a larger dependency than the three
//! objects it would be used for.

use std::fmt::Write as _;

/// Builds a JSON document.
pub struct Writer {
    out: String,
    /// True when something has already been written at the current depth, so
    /// the next entry needs a separator.
    populated: Vec<bool>,
    indent: usize,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    /// An empty document.
    #[must_use]
    pub fn new() -> Self {
        Self {
            out: String::with_capacity(1024),
            populated: Vec::new(),
            indent: 0,
        }
    }

    /// The document written so far.
    #[must_use]
    pub fn finish(mut self) -> String {
        self.out.push('\n');
        self.out
    }

    /// Opens an object.
    pub fn object(&mut self, key: Option<&str>) {
        self.prefix(key);
        self.out.push('{');
        self.populated.push(false);
        self.indent += 1;
    }

    /// Opens an array.
    pub fn array(&mut self, key: Option<&str>) {
        self.prefix(key);
        self.out.push('[');
        self.populated.push(false);
        self.indent += 1;
    }

    /// Closes the innermost object or array.
    fn end(&mut self, closing: char) {
        let had_entries = self.populated.pop().unwrap_or(false);
        self.indent = self.indent.saturating_sub(1);
        if had_entries {
            self.newline();
        }
        self.out.push(closing);
    }

    /// Closes an object.
    pub fn end_object(&mut self) {
        self.end('}');
    }

    /// Closes an array.
    pub fn end_array(&mut self) {
        self.end(']');
    }

    /// Writes a string field.
    pub fn string(&mut self, key: Option<&str>, value: &str) {
        self.prefix(key);
        self.quoted(value);
    }

    /// Writes an integer field.
    pub fn number(&mut self, key: Option<&str>, value: i64) {
        self.prefix(key);
        let _ = write!(self.out, "{value}");
    }

    /// Writes a boolean field.
    pub fn boolean(&mut self, key: Option<&str>, value: bool) {
        self.prefix(key);
        self.out.push_str(if value { "true" } else { "false" });
    }

    /// Writes an array of strings.
    pub fn string_array<'a>(
        &mut self,
        key: &str,
        values: impl IntoIterator<Item = &'a str>,
    ) {
        self.array(Some(key));
        for value in values {
            self.string(None, value);
        }
        self.end_array();
    }

    fn prefix(&mut self, key: Option<&str>) {
        if let Some(last) = self.populated.last_mut() {
            if *last {
                self.out.push(',');
            }
            *last = true;
        }
        self.newline();
        if let Some(key) = key {
            self.quoted(key);
            self.out.push_str(": ");
        }
    }

    fn newline(&mut self) {
        if self.populated.is_empty() {
            return;
        }
        self.out.push('\n');
        for _ in 0..self.indent {
            self.out.push_str("  ");
        }
    }

    /// Writes a string with the escapes JSON requires.
    fn quoted(&mut self, value: &str) {
        self.out.push('"');
        for ch in value.chars() {
            match ch {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\r' => self.out.push_str("\\r"),
                '\t' => self.out.push_str("\\t"),
                // Everything below a space has to be escaped, and the numeric
                // form is the only one that covers all of them.
                c if (c as u32) < 0x20 => {
                    let _ = write!(self.out, "\\u{:04x}", c as u32);
                }
                c => self.out.push(c),
            }
        }
        self.out.push('"');
    }
}
