//! The list of file writes a cgroup configuration comes down to.
//!
//! Both backends lower a configuration into the same shape: a controller, a
//! file name relative to that controller's directory, and the exact bytes to
//! write. Rendering the bytes during lowering rather than at write time keeps
//! the apply path free of formatting, and it makes a configuration comparable
//! against a reference without starting a container.

use std::os::fd::BorrowedFd;

use crate::{
    oci::spec::Rdma,
    sys::{
        error::{Context, Error, Result},
        path::PathBuf,
    },
};

/// A rendered value.
///
/// The widest rendered value is a block I/O throttle line, which names a
/// device and four rates. A `cpuset.cpus` list can be longer on a very large
/// machine, so those stay borrowed text rather than being rendered.
pub type ValueBuf = PathBuf<192>;

/// A cgroup file name.
///
/// Most names are fixed, but huge page files are named after the page size, so
/// the name is a small buffer rather than a borrow. Sixty-four bytes covers
/// every name in either hierarchy.
pub type NameBuf = PathBuf<64>;

/// What to write into one cgroup file.
#[derive(Clone, Debug)]
pub enum Value<'a> {
    /// Text taken straight from the configuration.
    Text(&'a str),
    /// A value the runtime rendered.
    Rendered(ValueBuf),
}

impl Value<'_> {
    /// The bytes to write.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Rendered(buf) => buf.as_bytes(),
        }
    }
}

/// One file to write.
#[derive(Clone, Debug)]
pub struct Write<'a> {
    /// Controller whose directory the file lives in, or empty on the unified
    /// hierarchy where there is only one directory.
    pub controller: &'static str,
    /// File name, relative to that directory.
    pub file: NameBuf,
    /// Bytes to write.
    pub value: Value<'a>,
    /// True when a failure is not fatal, because the controller may simply not
    /// be compiled into this kernel.
    pub optional: bool,
    /// True when the value is appended rather than replacing the file, which
    /// the legacy device and throttle files need.
    pub append: bool,
}

/// Collects writes while lowering, so the caller owns the allocation.
#[derive(Default)]
pub struct Writes<'a> {
    entries: Vec<Write<'a>>,
    controller: &'static str,
    optional: bool,
}

impl<'a> Writes<'a> {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Discards the contents, keeping the buffer.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.controller = "";
        self.optional = false;
    }

    /// The collected writes.
    #[must_use]
    pub fn entries(&self) -> &[Write<'a>] {
        &self.entries
    }

    /// Sets the controller every later write belongs to.
    ///
    /// The legacy hierarchy has a directory per controller, and lowering walks
    /// one controller at a time, so saying it once per group is both less
    /// noise and less chance of attaching a file to the wrong tree.
    pub const fn controller(&mut self, name: &'static str) {
        self.controller = name;
    }

    /// Marks every later write as one whose failure is tolerable.
    pub const fn tolerate_missing(&mut self, tolerate: bool) {
        self.optional = tolerate;
    }

    /// Records writes with a different tolerance for just one call.
    pub(crate) fn with_optional(
        &mut self,
        optional: bool,
        write: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let previous = self.optional;
        self.optional = optional;
        let outcome = write(self);
        self.optional = previous;
        outcome
    }

    fn push(&mut self, file: NameBuf, value: Value<'a>, append: bool) {
        self.entries.push(Write {
            controller: self.controller,
            file,
            value,
            optional: self.optional,
            append,
        });
    }

    fn record(
        &mut self,
        file: &str,
        value: Value<'a>,
        append: bool,
    ) -> Result<()> {
        let file = NameBuf::from(file.as_bytes())?;
        self.push(file, value, append);
        Ok(())
    }

    /// Records a write of text taken from the configuration.
    pub fn text(&mut self, file: &str, value: &'a str) -> Result<()> {
        self.record(file, Value::Text(value), false)
    }

    /// Records a write of a rendered value.
    pub fn rendered(&mut self, file: &str, value: ValueBuf) -> Result<()> {
        self.record(file, Value::Rendered(value), false)
    }

    /// Records a hugepage limit.
    ///
    /// Both hierarchies name the file after the page size and differ only in
    /// the suffix, which the caller supplies.
    pub fn hugepage(
        &mut self,
        page_size: &str,
        suffix: &str,
        limit: u64,
    ) -> Result<()> {
        let mut file = NameBuf::new();
        file.push_str("hugetlb.")?;
        file.push_str(page_size)?;
        file.push_str(suffix)?;
        let mut value = ValueBuf::new();
        value.push_u64(limit)?;
        self.push(file, Value::Rendered(value), false);
        Ok(())
    }

    /// Records one RDMA limit line, appended only on the legacy hierarchy.
    pub(crate) fn rdma(
        &mut self,
        device: &str,
        limits: Rdma,
        append: bool,
    ) -> Result<()> {
        let mut value = ValueBuf::new();
        value.push_str(device)?;
        value.push_str(" hca_handle=")?;
        match limits.hca_handles {
            Some(limit) => value.push_u64(u64::from(limit))?,
            None => value.push_str("max")?,
        }
        value.push_str(" hca_object=")?;
        match limits.hca_objects {
            Some(limit) => value.push_u64(u64::from(limit))?,
            None => value.push_str("max")?,
        }
        if append {
            self.append("rdma.max", value)
        } else {
            self.rendered("rdma.max", value)
        }
    }

    /// Records a line appended to a file that accumulates entries, such as the
    /// legacy device and throttle files.
    pub fn append(&mut self, file: &str, value: ValueBuf) -> Result<()> {
        self.record(file, Value::Rendered(value), true)
    }

    /// Records a signed value, writing the given word for no limit when it is
    /// negative.
    pub fn signed(
        &mut self,
        file: &str,
        value: i64,
        unlimited: &str,
    ) -> Result<()> {
        let mut buf = ValueBuf::new();
        if value < 0 {
            buf.push_str(unlimited)?;
        } else {
            buf.push_i64(value)?;
        }
        self.rendered(file, buf)
    }

    /// Records an unsigned value.
    pub fn unsigned(&mut self, file: &str, value: u64) -> Result<()> {
        let mut buf = ValueBuf::new();
        buf.push_u64(value)?;
        self.rendered(file, buf)
    }

    /// Records a value built by `render`.
    pub fn build(
        &mut self,
        file: &str,
        render: impl FnOnce(&mut ValueBuf) -> Result<()>,
    ) -> Result<()> {
        self.rendered(file, built(render)?)
    }

    /// Records an appended value built by `render`.
    pub fn build_append(
        &mut self,
        file: &str,
        render: impl FnOnce(&mut ValueBuf) -> Result<()>,
    ) -> Result<()> {
        self.append(file, built(render)?)
    }
}

/// Runs `render` into one of the fixed-size value buffers.
fn built(render: impl FnOnce(&mut ValueBuf) -> Result<()>) -> Result<ValueBuf> {
    let mut buf = ValueBuf::new();
    render(&mut buf)?;
    Ok(buf)
}

/// Applies every write to one directory, as the unified hierarchy needs.
///
/// The directory stays open, so each write is one `openat` and one `write`
/// relative to a descriptor rather than a fresh path resolution.
pub fn apply(directory: BorrowedFd<'_>, writes: &[Write<'_>]) -> Result<()> {
    for write in writes {
        let outcome = write_one(
            directory,
            write.file.as_c_str(),
            write.value.as_bytes(),
            write.append,
        );
        match outcome {
            Ok(()) => {}
            // A controller the kernel does not implement cannot be configured,
            // and refusing to start for that reason would make the runtime
            // unusable on a stripped-down kernel.
            Err(_) if write.optional => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Writes one file relative to a cgroup directory.
pub fn write_one(
    directory: BorrowedFd<'_>,
    file: &core::ffi::CStr,
    value: &[u8],
    append: bool,
) -> Result<()> {
    use rustix::fs::{Mode, OFlags};

    let mut flags = OFlags::WRONLY | OFlags::CLOEXEC;
    if append {
        flags |= OFlags::APPEND;
    }
    let fd = rustix::fs::openat(directory, file, flags, Mode::empty())
        .context("cgroup: open file")?;
    let written = rustix::io::write(&fd, value).context("cgroup: write")?;
    if written != value.len() {
        return Err(Error::msg("cgroup: short write"));
    }
    Ok(())
}

/// Reads one file relative to a cgroup directory.
pub fn read_one(
    directory: BorrowedFd<'_>,
    file: &core::ffi::CStr,
    out: &mut [u8],
) -> Result<usize> {
    use rustix::fs::{Mode, OFlags};

    let fd = rustix::fs::openat(
        directory,
        file,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("cgroup: open file")?;
    rustix::io::read(&fd, out).context("cgroup: read")
}
