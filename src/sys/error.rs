//! The error type used by every layer that touches the kernel.
//!
//! An [`Error`] is two machine words: a raw errno and a static description of
//! what was being attempted. It never allocates, so it is usable inside the
//! container init process, where allocation is forbidden.

use core::fmt;

/// A failed operation, identified by errno and by what was attempted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error {
    errno: i32,
    context: &'static str,
}

impl Error {
    /// Builds an error from a positive errno value.
    #[must_use]
    pub const fn new(errno: i32, context: &'static str) -> Self {
        Self { errno, context }
    }

    /// Builds an error that has no corresponding errno, for invariants that
    /// the kernel never reports on.
    #[must_use]
    pub const fn msg(context: &'static str) -> Self {
        Self { errno: 0, context }
    }

    /// Builds an error from the current value of the C `errno` convention,
    /// that is, a negative return value from a raw syscall.
    #[must_use]
    pub const fn from_ret(ret: isize, context: &'static str) -> Self {
        // The range check bounds `-ret` to 1..4096, so the cast is exact on
        // every supported target.
        #[allow(clippy::cast_possible_truncation)]
        let errno = if ret < 0 && ret > -4096 {
            (-ret) as i32
        } else {
            0
        };
        Self { errno, context }
    }

    /// The raw errno, or zero when the failure did not come from a syscall.
    #[must_use]
    pub const fn errno(self) -> i32 {
        self.errno
    }

    /// What was being attempted when the failure happened.
    #[must_use]
    pub const fn context(self) -> &'static str {
        self.context
    }

    /// Replaces the context, keeping the errno.
    ///
    /// Used when an inner call's description is less useful than the caller's.
    #[must_use]
    pub const fn describe(self, context: &'static str) -> Self {
        Self {
            errno: self.errno,
            context,
        }
    }

    /// True when the failure means the kernel lacks the feature, so a caller
    /// may fall back to an older interface.
    #[must_use]
    pub const fn is_unsupported(self) -> bool {
        matches!(self.errno, ENOSYS | EOPNOTSUPP | EINVAL | EPERM)
    }

    /// True when the target of the operation did not exist.
    #[must_use]
    pub const fn is_not_found(self) -> bool {
        self.errno == ENOENT
    }

    /// True when the operation was interrupted and may be retried verbatim.
    #[must_use]
    pub const fn is_interrupted(self) -> bool {
        self.errno == EINTR
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errno == 0 {
            f.write_str(self.context)
        } else {
            write!(f, "{}: {}", self.context, strerror(self.errno))
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl core::error::Error for Error {}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self {
            errno: e.raw_os_error(),
            context: "syscall",
        }
    }
}

/// Result type used throughout the runtime.
pub type Result<T> = core::result::Result<T, Error>;

/// Adds a static description to a `Result` whose error lacks one.
pub trait Context<T> {
    /// Replaces the error's context with `context`.
    fn context(self, context: &'static str) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for core::result::Result<T, E> {
    fn context(self, context: &'static str) -> Result<T> {
        self.map_err(|e| e.into().describe(context))
    }
}

macro_rules! errno_table {
    ($($name:ident = $value:expr, $text:expr;)*) => {
        $(
            #[doc = $text]
            pub const $name: i32 = $value;
        )*

        /// Returns a short description for a known errno.
        #[must_use]
        pub const fn strerror(errno: i32) -> &'static str {
            match errno {
                $($value => $text,)*
                _ => "unknown error",
            }
        }
    };
}

errno_table! {
    EPERM = 1, "operation not permitted";
    ENOENT = 2, "no such file or directory";
    ESRCH = 3, "no such process";
    EINTR = 4, "interrupted system call";
    EIO = 5, "input/output error";
    ENXIO = 6, "no such device or address";
    E2BIG = 7, "argument list too long";
    ENOEXEC = 8, "exec format error";
    EBADF = 9, "bad file descriptor";
    ECHILD = 10, "no child processes";
    EAGAIN = 11, "resource temporarily unavailable";
    ENOMEM = 12, "cannot allocate memory";
    EACCES = 13, "permission denied";
    EFAULT = 14, "bad address";
    EBUSY = 16, "device or resource busy";
    EEXIST = 17, "file exists";
    EXDEV = 18, "invalid cross-device link";
    ENODEV = 19, "no such device";
    ENOTDIR = 20, "not a directory";
    EISDIR = 21, "is a directory";
    EINVAL = 22, "invalid argument";
    ENFILE = 23, "too many open files in system";
    EMFILE = 24, "too many open files";
    ENOTTY = 25, "inappropriate ioctl for device";
    ETXTBSY = 26, "text file busy";
    EFBIG = 27, "file too large";
    ENOSPC = 28, "no space left on device";
    ESPIPE = 29, "illegal seek";
    EROFS = 30, "read-only file system";
    EMLINK = 31, "too many links";
    EPIPE = 32, "broken pipe";
    ERANGE = 34, "numerical result out of range";
    ENAMETOOLONG = 36, "file name too long";
    ENOSYS = 38, "function not implemented";
    ENOTEMPTY = 39, "directory not empty";
    ELOOP = 40, "too many levels of symbolic links";
    ENODATA = 61, "no data available";
    EPROTO = 71, "protocol error";
    EOVERFLOW = 75, "value too large for defined data type";
    EOPNOTSUPP = 95, "operation not supported";
    EADDRINUSE = 98, "address already in use";
    ECONNRESET = 104, "connection reset by peer";
    ETIMEDOUT = 110, "connection timed out";
    ECONNREFUSED = 111, "connection refused";
    ESTALE = 116, "stale file handle";
    ECANCELED = 125, "operation canceled";
}
