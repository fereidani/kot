//! The syscall boundary for the kot runtime.
//!
//! Everything that talks directly to the kernel lives here. Interfaces that
//! `rustix` already covers are used from there; the rest are wrapped in
//! [`raw`] and exposed as safe functions by the modules beside it. The
//! `unsafe` left above this module is confined to two things the type system
//! cannot express: adopting a descriptor handed over by number, and crossing
//! the clone and exec boundary.
//!
//! Two rules hold throughout:
//!
//! - No function here allocates, so every one of them is usable inside the
//!   container init process. [`heap`] is the allocator itself rather than a
//!   user of one, and is the only exception.
//! - Every error carries an errno and a static description of what failed, so
//!   init can report a failure to the driver as a fixed-size message.

#![deny(missing_docs)]

pub mod bpf;
pub mod caps;
pub mod clone;
pub mod error;
pub mod heap;
pub mod mountattr;
pub mod net;
pub mod path;
pub mod prctl;
pub mod process;
pub mod pty;
pub mod raw;
pub mod seccomp;
pub mod signal;
pub mod signalfd;

pub use error::{Context, Error, Result};
pub use path::{Path, PathBuf};
