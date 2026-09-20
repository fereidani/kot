//! The part of the runtime that runs inside the container.
//!
//! Everything here is applied by the container init process, which runs from a
//! sealed image and reads a plan out of a memory file. Two constraints hold
//! throughout and are what the module boundaries are drawn around:
//!
//! - **No allocation while the plan is applied.** Init works from the mapped
//!   arena and fixed-size path buffers, and there is no parser anywhere in it.
//!   The owned collections that remain are built once, before the payload is
//!   executed, and each is bounded by the plan: the argument and environment
//!   pointer arrays, the supplementary group list, and the filter the plan
//!   carries.
//! - **No decisions.** Every question about whether a configuration is valid
//!   was answered while the plan was built, in the driver. What is left is
//!   syscalls, and the only failures left are the kernel's.

#![deny(missing_docs)]

pub mod copyup;
pub mod handoff;
pub mod init;
pub mod mount;
pub mod namespace;
pub mod process;
pub mod rootfs;
pub mod sync;
pub mod terminal;
