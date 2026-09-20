//! cgroup management for the kot runtime.
//!
//! Both hierarchies are supported at full parity: cgroup v2 unified, and
//! cgroup v1 including hybrid hosts. Which one the host runs is settled once
//! at startup and selected by enum, so neither costs a virtual call on the
//! container start path.
//!
//! The systemd manager talks to systemd directly through the client in
//! [`dbus`], which replaces `libsystemd` and so leaves the runtime statically
//! linkable. It is also where most of the latency in a container start used to
//! be, and [`manager`] explains what changed.

#![deny(missing_docs)]

pub mod dbus;
pub mod devices;
pub mod layout;
pub mod manager;
pub mod v1;
pub mod v2;
pub mod write;

pub use layout::Layout;
pub use manager::{Kind, Manager};
