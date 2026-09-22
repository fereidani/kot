//! The systemd manager methods the runtime uses.
//!
//! Four methods. Everything else systemd exposes is somebody else's problem.

use crate::{
    cgroup::dbus::{Connection, marshal::Writer, message::Target},
    sys::error::Result,
};

/// Bus name of the systemd manager.
const DESTINATION: &str = "org.freedesktop.systemd1";
/// Object path of the systemd manager.
const PATH: &str = "/org/freedesktop/systemd1";
/// Interface of the systemd manager.
const INTERFACE: &str = "org.freedesktop.systemd1.Manager";

/// How systemd should handle a conflicting job.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Cancel any conflicting job.
    Replace,
}

impl Mode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Replace => "replace",
        }
    }
}

/// One property of a transient unit.
///
/// systemd types these strictly, so the variant tag has to match what the
/// property expects or the call is rejected with an unhelpful message.
#[derive(Clone, Copy, Debug)]
pub enum Property<'a> {
    /// A string-valued property, such as `Description` or `Slice`.
    Str(&'a str, &'a str),
    /// A boolean, such as `Delegate`.
    Bool(&'a str, bool),
    /// A 64-bit value, which covers every resource limit systemd takes.
    U64(&'a str, u64),
    /// The `PIDs` property, which places existing processes in the unit.
    Pids(&'a str, &'a [u32]),
    /// A 32-bit unsigned value, which some unit properties are typed as.
    U32(&'a str, u32),
    /// A 64-bit signed value, likewise.
    I64(&'a str, i64),
    /// A 32-bit signed value, such as `KillSignal`.
    I32(&'a str, i32),
}

impl Property<'_> {
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.align(8);
        let (Self::Str(name, _)
        | Self::Bool(name, _)
        | Self::U64(name, _)
        | Self::Pids(name, _)
        | Self::U32(name, _)
        | Self::I64(name, _)
        | Self::I32(name, _)) = self;
        w.string(name)?;
        match self {
            Self::Str(_, value) => w.variant_string(value),
            Self::Bool(_, value) => w.variant_bool(value),
            Self::U64(_, value) => w.variant_u64(value),
            Self::Pids(_, pids) => w.variant_u32_array(pids),
            Self::U32(_, value) => w.variant_u32(value),
            Self::I64(_, value) => w.variant_i64(value),
            Self::I32(_, value) => w.variant_i32(value),
        }
    }
}

/// Writes the `a(sv)` property array a unit call carries.
fn write_properties(
    w: &mut Writer<'_>,
    properties: &[Property<'_>],
) -> Result<()> {
    let mark = w.begin_array(8);
    for property in properties {
        property.write(w)?;
    }
    w.end_array(mark)
}

fn target(member: &'static str) -> Target<'static> {
    Target {
        destination: Some(DESTINATION),
        path: PATH,
        interface: INTERFACE,
        member,
    }
}

/// Creates a transient unit and returns the call's serial.
///
/// systemd answers immediately with a job object path; the unit itself is
/// created asynchronously. The caller therefore has two ways to learn the
/// cgroup is ready: wait for the `JobRemoved` signal, or watch for the cgroup
/// directory to appear. The second happens sooner, so the cgroup manager takes
/// it.
pub fn start_transient_unit(
    connection: &mut Connection,
    name: &str,
    mode: Mode,
    properties: &[Property<'_>],
) -> Result<u32> {
    connection.call(target("StartTransientUnit"), "ssa(sv)a(sa(sv))", |w| {
        w.string(name)?;
        w.string(mode.as_str())?;
        write_properties(w, properties)?;
        // The auxiliary unit list is always empty: a container scope has
        // no sub-units to create alongside it.
        let aux = w.begin_array(8);
        w.end_array(aux)
    })
}

/// Asks systemd to stop a unit and returns the call's serial.
///
/// The caller is not expected to wait for the resulting job. An empty scope is
/// collected by systemd on its own, and blocking on the job's completion
/// signal costs an order of magnitude more than the collection itself.
pub fn stop_unit(
    connection: &mut Connection,
    name: &str,
    mode: Mode,
) -> Result<u32> {
    connection.call(target("StopUnit"), "ss", |w| {
        w.string(name)?;
        w.string(mode.as_str())
    })
}

/// Clears the failed state of a unit, so its name can be reused.
pub fn reset_failed_unit(
    connection: &mut Connection,
    name: &str,
) -> Result<u32> {
    connection.call(target("ResetFailedUnit"), "s", |w| w.string(name))
}

/// Changes properties of a running unit, which is how `update` reaches
/// systemd-managed limits.
pub fn set_unit_properties(
    connection: &mut Connection,
    name: &str,
    runtime: bool,
    properties: &[Property<'_>],
) -> Result<u32> {
    connection.call(target("SetUnitProperties"), "sba(sv)", |w| {
        w.string(name)?;
        w.bool(runtime);
        write_properties(w, properties)
    })
}
