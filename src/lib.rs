//! kot: an OCI container runtime.
//!
//! One crate, in layers. `sys` is the syscall boundary, and the only place
//! that issues syscall instructions. `seccomp`, `cgroup` and `oci` sit on it
//! and know nothing about each other: a filter compiler, a control group
//! manager, and the specification with the plan it lowers to. `linux` is the
//! half that runs inside the container. The modules beside this file are the
//! runtime itself, the part a caller drives.

#![deny(missing_docs)]

pub mod cgroup;
pub(crate) mod linux;
pub mod oci;
pub mod seccomp;
pub mod sys;

mod cli;
mod commands;
mod devices;
mod driver;
mod exec;
mod features;
mod file;
mod hooks;
mod image;
mod json;
pub mod log;
mod seccomp_agent;
mod state;
mod template;
mod terminal;
mod update;
mod validate;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::state::{Record, Status};

/// Every allocation in the process comes from here; see [`sys::heap`] for
/// why a runtime that lives a few milliseconds wants a heap of its own.
#[global_allocator]
static HEAP: sys::heap::Heap = sys::heap::Heap;

/// Exit code for a runtime failure, as distinct from a payload's own status.
pub const FAILURE: i32 = 255;

/// Runs one command line and returns the code the caller should exit with.
///
/// # Errors
///
/// Returns whatever the command failed with, for the entry point to report.
pub fn run(argv: &[String]) -> Result<i32> {
    let (global, command) = cli::parse(argv)?;
    log::configure(&global);

    // The init subcommand is the runtime re-entering itself from a sealed
    // image. It never returns on success, and it reports failures back to the
    // driver over a socket rather than to a terminal that may not exist.
    if let cli::Command::Init { args } = &command {
        let parsed = crate::linux::handoff::InitArgs::decode(args)?;
        let failure = crate::linux::init::run(&parsed);
        if failure.reported {
            // The driver has it and reports it where the caller is looking.
            return Ok(FAILURE);
        }
        return Err(anyhow::anyhow!("{}", failure.error));
    }

    let store = state::Store::open(global.root.as_deref())?;
    commands::dispatch(&global, &store, &command)
}

/// The current time, as the timestamp the state record carries.
///
/// Rendered by hand instead of through a date library: the format is fixed,
/// the input is a count of seconds, and a dependency for this would be a
/// liability out of proportion to twenty lines.
#[must_use]
pub fn now() -> String {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = since.as_secs();
    let nanos = since.subsec_nanos();

    let days = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        time_of_day / 3600,
        (time_of_day / 60) % 60,
        time_of_day % 60,
    )
}

/// Converts a day count since the epoch into a calendar date.
///
/// The arithmetic treats March as the first month, which makes the leap day
/// the last day of the year and removes every special case from the
/// conversion.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let year = year_of_era + era * 400;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Opens the cgroup manager a container was created with.
///
/// The manager is rebuilt from the state record and never from the
/// configuration, so that `delete` undoes exactly what `create` did even if
/// the bundle has changed since.
pub fn cgroup_for(record: &Record) -> Result<crate::cgroup::Manager> {
    let kind = crate::cgroup::Kind::by_name(&record.cgroup_manager)
        .unwrap_or(crate::cgroup::Kind::Cgroupfs);
    let path =
        (!record.cgroup_path.is_empty()).then_some(record.cgroup_path.as_str());
    let path = match kind {
        crate::cgroup::Kind::Systemd if !record.systemd_unit.is_empty() => None,
        _ => path,
    };
    let mut manager = crate::cgroup::Manager::new(kind, path, &record.id)?;
    let _ = manager.wait_ready();
    Ok(manager)
}

/// The status to report to a caller, including whether the container is
/// frozen.
///
/// Whether a container is paused is kept by the kernel in the cgroup rather
/// than in the state record, because the run of the runtime that reports a
/// container's state is never the run that paused it. Answering costs a read,
/// so only the commands that report state ask.
#[must_use]
pub fn observed_status(record: &Record) -> Status {
    refine_status(record, state::observe(record))
}

/// The same answer for a caller that already established whether the
/// container is alive.
///
/// Both halves cost syscalls, so a command that has already asked passes the
/// answer in instead of asking again.
#[must_use]
pub fn refine_status(record: &Record, status: Status) -> Status {
    if status != Status::Running {
        return status;
    }
    let Ok(mut manager) = cgroup_for(record) else {
        return status;
    };
    if manager.frozen().unwrap_or(false) {
        Status::Paused
    } else {
        status
    }
}

/// Waits for a process and returns the exit code a caller should see.
pub fn wait_for_process(pid: i32) -> Result<i32> {
    use rustix::process::{Pid, WaitOptions, waitpid};
    let Some(pid) = Pid::from_raw(pid) else {
        anyhow::bail!("there is no process to wait for");
    };
    // Bounded: only an interrupted wait repeats, and a signal cannot arrive
    // without bound.
    for _ in 0..100_000 {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                if let Some(code) = status.exit_status() {
                    return Ok(code);
                }
                if let Some(signal) = status.terminating_signal() {
                    // The convention every shell uses, and what a caller
                    // expects to see when a container is killed.
                    return Ok(128 + signal);
                }
                return Ok(0);
            }
            Ok(None) => {}
            Err(e) if e.raw_os_error() == crate::sys::error::EINTR => {}
            Err(e) => return Err(anyhow::Error::new(e).context("waiting")),
        }
    }
    anyhow::bail!("gave up waiting for the process")
}

/// Who created a container, for the state record.
#[must_use]
pub fn owner() -> String {
    let uid = rustix::process::geteuid().as_raw();
    // The name would have to come from the host's user database, which this
    // runtime deliberately does not read. The number identifies the owner just
    // as well and cannot be wrong.
    format!("{uid}")
}
