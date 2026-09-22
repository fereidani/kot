//! What a container is using, and the events a supervisor watches for.
//!
//! The numbers come from the cgroup, which keeps them in a different set of
//! files in each hierarchy and in different units. Reading and parsing are
//! separated here from where the bytes come from: the parsers below take the
//! text of a file, so what a given input produces can be checked without a
//! container, and the collection above them is only the question of which
//! file to read.

use crate::{
    cgroup::{Manager, write::read_all},
    json::Writer,
    sys::error::Result,
};

/// Processor time, in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cpu {
    /// Time spent in total.
    pub total: u64,
    /// Time spent in the kernel on the container's behalf.
    pub kernel: u64,
    /// Time spent running the container's own instructions.
    pub user: u64,
}

/// Memory in use and the bound on it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    /// Bytes in use.
    pub usage: u64,
    /// The limit, or zero when there is none.
    pub limit: u64,
    /// The most in use at once, where the hierarchy records it.
    pub peak: u64,
    /// How many times a limit was reached.
    pub failures: u64,
    /// Swap in use.
    pub swap_usage: u64,
    /// The swap limit, or zero when there is none.
    pub swap_limit: u64,
}

/// How many processes the container holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pids {
    /// Processes and threads now.
    pub current: u64,
    /// The limit, or zero when there is none.
    pub limit: u64,
}

/// One device's share of the block I/O figures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Device {
    /// Device major number.
    pub major: u64,
    /// Device minor number.
    pub minor: u64,
    /// Bytes read.
    pub read_bytes: u64,
    /// Bytes written.
    pub write_bytes: u64,
    /// Read operations.
    pub reads: u64,
    /// Write operations.
    pub writes: u64,
}

/// Everything one sample carries.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Processor time.
    pub cpu: Cpu,
    /// Memory.
    pub memory: Memory,
    /// Processes.
    pub pids: Pids,
    /// Block devices.
    pub devices: Vec<Device>,
    /// How many times the container has been killed for running out of
    /// memory, which is what an out-of-memory event is reported from.
    pub oom_kills: u64,
}

/// Reads the value of one key from a file of `key value` lines.
///
/// Returns zero for a key the hierarchy does not have, because a figure that
/// is not kept is not a figure of zero worth reporting differently: a caller
/// comparing samples sees no movement either way.
#[must_use]
pub fn field(text: &str, wanted: &str) -> u64 {
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        if parts.next() == Some(wanted) {
            return parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// Reads a file holding one number, treating the kernel's word for no limit
/// as none.
#[must_use]
pub fn number(text: &str) -> u64 {
    let text = text.trim();
    if text == "max" {
        return 0;
    }
    text.parse().unwrap_or(0)
}

/// Parses the unified hierarchy's processor accounting.
///
/// The unified files count microseconds; the figures here are nanoseconds,
/// the unit the older hierarchy reports and the one a caller comparing
/// samples across hosts has to be given consistently.
#[must_use]
pub fn unified_cpu(stat: &str) -> Cpu {
    Cpu {
        total: field(stat, "usage_usec").saturating_mul(1000),
        kernel: field(stat, "system_usec").saturating_mul(1000),
        user: field(stat, "user_usec").saturating_mul(1000),
    }
}

/// Parses the legacy hierarchy's processor accounting.
///
/// `usage` is already nanoseconds. `stat` counts clock ticks, which are a
/// hundredth of a second on every architecture this runtime targets.
#[must_use]
pub fn legacy_cpu(usage: &str, stat: &str) -> Cpu {
    /// Nanoseconds in one clock tick.
    const TICK: u64 = 10_000_000;

    Cpu {
        total: number(usage),
        kernel: field(stat, "system").saturating_mul(TICK),
        user: field(stat, "user").saturating_mul(TICK),
    }
}

/// Parses the unified hierarchy's per-device I/O figures.
///
/// Each line names a device and then counters as `key=value`, and a kernel
/// that does not keep one of them simply leaves it out.
#[must_use]
pub fn unified_devices(text: &str) -> Vec<Device> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_ascii_whitespace();
        let Some((major, minor)) = parts.next().and_then(split_device) else {
            continue;
        };
        let mut device = Device {
            major,
            minor,
            ..Device::default()
        };
        for field in parts {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let value = value.parse().unwrap_or(0);
            match key {
                "rbytes" => device.read_bytes = value,
                "wbytes" => device.write_bytes = value,
                "rios" => device.reads = value,
                "wios" => device.writes = value,
                _ => {}
            }
        }
        out.push(device);
    }
    out
}

/// Parses the legacy hierarchy's per-device I/O figures.
///
/// Two files carry them, one counting bytes and one counting operations, and
/// both use `major:minor operation value` lines with a total at the end that
/// names no device. Each file is folded into the same list, so a device that
/// appears in both is one entry.
#[must_use]
pub fn legacy_devices(bytes: &str, operations: &str) -> Vec<Device> {
    let mut out: Vec<Device> = Vec::new();
    for (text, counting_bytes) in [(bytes, true), (operations, false)] {
        for line in text.lines() {
            let mut parts = line.split_ascii_whitespace();
            let Some((major, minor)) = parts.next().and_then(split_device)
            else {
                continue;
            };
            let (Some(operation), Some(value)) = (parts.next(), parts.next())
            else {
                continue;
            };
            let value: u64 = value.parse().unwrap_or(0);
            let at = out
                .iter()
                .position(|d| d.major == major && d.minor == minor);
            let device = if let Some(at) = at {
                out.get_mut(at)
            } else {
                out.push(Device {
                    major,
                    minor,
                    ..Device::default()
                });
                out.last_mut()
            };
            let Some(device) = device else {
                continue;
            };
            match (operation, counting_bytes) {
                ("Read", true) => device.read_bytes = value,
                ("Write", true) => device.write_bytes = value,
                ("Read", false) => device.reads = value,
                ("Write", false) => device.writes = value,
                _ => {}
            }
        }
    }
    out
}

/// Splits a `major:minor` device name.
fn split_device(text: &str) -> Option<(u64, u64)> {
    let (major, minor) = text.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Renders one event.
///
/// The shape is the one supervisors already read: an envelope naming the
/// kind of event and the container, with the sample under `data`.
#[must_use]
pub fn render(kind: &str, id: &str, stats: Option<&Stats>) -> String {
    let mut json = Writer::compact();
    json.object(None);
    json.string(Some("type"), kind);
    json.string(Some("id"), id);
    if let Some(stats) = stats {
        json.object(Some("data"));
        render_cpu(&mut json, stats.cpu);
        render_memory(&mut json, stats.memory);

        json.object(Some("pids"));
        json.number(Some("current"), cast(stats.pids.current));
        json.number(Some("limit"), cast(stats.pids.limit));
        json.end_object();

        render_devices(&mut json, &stats.devices);
        json.end_object();
    }
    json.end_object();
    json.finish()
}

fn render_cpu(json: &mut Writer, cpu: Cpu) {
    json.object(Some("cpu"));
    json.object(Some("usage"));
    json.number(Some("total"), cast(cpu.total));
    json.number(Some("kernel"), cast(cpu.kernel));
    json.number(Some("user"), cast(cpu.user));
    json.end_object();
    json.end_object();
}

fn render_memory(json: &mut Writer, memory: Memory) {
    json.object(Some("memory"));
    json.object(Some("usage"));
    json.number(Some("usage"), cast(memory.usage));
    json.number(Some("limit"), cast(memory.limit));
    json.number(Some("max"), cast(memory.peak));
    json.number(Some("failcnt"), cast(memory.failures));
    json.end_object();
    json.object(Some("swap"));
    json.number(Some("usage"), cast(memory.swap_usage));
    json.number(Some("limit"), cast(memory.swap_limit));
    json.end_object();
    json.end_object();
}

fn render_devices(json: &mut Writer, devices: &[Device]) {
    json.object(Some("blkio"));
    json.array(Some("ioServiceBytesRecursive"));
    for device in devices {
        for (operation, value) in
            [("Read", device.read_bytes), ("Write", device.write_bytes)]
        {
            entry(json, device, operation, value);
        }
    }
    json.end_array();
    json.array(Some("ioServicedRecursive"));
    for device in devices {
        for (operation, value) in
            [("Read", device.reads), ("Write", device.writes)]
        {
            entry(json, device, operation, value);
        }
    }
    json.end_array();
    json.end_object();
}

fn entry(json: &mut Writer, device: &Device, operation: &str, value: u64) {
    json.object(None);
    json.number(Some("major"), cast(device.major));
    json.number(Some("minor"), cast(device.minor));
    json.string(Some("op"), operation);
    json.number(Some("value"), cast(value));
    json.end_object();
}

/// Narrows a counter to what the document can carry.
///
/// Every figure here is a count the kernel keeps as an unsigned word, and
/// JSON numbers are signed. None of them reach the boundary in practice, and
/// saturating there is better than reporting a negative count.
fn cast(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reads one cgroup file as text, or an empty string when it is not there.
fn read(manager: &Manager, controller: &str, file: &core::ffi::CStr) -> String {
    let Some(directory) = manager.place(controller) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    if read_all(directory, file, &mut bytes).is_err() {
        return String::new();
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// Takes one sample from a container's cgroup.
///
/// Every file is optional: a controller the host did not mount, or a figure
/// this kernel does not keep, leaves its part of the sample at zero rather
/// than failing the whole report. A supervisor asking what a container is
/// using is better served by the figures that exist than by an error naming
/// the one that does not.
pub fn collect(manager: &mut Manager, legacy: bool) -> Result<Stats> {
    let mut stats = Stats::default();
    if !manager.ready_for_stats()? {
        return Ok(stats);
    }

    if legacy {
        stats.cpu = legacy_cpu(
            &read(manager, "cpuacct", c"cpuacct.usage"),
            &read(manager, "cpuacct", c"cpuacct.stat"),
        );
        let memory = read(manager, "memory", c"memory.stat");
        stats.memory = Memory {
            usage: number(&read(manager, "memory", c"memory.usage_in_bytes")),
            limit: number(&read(manager, "memory", c"memory.limit_in_bytes")),
            peak: number(&read(
                manager,
                "memory",
                c"memory.max_usage_in_bytes",
            )),
            failures: number(&read(manager, "memory", c"memory.failcnt")),
            swap_usage: number(&read(
                manager,
                "memory",
                c"memory.memsw.usage_in_bytes",
            )),
            swap_limit: number(&read(
                manager,
                "memory",
                c"memory.memsw.limit_in_bytes",
            )),
        };
        stats.oom_kills = field(&memory, "oom_kill");
        stats.devices = legacy_devices(
            &read(
                manager,
                "blkio",
                c"blkio.throttle.io_service_bytes_recursive",
            ),
            &read(manager, "blkio", c"blkio.throttle.io_serviced_recursive"),
        );
        stats.pids = Pids {
            current: number(&read(manager, "pids", c"pids.current")),
            limit: number(&read(manager, "pids", c"pids.max")),
        };
        return Ok(stats);
    }

    stats.cpu = unified_cpu(&read(manager, "", c"cpu.stat"));
    stats.memory = Memory {
        usage: number(&read(manager, "", c"memory.current")),
        limit: number(&read(manager, "", c"memory.max")),
        peak: number(&read(manager, "", c"memory.peak")),
        failures: field(&read(manager, "", c"memory.events"), "max"),
        swap_usage: number(&read(manager, "", c"memory.swap.current")),
        swap_limit: number(&read(manager, "", c"memory.swap.max")),
    };
    stats.oom_kills = field(&read(manager, "", c"memory.events"), "oom_kill");
    stats.devices = unified_devices(&read(manager, "", c"io.stat"));
    stats.pids = Pids {
        current: number(&read(manager, "", c"pids.current")),
        limit: number(&read(manager, "", c"pids.max")),
    };
    Ok(stats)
}
