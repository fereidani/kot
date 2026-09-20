//! The unified hierarchy.
//!
//! One tree, controllers enabled per node, and one directory per container.
//! Most of the work is translating the configuration's units into the ones the
//! unified files use, which differ from the legacy ones more often than not.

use crate::{
    cgroup::write::{ValueBuf, Writes},
    oci::spec::{BlockIo, Cpu, Memory, Resources},
    sys::error::{Error, Result},
};

/// The kernel's word for an absent limit.
const MAX: &str = "max";

/// Lowers a resource configuration into unified-hierarchy writes.
pub fn lower<'a>(
    resources: &'a Resources<'a>,
    out: &mut Writes<'a>,
) -> Result<()> {
    out.clear();
    if let Some(memory) = resources.memory.as_ref() {
        lower_memory(memory, out)?;
    }
    if let Some(cpu) = resources.cpu.as_ref() {
        lower_cpu(cpu, out)?;
    }
    if let Some(limit) = resources.pids_limit {
        out.signed("pids.max", limit, MAX)?;
    }
    if let Some(block_io) = resources.block_io.as_ref() {
        lower_block_io(block_io, out)?;
    }
    for limit in &resources.hugepage_limits {
        out.hugepage(limit.page_size, ".max", limit.limit)?;
    }
    lower_rdma(resources, out)?;

    // `unified` is written last so that a configuration can override anything
    // the translation above produced. That is the point of the field: it
    // reaches a knob the specification has no name for.
    for &(file, value) in &resources.unified {
        out.text(file, value)?;
    }
    Ok(())
}

/// The swap limit this hierarchy wants, from the total the configuration
/// states.
///
/// The configuration states memory plus swap combined, as the legacy hierarchy
/// took it. The unified hierarchy wants swap alone, so the memory limit comes
/// back out of it. A negative total means no limit.
pub fn swap_limit(swap: i64, limit: Option<i64>) -> Result<i64> {
    match (swap, limit) {
        (total, _) if total < 0 => Ok(-1),
        (total, Some(limit)) if limit >= 0 => {
            // A total below the memory limit leaves nothing for swap and
            // subtracting would go negative, which this hierarchy reads as no
            // limit at all. Asking for a tighter bound must not produce a
            // looser one.
            if total < limit {
                return Err(Error::msg(
                    "memory: swap total is below the memory limit",
                ));
            }
            Ok(total - limit)
        }
        (total, _) => Ok(total),
    }
}

fn lower_memory(memory: &Memory, out: &mut Writes<'_>) -> Result<()> {
    if let Some(limit) = memory.limit {
        out.signed("memory.max", limit, MAX)?;
    }
    if let Some(reservation) = memory.reservation {
        out.signed("memory.low", reservation, MAX)?;
    }
    if let Some(swap) = memory.swap {
        out.signed("memory.swap.max", swap_limit(swap, memory.limit)?, MAX)?;
    }
    if memory.disable_oom_killer == Some(true) {
        return Err(Error::msg(
            "memory: disableOOMKiller is not available on cgroup v2",
        ));
    }
    if memory.kernel.is_some() || memory.kernel_tcp.is_some() {
        // The unified hierarchy accounts kernel memory against the same limit,
        // so a separate one cannot be honoured. Silently ignoring it would
        // leave the container less constrained than asked.
        return Err(Error::msg(
            "memory: kernel limits are not available on cgroup v2",
        ));
    }
    Ok(())
}

fn lower_cpu<'a>(cpu: &'a Cpu<'a>, out: &mut Writes<'a>) -> Result<()> {
    if let Some(shares) = cpu.shares {
        out.unsigned("cpu.weight", shares_to_weight(shares))?;
    }
    if cpu.quota.is_some() || cpu.period.is_some() {
        out.build("cpu.max", |buf| {
            match cpu.quota {
                Some(quota) if quota > 0 => buf.push_i64(quota)?,
                _ => buf.push_str(MAX)?,
            }
            buf.push_str(" ")?;
            buf.push_u64(cpu.period.unwrap_or(100_000))
        })?;
    }
    if let Some(burst) = cpu.burst {
        // Burst arrived late and is absent on older kernels, so its write is
        // tolerated rather than required.
        out.with_optional(true, |out| out.unsigned("cpu.max.burst", burst))?;
    }
    if let Some(idle) = cpu.idle {
        out.with_optional(true, |out| {
            out.unsigned("cpu.idle", idle.unsigned_abs())
        })?;
    }
    if let Some(cpus) = cpu.cpus {
        out.text("cpuset.cpus", cpus)?;
    }
    if let Some(mems) = cpu.mems {
        out.text("cpuset.mems", mems)?;
    }
    if cpu.realtime_runtime.is_some() || cpu.realtime_period.is_some() {
        return Err(Error::msg(
            "cpu: realtime limits are not available on cgroup v2",
        ));
    }
    Ok(())
}

/// Converts a legacy CPU share into a unified weight.
///
/// Shares run from 2 to 262144 and weights from 1 to 10000, and the mapping
/// below is the one the kernel documents, so a configuration written for
/// either hierarchy lands on the same proportion of the machine.
#[must_use]
pub const fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }
    let clamped = if shares < 2 {
        2
    } else if shares > 262_144 {
        262_144
    } else {
        shares
    };
    1 + ((clamped - 2) * 9999) / 262_142
}

/// The I/O weight this hierarchy uses, from the one the configuration states.
///
/// Legacy weights run from 10 to 1000 and unified ones from 1 to 10000.
#[must_use]
pub fn io_weight(weight: u16) -> u64 {
    let scaled = u64::from(weight).saturating_mul(10000) / 1000;
    scaled.clamp(1, 10000)
}

fn lower_block_io(io: &BlockIo, out: &mut Writes<'_>) -> Result<()> {
    if let Some(weight) = io.weight {
        out.build("io.weight", |buf| {
            buf.push_str("default ")?;
            buf.push_u64(io_weight(weight))
        })?;
    }

    // Every rate for one device goes on one line, so collect them per device
    // rather than writing the same device several times.
    let mut devices: Vec<(i64, i64)> = Vec::new();
    for list in [
        &io.throttle_read_bps,
        &io.throttle_write_bps,
        &io.throttle_read_iops,
        &io.throttle_write_iops,
    ] {
        for device in list {
            let key = (device.major, device.minor);
            if !devices.contains(&key) {
                devices.push(key);
            }
        }
    }

    for (major, minor) in devices {
        let mut buf = ValueBuf::new();
        buf.push_i64(major)?;
        buf.push_str(":")?;
        buf.push_i64(minor)?;
        for (name, list) in [
            ("rbps", &io.throttle_read_bps),
            ("wbps", &io.throttle_write_bps),
            ("riops", &io.throttle_read_iops),
            ("wiops", &io.throttle_write_iops),
        ] {
            let Some(device) =
                list.iter().find(|d| d.major == major && d.minor == minor)
            else {
                continue;
            };
            buf.push_str(" ")?;
            buf.push_str(name)?;
            buf.push_str("=")?;
            buf.push_u64(device.rate)?;
        }
        out.rendered("io.max", buf)?;
    }

    if io.leaf_weight.is_some() || !io.weight_device.is_empty() {
        return Err(Error::msg(
            "blockIO: per-device weights are not available on cgroup v2",
        ));
    }
    Ok(())
}

fn lower_rdma(resources: &Resources<'_>, out: &mut Writes<'_>) -> Result<()> {
    if resources.rdma.is_empty() {
        return Ok(());
    }
    out.tolerate_missing(true);
    for &(device, limits) in &resources.rdma {
        out.rdma(device, limits, false)?;
    }
    out.tolerate_missing(false);
    Ok(())
}

/// Renders the `cgroup.subtree_control` value a container's parent needs.
///
/// A unified cgroup can only use a controller its parent has delegated, so the
/// parent's `cgroup.subtree_control` has to name it first. Doing this lazily,
/// only for the controllers the configuration actually uses, avoids disturbing
/// controllers the host has deliberately left off.
#[must_use]
pub fn subtree_control(resources: Option<&Resources<'_>>) -> ValueBuf {
    let mut buf = ValueBuf::new();
    let Some(resources) = resources else {
        return buf;
    };
    let wanted = [
        ("+cpu", resources.cpu.is_some()),
        (
            "+cpuset",
            resources
                .cpu
                .as_ref()
                .is_some_and(|c| c.cpus.is_some() || c.mems.is_some()),
        ),
        ("+memory", resources.memory.is_some()),
        ("+pids", resources.pids_limit.is_some()),
        ("+io", resources.block_io.is_some()),
        ("+hugetlb", !resources.hugepage_limits.is_empty()),
        ("+rdma", !resources.rdma.is_empty()),
    ];
    for (name, needed) in wanted {
        if !needed {
            continue;
        }
        if !buf.is_empty() {
            let _ = buf.push_str(" ");
        }
        let _ = buf.push_str(name);
    }
    buf
}
