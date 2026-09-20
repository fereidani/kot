//! The legacy hierarchy.
//!
//! One tree per controller, different file names, and different units from the
//! unified hierarchy for most values. None of that is structural: it is a
//! second table feeding the same executor, which is why supporting both costs
//! a file rather than a second design.
//!
//! One thing here is not just a table: the freezer is not synchronous, so
//! pausing has to wait for the transition it starts to settle.

use std::os::fd::BorrowedFd;

use crate::{
    cgroup::write::{ValueBuf, Writes},
    oci::spec::{BlockIo, Cpu, Memory, Network, Resources},
    sys::error::{Error, Result},
};

/// The legacy hierarchy's word for an absent limit.
const UNLIMITED: &str = "-1";
/// The legacy hierarchy's word for an absent process limit.
const MAX: &str = "max";

/// Lowers a resource configuration into legacy-hierarchy writes.
pub fn lower<'a>(
    resources: &'a Resources<'a>,
    out: &mut Writes<'a>,
) -> Result<()> {
    out.clear();
    if let Some(memory) = resources.memory.as_ref() {
        out.controller("memory");
        lower_memory(memory, out)?;
    }
    if let Some(cpu) = resources.cpu.as_ref() {
        lower_cpu(cpu, out)?;
    }
    if let Some(limit) = resources.pids_limit {
        out.controller("pids");
        out.signed("pids.max", limit, MAX)?;
    }
    if let Some(block_io) = resources.block_io.as_ref() {
        out.controller("blkio");
        lower_block_io(block_io, out)?;
    }
    if !resources.hugepage_limits.is_empty() {
        out.controller("hugetlb");
        for limit in &resources.hugepage_limits {
            out.hugepage(limit.page_size, ".limit_in_bytes", limit.limit)?;
        }
    }
    if let Some(network) = resources.network.as_ref() {
        lower_network(network, out)?;
    }
    if !resources.rdma.is_empty() {
        out.controller("rdma");
        lower_rdma(resources, out)?;
    }
    out.controller("");
    if !resources.unified.is_empty() {
        return Err(Error::msg(
            "resources: unified values need the unified hierarchy",
        ));
    }
    Ok(())
}

fn lower_memory(memory: &Memory, out: &mut Writes<'_>) -> Result<()> {
    // The order matters: raising a combined memory and swap limit has to
    // happen after the memory limit it contains, and lowering it has to happen
    // before. Writing the memory limit first and letting a failure surface is
    // what the kernel's own documentation recommends.
    if let Some(limit) = memory.limit {
        out.signed("memory.limit_in_bytes", limit, UNLIMITED)?;
    }
    if let Some(swap) = memory.swap {
        out.signed("memory.memsw.limit_in_bytes", swap, UNLIMITED)?;
    }
    if let Some(reservation) = memory.reservation {
        out.signed("memory.soft_limit_in_bytes", reservation, UNLIMITED)?;
    }
    if let Some(kernel) = memory.kernel {
        out.with_optional(true, |out| {
            out.signed("memory.kmem.limit_in_bytes", kernel, UNLIMITED)
        })?;
    }
    if let Some(kernel_tcp) = memory.kernel_tcp {
        out.with_optional(true, |out| {
            out.signed("memory.kmem.tcp.limit_in_bytes", kernel_tcp, UNLIMITED)
        })?;
    }
    if let Some(swappiness) = memory.swappiness {
        if swappiness > 100 {
            return Err(Error::msg("memory: swappiness must be 0 to 100"));
        }
        out.unsigned("memory.swappiness", swappiness)?;
    }
    if let Some(disable) = memory.disable_oom_killer {
        out.unsigned("memory.oom_control", u64::from(disable))?;
    }
    if let Some(hierarchy) = memory.use_hierarchy {
        out.with_optional(true, |out| {
            out.unsigned("memory.use_hierarchy", u64::from(hierarchy))
        })?;
    }
    Ok(())
}

fn lower_cpu<'a>(cpu: &'a Cpu<'a>, out: &mut Writes<'a>) -> Result<()> {
    out.controller("cpu");
    if let Some(shares) = cpu.shares {
        out.unsigned("cpu.shares", shares)?;
    }
    if let Some(period) = cpu.period {
        out.unsigned("cpu.cfs_period_us", period)?;
    }
    if let Some(quota) = cpu.quota {
        out.signed("cpu.cfs_quota_us", quota, UNLIMITED)?;
    }
    if let Some(burst) = cpu.burst {
        out.with_optional(true, |out| out.unsigned("cpu.cfs_burst_us", burst))?;
    }
    if let Some(runtime) = cpu.realtime_runtime {
        out.signed("cpu.rt_runtime_us", runtime, UNLIMITED)?;
    }
    if let Some(period) = cpu.realtime_period {
        out.unsigned("cpu.rt_period_us", period)?;
    }
    if let Some(idle) = cpu.idle {
        out.with_optional(true, |out| out.signed("cpu.idle", idle, "0"))?;
    }

    if cpu.cpus.is_some() || cpu.mems.is_some() {
        out.controller("cpuset");
        if let Some(cpus) = cpu.cpus {
            out.text("cpuset.cpus", cpus)?;
        }
        if let Some(mems) = cpu.mems {
            out.text("cpuset.mems", mems)?;
        }
    }
    Ok(())
}

fn lower_block_io(io: &BlockIo, out: &mut Writes<'_>) -> Result<()> {
    if let Some(weight) = io.weight {
        out.unsigned("blkio.weight", u64::from(weight))?;
    }
    if let Some(leaf) = io.leaf_weight {
        out.with_optional(true, |out| {
            out.unsigned("blkio.leaf_weight", u64::from(leaf))
        })?;
    }
    for device in &io.weight_device {
        if let Some(weight) = device.weight {
            out.build_append("blkio.weight_device", |buf| {
                device_value(buf, device.major, device.minor, u64::from(weight))
            })?;
        }
        if let Some(leaf) = device.leaf_weight {
            out.with_optional(true, |out| {
                out.build_append("blkio.leaf_weight_device", |buf| {
                    device_value(
                        buf,
                        device.major,
                        device.minor,
                        u64::from(leaf),
                    )
                })
            })?;
        }
    }
    for (file, list) in [
        ("blkio.throttle.read_bps_device", &io.throttle_read_bps),
        ("blkio.throttle.write_bps_device", &io.throttle_write_bps),
        ("blkio.throttle.read_iops_device", &io.throttle_read_iops),
        ("blkio.throttle.write_iops_device", &io.throttle_write_iops),
    ] {
        for device in list {
            out.build_append(file, |buf| {
                device_value(buf, device.major, device.minor, device.rate)
            })?;
        }
    }
    Ok(())
}

fn lower_network<'a>(
    network: &'a Network<'a>,
    out: &mut Writes<'a>,
) -> Result<()> {
    if let Some(class_id) = network.class_id {
        out.controller("net_cls");
        out.unsigned("net_cls.classid", u64::from(class_id))?;
    }
    if !network.priorities.is_empty() {
        out.controller("net_prio");
        for &(name, priority) in &network.priorities {
            out.build_append("net_prio.ifpriomap", |buf| {
                buf.push_str(name)?;
                buf.push_str(" ")?;
                buf.push_u64(u64::from(priority))
            })?;
        }
    }
    Ok(())
}

fn lower_rdma(resources: &Resources<'_>, out: &mut Writes<'_>) -> Result<()> {
    out.tolerate_missing(true);
    for &(device, limits) in &resources.rdma {
        out.rdma(device, limits, true)?;
    }
    out.tolerate_missing(false);
    Ok(())
}

/// Renders `major:minor value`, the shape every per-device file takes.
fn device_value(
    buf: &mut ValueBuf,
    major: i64,
    minor: i64,
    value: u64,
) -> Result<()> {
    buf.push_i64(major)?;
    buf.push_str(":")?;
    buf.push_i64(minor)?;
    buf.push_str(" ")?;
    buf.push_u64(value)
}

/// Freezer states the legacy hierarchy uses.
pub mod freezer {
    /// Running.
    pub const THAWED: &[u8] = b"THAWED";
    /// Fully stopped.
    pub const FROZEN: &[u8] = b"FROZEN";
    /// Transitioning towards frozen.
    pub const FREEZING: &str = "FREEZING";
}

/// Waits for a freeze to settle, re-asserting it while the kernel is still
/// working through the transition.
///
/// Writing `FROZEN` starts a transition that the kernel completes
/// asynchronously, and a process in an uninterruptible sleep can hold it in
/// `FREEZING` for a while. The kernel's own documentation recommends
/// re-asserting the write.
///
/// Returns true when the cgroup reached `FROZEN`.
pub fn settle_freezer(directory: BorrowedFd<'_>) -> Result<bool> {
    let mut buf = [0u8; 32];
    // The bound keeps a wedged container from wedging the runtime with it.
    for _ in 0..1000u32 {
        let read = crate::cgroup::write::read_one(
            directory,
            c"freezer.state",
            &mut buf,
        )?;
        let state = buf.get(..read).unwrap_or(&[]);
        let text = core::str::from_utf8(state).unwrap_or("").trim();
        if text != freezer::FREEZING {
            return Ok(text.as_bytes() == freezer::FROZEN);
        }
        // Re-assert the request: a process that was briefly uninterruptible
        // can leave the transition stuck until it is asked again.
        crate::cgroup::write::write_one(
            directory,
            c"freezer.state",
            freezer::FROZEN,
            false,
        )?;
    }
    Err(Error::msg("cgroup: freezer did not settle"))
}
