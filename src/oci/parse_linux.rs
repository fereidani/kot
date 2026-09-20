//! Reading the `linux` section, which carries most of the configuration.

use crate::{
    oci::{
        json::Parser,
        parse,
        spec::{
            BlockIo, Cpu, Device, DeviceRule, HugepageLimit, IntelRdt, Linux,
            Memory, MemoryPolicy, Namespace, Network, Personality, Rdma,
            Resources, Seccomp, Syscall, SyscallArg, ThrottleDevice,
            TimeOffset, WeightDevice,
        },
    },
    sys::error::{Error, Result},
};

/// Parses the `linux` section.
pub fn linux<'a>(p: &mut Parser<'a>) -> Result<Linux<'a>> {
    p.object(Linux::default(), |p, key, out| {
        match key {
            "uidMappings" => parse::id_mappings(p, &mut out.uid_mappings)?,
            "gidMappings" => parse::id_mappings(p, &mut out.gid_mappings)?,
            "sysctl" => p.string_map(&mut out.sysctl)?,
            "resources" => out.resources = Some(resources(p)?),
            "cgroupsPath" => out.cgroups_path = Some(p.string()?),
            "namespaces" => namespaces(p, &mut out.namespaces)?,
            "devices" => devices(p, &mut out.devices)?,
            "netDevices" => net_devices(p, &mut out.net_devices)?,
            "seccomp" => out.seccomp = Some(seccomp(p)?),
            "rootfsPropagation" => {
                out.rootfs_propagation = Some(p.string()?);
            }
            "maskedPaths" => p.string_array(&mut out.masked_paths)?,
            "readonlyPaths" => p.string_array(&mut out.readonly_paths)?,
            "mountLabel" => out.mount_label = Some(p.string()?),
            "intelRdt" => out.intel_rdt = Some(intel_rdt(p)?),
            "memoryPolicy" => out.memory_policy = Some(memory_policy(p)?),
            "personality" => out.personality = Some(personality(p)?),
            "timeOffsets" => time_offsets(p, &mut out.time_offsets)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn namespaces<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<Namespace<'a>>,
) -> Result<()> {
    p.object_array(out, |p, key, namespace| {
        match key {
            "type" => namespace.kind = p.string()?,
            "path" => {
                let path = p.string()?;
                namespace.path =
                    if path.is_empty() { None } else { Some(path) };
            }
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn devices<'a>(p: &mut Parser<'a>, out: &mut Vec<Device<'a>>) -> Result<()> {
    p.object_array(out, |p, key, device| {
        match key {
            "path" => device.path = p.string()?,
            "type" => device.kind = p.string()?,
            "major" => device.major = p.i64()?,
            "minor" => device.minor = p.i64()?,
            "fileMode" => device.file_mode = Some(p.u32()?),
            "uid" => device.uid = Some(p.u32()?),
            "gid" => device.gid = Some(p.u32()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn net_devices<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<(&'a str, Option<&'a str>)>,
) -> Result<()> {
    p.object_map(out, |p, key, renamed| {
        match key {
            "name" => *renamed = Some(p.string()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn time_offsets<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<(&'a str, TimeOffset)>,
) -> Result<()> {
    p.object_map(out, |p, key, offset| {
        match key {
            "secs" => offset.secs = p.i64()?,
            "nanosecs" => offset.nanosecs = p.u32()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn personality<'a>(p: &mut Parser<'a>) -> Result<Personality<'a>> {
    p.object(Personality::default(), |p, key, out| {
        match key {
            "domain" => out.domain = p.string()?,
            "flags" => p.string_array(&mut out.flags)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn memory_policy<'a>(p: &mut Parser<'a>) -> Result<MemoryPolicy<'a>> {
    p.object(MemoryPolicy::default(), |p, key, out| {
        match key {
            "mode" => out.mode = p.string()?,
            "nodes" => out.nodes = Some(p.string()?),
            "flags" => p.string_array(&mut out.flags)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn intel_rdt<'a>(p: &mut Parser<'a>) -> Result<IntelRdt<'a>> {
    p.object(IntelRdt::default(), |p, key, out| {
        match key {
            "closID" => out.clos_id = Some(p.string()?),
            "schemata" => p.string_array(&mut out.schemata)?,
            "l3CacheSchema" => out.l3_cache_schema = Some(p.string()?),
            "memBwSchema" => out.mem_bw_schema = Some(p.string()?),
            "enableMonitoring" => out.enable_monitoring = p.bool()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

/// Parses the `linux.resources` section.
pub fn resources<'a>(p: &mut Parser<'a>) -> Result<Resources<'a>> {
    p.object(Resources::default(), |p, key, out| {
        match key {
            "devices" => device_rules(p, &mut out.devices)?,
            "memory" => out.memory = Some(memory(p)?),
            "cpu" => out.cpu = Some(cpu(p)?),
            "pids" => out.pids_limit = pids(p)?,
            "blockIO" => out.block_io = Some(block_io(p)?),
            "hugepageLimits" => {
                hugepage_limits(p, &mut out.hugepage_limits)?;
            }
            "network" => out.network = Some(network(p)?),
            "rdma" => rdma(p, &mut out.rdma)?,
            "unified" => p.string_map(&mut out.unified)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn device_rules<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<DeviceRule<'a>>,
) -> Result<()> {
    p.object_array(out, |p, key, rule| {
        match key {
            "allow" => rule.allow = p.bool()?,
            "type" => rule.kind = Some(p.string()?),
            "major" => rule.major = Some(p.i64()?),
            "minor" => rule.minor = Some(p.i64()?),
            "access" => rule.access = Some(p.string()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn memory(p: &mut Parser<'_>) -> Result<Memory> {
    p.object(Memory::default(), |p, key, out| {
        match key {
            "limit" => out.limit = Some(p.i64()?),
            "reservation" => out.reservation = Some(p.i64()?),
            "swap" => out.swap = Some(p.i64()?),
            "kernel" => out.kernel = Some(p.i64()?),
            "kernelTCP" => out.kernel_tcp = Some(p.i64()?),
            "swappiness" => out.swappiness = Some(p.u64()?),
            "disableOOMKiller" => out.disable_oom_killer = Some(p.bool()?),
            "useHierarchy" => out.use_hierarchy = Some(p.bool()?),
            "checkBeforeUpdate" => out.check_before_update = Some(p.bool()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn cpu<'a>(p: &mut Parser<'a>) -> Result<Cpu<'a>> {
    p.object(Cpu::default(), |p, key, out| {
        match key {
            "shares" => out.shares = Some(p.u64()?),
            "quota" => out.quota = Some(p.i64()?),
            "burst" => out.burst = Some(p.u64()?),
            "period" => out.period = Some(p.u64()?),
            "realtimeRuntime" => out.realtime_runtime = Some(p.i64()?),
            "realtimePeriod" => out.realtime_period = Some(p.u64()?),
            "cpus" => out.cpus = Some(p.string()?),
            "mems" => out.mems = Some(p.string()?),
            "idle" => out.idle = Some(p.i64()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn pids(p: &mut Parser<'_>) -> Result<Option<i64>> {
    p.object(None, |p, key, limit| {
        match key {
            "limit" => *limit = Some(p.i64()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn block_io(p: &mut Parser<'_>) -> Result<BlockIo> {
    p.object(BlockIo::default(), |p, key, out| {
        match key {
            "weight" => out.weight = Some(u16_of(p)?),
            "leafWeight" => out.leaf_weight = Some(u16_of(p)?),
            "weightDevice" => weight_devices(p, &mut out.weight_device)?,
            "throttleReadBpsDevice" => {
                throttle_devices(p, &mut out.throttle_read_bps)?;
            }
            "throttleWriteBpsDevice" => {
                throttle_devices(p, &mut out.throttle_write_bps)?;
            }
            "throttleReadIOPSDevice" => {
                throttle_devices(p, &mut out.throttle_read_iops)?;
            }
            "throttleWriteIOPSDevice" => {
                throttle_devices(p, &mut out.throttle_write_iops)?;
            }
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn u16_of(p: &mut Parser<'_>) -> Result<u16> {
    let value = p.u64()?;
    u16::try_from(value).map_err(|_| Error::msg("json: value exceeds 16 bits"))
}

fn weight_devices(
    p: &mut Parser<'_>,
    out: &mut Vec<WeightDevice>,
) -> Result<()> {
    p.object_array(out, |p, key, device| {
        match key {
            "major" => device.major = p.i64()?,
            "minor" => device.minor = p.i64()?,
            "weight" => device.weight = Some(u16_of(p)?),
            "leafWeight" => device.leaf_weight = Some(u16_of(p)?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn throttle_devices(
    p: &mut Parser<'_>,
    out: &mut Vec<ThrottleDevice>,
) -> Result<()> {
    p.object_array(out, |p, key, device| {
        match key {
            "major" => device.major = p.i64()?,
            "minor" => device.minor = p.i64()?,
            "rate" => device.rate = p.u64()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn hugepage_limits<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<HugepageLimit<'a>>,
) -> Result<()> {
    p.object_array(out, |p, key, limit| {
        match key {
            "pageSize" => limit.page_size = p.string()?,
            "limit" => limit.limit = p.u64()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn network<'a>(p: &mut Parser<'a>) -> Result<Network<'a>> {
    p.object(Network::default(), |p, key, out| {
        match key {
            "classID" => out.class_id = Some(p.u32()?),
            "priorities" => {
                p.object_array(&mut out.priorities, |p, field, entry| {
                    match field {
                        "name" => entry.0 = p.string()?,
                        "priority" => entry.1 = p.u32()?,
                        _ => p.skip_value()?,
                    }
                    Ok(())
                })?;
            }
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn rdma<'a>(p: &mut Parser<'a>, out: &mut Vec<(&'a str, Rdma)>) -> Result<()> {
    p.object_map(out, |p, key, limits| {
        match key {
            "hcaHandles" => limits.hca_handles = Some(p.u32()?),
            "hcaObjects" => limits.hca_objects = Some(p.u32()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

/// Parses the `linux.seccomp` section.
fn seccomp<'a>(p: &mut Parser<'a>) -> Result<Seccomp<'a>> {
    p.object(Seccomp::default(), |p, key, out| {
        match key {
            "defaultAction" => out.default_action = p.string()?,
            "defaultErrnoRet" => out.default_errno_ret = Some(p.u32()?),
            "architectures" => p.string_array(&mut out.architectures)?,
            "flags" => p.string_array(&mut out.flags)?,
            "listenerPath" => out.listener_path = Some(p.string()?),
            "listenerMetadata" => out.listener_metadata = Some(p.string()?),
            "syscalls" => syscalls(p, &mut out.syscalls)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn syscalls<'a>(p: &mut Parser<'a>, out: &mut Vec<Syscall<'a>>) -> Result<()> {
    p.object_array(out, |p, key, rule| {
        match key {
            "names" => p.string_array(&mut rule.names)?,
            "action" => rule.action = p.string()?,
            "errnoRet" => rule.errno_ret = Some(p.u32()?),
            "args" => syscall_args(p, &mut rule.args)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn syscall_args<'a>(
    p: &mut Parser<'a>,
    out: &mut Vec<SyscallArg<'a>>,
) -> Result<()> {
    p.object_array(out, |p, key, arg| {
        match key {
            "index" => arg.index = p.u32()?,
            "value" => arg.value = p.u64()?,
            "valueTwo" => arg.value_two = p.u64()?,
            "op" => arg.op = p.string()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}
