//! Reading a `config.json` into [`Spec`].
//!
//! Unknown keys are skipped, which the specification requires: a bundle may
//! carry fields from a newer version than the runtime knows. Keys that name a
//! platform this runtime does not implement are recorded instead of skipped,
//! so that validation can refuse the bundle rather than start a container that
//! ignores half of its configuration.

use bumpalo::Bump;

pub use crate::oci::parse_linux::resources;
use crate::{
    oci::{
        json::Parser,
        parse_linux,
        spec::{
            Capabilities, ConsoleSize, CpuAffinity, Hook, Hooks, IdMapping,
            IoPriority, Mount, Process, Rlimit, Root, Scheduler, Spec, User,
        },
    },
    sys::error::Result,
};

/// Platform sections this runtime does not implement.
const FOREIGN_PLATFORMS: [&str; 5] =
    ["solaris", "windows", "vm", "zos", "freebsd"];

/// Parses a complete configuration.
pub fn spec<'a>(input: &'a [u8], arena: &'a Bump) -> Result<Spec<'a>> {
    let mut p = Parser::new(input, arena);
    let spec = p.object(Spec::default(), |p, key, out| {
        match key {
            "ociVersion" => out.version = p.string()?,
            "process" => out.process = Some(process(p)?),
            "root" => out.root = Some(root(p)?),
            "hostname" => out.hostname = Some(p.string()?),
            "domainname" => out.domainname = Some(p.string()?),
            "mounts" => mounts(p, &mut out.mounts)?,
            "hooks" => out.hooks = Some(hooks(p)?),
            "annotations" => p.string_map(&mut out.annotations)?,
            "linux" => out.linux = Some(parse_linux::linux(p)?),
            _ if FOREIGN_PLATFORMS.contains(&key) => {
                out.foreign_platforms.push(key);
                p.skip_value()?;
            }
            _ => p.skip_value()?,
        }
        Ok(())
    })?;
    p.finish()?;
    Ok(spec)
}

/// Parses the `process` section.
pub fn process<'a>(p: &mut Parser<'a>) -> Result<Process<'a>> {
    p.object(Process::default(), |p, key, out| {
        match key {
            "terminal" => out.terminal = p.bool()?,
            "consoleSize" => out.console_size = Some(console_size(p)?),
            "user" => out.user = user(p)?,
            "args" => p.string_array(&mut out.args)?,
            "commandLine" => out.command_line = Some(p.string()?),
            "env" => p.string_array(&mut out.env)?,
            "cwd" => out.cwd = p.string()?,
            "capabilities" => out.capabilities = Some(capabilities(p)?),
            "rlimits" => rlimits(p, &mut out.rlimits)?,
            "noNewPrivileges" => out.no_new_privileges = p.bool()?,
            "apparmorProfile" => out.apparmor_profile = Some(p.string()?),
            "oomScoreAdj" => out.oom_score_adj = Some(p.i64()?),
            "scheduler" => out.scheduler = Some(scheduler(p)?),
            "selinuxLabel" => out.selinux_label = Some(p.string()?),
            "ioPriority" => out.io_priority = Some(io_priority(p)?),
            "execCPUAffinity" => {
                out.exec_cpu_affinity = Some(cpu_affinity(p)?);
            }
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn console_size(p: &mut Parser<'_>) -> Result<ConsoleSize> {
    p.object(ConsoleSize::default(), |p, key, out| {
        match key {
            "height" => out.height = p.u32()?,
            "width" => out.width = p.u32()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn user(p: &mut Parser<'_>) -> Result<User> {
    p.object(User::default(), |p, key, out| {
        match key {
            "uid" => out.uid = p.u32()?,
            "gid" => out.gid = p.u32()?,
            "umask" => out.umask = Some(p.u32()?),
            "additionalGids" => p.u32_array(&mut out.additional_gids)?,
            // `username` names a user inside the container, which the runtime
            // resolves from the container's own password file rather than the
            // host's. Nothing here needs it.
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn capabilities<'a>(p: &mut Parser<'a>) -> Result<Capabilities<'a>> {
    p.object(Capabilities::default(), |p, key, out| {
        let set = match key {
            "bounding" => &mut out.bounding,
            "effective" => &mut out.effective,
            "inheritable" => &mut out.inheritable,
            "permitted" => &mut out.permitted,
            "ambient" => &mut out.ambient,
            _ => return p.skip_value(),
        };
        p.string_array(set.get_or_insert_default())
    })
}

fn rlimits<'a>(p: &mut Parser<'a>, out: &mut Vec<Rlimit<'a>>) -> Result<()> {
    p.object_array(out, |p, key, limit| {
        match key {
            "type" => limit.kind = p.string()?,
            "hard" => limit.hard = p.u64()?,
            "soft" => limit.soft = p.u64()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn scheduler<'a>(p: &mut Parser<'a>) -> Result<Scheduler<'a>> {
    p.object(Scheduler::default(), |p, key, out| {
        match key {
            "policy" => out.policy = p.string()?,
            "nice" => out.nice = p.i64()?,
            "priority" => out.priority = p.i64()?,
            "flags" => p.string_array(&mut out.flags)?,
            "runtime" => out.runtime = p.u64()?,
            "deadline" => out.deadline = p.u64()?,
            "period" => out.period = p.u64()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn io_priority<'a>(p: &mut Parser<'a>) -> Result<IoPriority<'a>> {
    p.object(IoPriority::default(), |p, key, out| {
        match key {
            "class" => out.class = p.string()?,
            "priority" => out.priority = p.i64()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn cpu_affinity<'a>(p: &mut Parser<'a>) -> Result<CpuAffinity<'a>> {
    p.object(CpuAffinity::default(), |p, key, out| {
        match key {
            "initial" => out.initial = Some(p.string()?),
            "final" => out.final_set = Some(p.string()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn root<'a>(p: &mut Parser<'a>) -> Result<Root<'a>> {
    p.object(Root::default(), |p, key, out| {
        match key {
            "path" => out.path = p.string()?,
            "readonly" => out.readonly = p.bool()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn mounts<'a>(p: &mut Parser<'a>, out: &mut Vec<Mount<'a>>) -> Result<()> {
    p.object_array(out, |p, key, mount| {
        match key {
            "destination" => mount.destination = p.string()?,
            "type" => mount.kind = Some(p.string()?),
            "source" => mount.source = Some(p.string()?),
            "options" => p.string_array(&mut mount.options)?,
            "uidMappings" => id_mappings(p, &mut mount.uid_mappings)?,
            "gidMappings" => id_mappings(p, &mut mount.gid_mappings)?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

/// Parses an array of id mapping ranges.
pub fn id_mappings(p: &mut Parser<'_>, out: &mut Vec<IdMapping>) -> Result<()> {
    p.object_array(out, |p, key, mapping| {
        match key {
            "containerID" => mapping.container_id = p.u32()?,
            "hostID" => mapping.host_id = p.u32()?,
            "size" => mapping.size = p.u32()?,
            _ => p.skip_value()?,
        }
        Ok(())
    })
}

fn hooks<'a>(p: &mut Parser<'a>) -> Result<Hooks<'a>> {
    p.object(Hooks::default(), |p, key, out| {
        let target = match key {
            "prestart" => &mut out.prestart,
            "createRuntime" => &mut out.create_runtime,
            "createContainer" => &mut out.create_container,
            "startContainer" => &mut out.start_container,
            "poststart" => &mut out.poststart,
            "poststop" => &mut out.poststop,
            _ => return p.skip_value(),
        };
        hook_list(p, target)
    })
}

fn hook_list<'a>(p: &mut Parser<'a>, out: &mut Vec<Hook<'a>>) -> Result<()> {
    p.object_array(out, |p, key, hook| {
        match key {
            "path" => hook.path = p.string()?,
            "args" => p.string_array(&mut hook.args)?,
            "env" => p.string_array(&mut hook.env)?,
            "timeout" => hook.timeout = Some(p.i64()?),
            _ => p.skip_value()?,
        }
        Ok(())
    })
}
