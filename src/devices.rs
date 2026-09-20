//! Attaching the device controller.
//!
//! On the unified hierarchy the controller is an eBPF program attached to the
//! container's cgroup; on the legacy one it is a list of text rules. Both come
//! from the same configuration, and both are applied here so the difference
//! stays in one place.

use std::os::fd::{AsFd as _, OwnedFd};

use anyhow::{Context as _, Result, bail};

use crate::{
    cgroup::{Kind, Manager, devices, write::Writes},
    oci::spec::Resources,
    sys::bpf::Insn,
};

/// Applies the device rules a configuration carries.
pub fn configure(
    manager: &mut Manager,
    resources: Option<&Resources<'_>>,
) -> Result<()> {
    let Some(resources) = resources else {
        return Ok(());
    };
    // Nothing to deny means nothing to enforce: the container inherits its
    // parent's device access, which is wider than any list here would be.
    if resources.devices.is_empty() {
        return Ok(());
    }
    // A container told to manage no cgroup has no device controller either,
    // which is the caller's own choice rather than a failure.
    if manager.kind() == Kind::Disabled {
        return Ok(());
    }
    // The legacy hierarchy keeps its device rules in the `devices`
    // controller's own tree, which is not where the unified node is, so the
    // directory has to be asked for by name rather than taken as the one the
    // container occupies. A host without that controller cannot enforce the
    // rules at all, and starting anyway would leave a container the
    // configuration meant to restrict with unrestricted access.
    let Some(directory) = manager.place("devices") else {
        bail!("the devices controller is not mounted");
    };

    let layout = crate::cgroup::Layout::detect()?;
    if devices::form(layout) == devices::Form::Rules {
        let mut writes = Writes::new();
        devices::lower_legacy(&resources.devices, &mut writes)?;
        return crate::cgroup::write::apply(directory, writes.entries())
            .context("applying the device rules");
    }

    let mut program = Vec::new();
    devices::program(&resources.devices, &mut program)
        .context("building the device program")?;

    // Loaded without asking for a verifier log first. Asking for one costs the
    // kernel a second pass, and a log buffer that turns out to be too small is
    // itself reported as a failure, which would turn a working program into a
    // spurious error.
    let mut empty = [];
    let loaded =
        load(&program, &mut empty).map_err(|first| explain(&program, first))?;

    crate::sys::bpf::prog_attach(
        directory,
        loaded.as_fd(),
        crate::sys::bpf::ATTACH_TYPE_CGROUP_DEVICE,
        crate::sys::bpf::F_ALLOW_MULTI,
    )
    .context("attaching the device program")
}

/// Asks the kernel to accept the device program, writing its verifier output
/// into `log`.
fn load(
    program: &[Insn],
    log: &mut [u8],
) -> Result<OwnedFd, crate::sys::Error> {
    crate::sys::bpf::prog_load(
        crate::sys::bpf::PROG_TYPE_CGROUP_DEVICE,
        program,
        "kot_devices",
        log,
    )
}

/// Describes a program the verifier rejected, quoting what it said.
///
/// The log is worth its second pass only once the program is known to be bad.
/// A retry that then succeeds leaves nothing to quote, so the first failure
/// stands on its own.
fn explain(program: &[Insn], first: crate::sys::Error) -> anyhow::Error {
    let mut log = vec![0u8; 256 * 1024];
    let context = "loading the device program";
    if load(program, &mut log).is_ok() {
        return anyhow::Error::new(first).context(context);
    }
    let text = core::str::from_utf8(&log)
        .unwrap_or("")
        .trim_end_matches('\0')
        .trim();
    anyhow::anyhow!("{first}: {text}").context(context)
}
