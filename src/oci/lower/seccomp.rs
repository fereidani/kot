//! Turning the configuration's seccomp section into an emitted filter.
//!
//! The filter is emitted here, while the plan is being built, and the finished
//! program travels in the plan. The container init process therefore installs
//! a filter it never had to compile, which removes the on-disk filter cache
//! other runtimes need.

use crate::{
    oci::spec,
    seccomp::{Action, Arch, ArgCmp, Compiler, Flags, Op, Profile, Rule},
    sys::{
        error::{Error, Result},
        seccomp::SockFilter,
    },
};

/// Emits the filter a configuration asks for.
pub fn filter(
    compiler: &mut Compiler,
    config: &spec::Seccomp<'_>,
    fail_unknown_syscall: bool,
    encoded: &mut Vec<u8>,
) -> Result<u32> {
    let default_errno = errno_of(config.default_errno_ret)?;
    let default_action = Action::by_name(config.default_action, default_errno)
        .ok_or_else(|| Error::msg("seccomp: unknown default action"))?;

    let mut arches = Vec::with_capacity(config.architectures.len());
    for name in &config.architectures {
        let arch = Arch::by_name(name)
            .ok_or_else(|| Error::msg("seccomp: unknown architecture"))?;
        if !arches.contains(&arch) {
            arches.push(arch);
        }
    }

    let mut flags = Flags::empty();
    for name in &config.flags {
        if !flags.add(name) {
            return Err(Error::msg("seccomp: unknown filter flag"));
        }
    }

    // Names and conditions go into two flat buffers, with each rule recording
    // where its own run starts. Building the borrowed `Rule` values afterwards
    // keeps the buffers from moving while something points into them.
    let mut names = Vec::new();
    let mut args = Vec::new();
    let mut spans = Vec::with_capacity(config.syscalls.len());
    for rule in &config.syscalls {
        let action = Action::by_name(rule.action, errno_of(rule.errno_ret)?)
            .ok_or_else(|| Error::msg("seccomp: unknown action"))?;

        let names_at = names.len();
        names.extend_from_slice(&rule.names);
        let args_at = args.len();
        for arg in &rule.args {
            args.push(ArgCmp {
                index: u8::try_from(arg.index).map_err(|_| {
                    Error::msg("seccomp: argument index out of range")
                })?,
                value: arg.value,
                value_two: arg.value_two,
                op: Op::by_name(arg.op).ok_or_else(|| {
                    Error::msg("seccomp: unknown comparison operator")
                })?,
            });
        }
        spans.push((names_at, names.len(), args_at, args.len(), action));
    }

    let mut rules = Vec::with_capacity(spans.len());
    for &(names_at, names_end, args_at, args_end, action) in &spans {
        let names = names
            .get(names_at..names_end)
            .ok_or_else(|| Error::msg("seccomp: name span out of range"))?;
        let args = args
            .get(args_at..args_end)
            .ok_or_else(|| Error::msg("seccomp: argument span out of range"))?;
        rules.push(Rule {
            names,
            action,
            args,
        });
    }

    let profile = Profile {
        default_action,
        arches: &arches,
        rules: &rules,
        fail_unknown_syscall,
    };
    let program = compiler.compile(&profile)?;
    encode_program(program, encoded);
    Ok(flags.bits())
}

/// Encodes a filter program into the plan's byte representation.
///
/// The plan stores instructions as bytes rather than as a typed array, because
/// a plan is a byte arena and reinterpreting bytes as a struct would need
/// `unsafe`, which no part of the plan uses.
pub fn encode_program(program: &[SockFilter], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(program.len() * 8);
    for insn in program {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
}

/// Decodes the plan's byte representation back into instructions.
pub fn decode_program(bytes: &[u8], out: &mut Vec<SockFilter>) -> Result<()> {
    out.clear();
    if bytes.len() % 8 != 0 {
        return Err(Error::msg(
            "seccomp: filter length is not a multiple of eight",
        ));
    }
    out.reserve(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let (Some(code), Some(jt), Some(jf), Some(k)) =
            (chunk.get(..2), chunk.get(2), chunk.get(3), chunk.get(4..8))
        else {
            return Err(Error::msg("seccomp: truncated instruction"));
        };
        let mut code_raw = [0u8; 2];
        code_raw.copy_from_slice(code);
        let mut k_raw = [0u8; 4];
        k_raw.copy_from_slice(k);
        out.push(SockFilter::new(
            u16::from_le_bytes(code_raw),
            *jt,
            *jf,
            u32::from_le_bytes(k_raw),
        ));
    }
    Ok(())
}

fn errno_of(value: Option<u32>) -> Result<Option<u16>> {
    value
        .map(|v| {
            u16::try_from(v).map_err(|_| Error::msg("seccomp: errno too large"))
        })
        .transpose()
}
