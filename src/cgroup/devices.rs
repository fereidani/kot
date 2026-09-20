//! The device controller.
//!
//! The two hierarchies could hardly be less alike here. The legacy one takes
//! text rules written into `devices.allow` and `devices.deny`; the unified one
//! takes an eBPF program attached to the cgroup. Both are driven from the same
//! rule list, and both preserve the rule that a later rule overrides an
//! earlier one, which is why the program below evaluates in reverse and
//! returns on the first match.

use crate::{
    cgroup::{layout::Layout, write::Writes},
    oci::spec::DeviceRule,
    sys::{
        bpf::Insn,
        error::{Error, Result},
    },
};

/// Device type: a block device.
const DEV_BLOCK: u32 = 1;
/// Device type: a character device.
const DEV_CHAR: u32 = 2;

/// Access: creating the node.
const ACC_MKNOD: u32 = 1;
/// Access: reading.
const ACC_READ: u32 = 2;
/// Access: writing.
const ACC_WRITE: u32 = 4;
/// Every access.
const ACC_ALL: u32 = ACC_MKNOD | ACC_READ | ACC_WRITE;

/// eBPF opcodes, spelled out rather than pulled from a crate, because the
/// program below is a dozen instructions and a dependency would be a larger
/// liability than the encoding.
mod op {
    /// Load a word from memory into a register.
    pub const LDX_MEM_W: u8 = 0x61;
    /// Move a register into another.
    pub const MOV64_REG: u8 = 0xbf;
    /// Move an immediate into a register.
    pub const MOV64_IMM: u8 = 0xb7;
    /// Bitwise and with an immediate, 32 bit.
    pub const ALU32_AND_IMM: u8 = 0x54;
    /// Shift right by an immediate, 32 bit.
    pub const ALU32_RSH_IMM: u8 = 0x74;
    /// Branch when a register differs from an immediate.
    pub const JMP_JNE_IMM: u8 = 0x55;
    /// Return from the program.
    pub const EXIT: u8 = 0x95;
}

/// Registers the program uses.
mod reg {
    /// Return value.
    pub const RESULT: u8 = 0;
    /// Context pointer on entry, scratch afterwards.
    pub const CTX: u8 = 1;
    /// Requested access.
    pub const ACCESS: u8 = 2;
    /// Device type.
    pub const KIND: u8 = 3;
    /// Major number.
    pub const MAJOR: u8 = 4;
    /// Minor number.
    pub const MINOR: u8 = 5;
}

/// Offsets within `struct bpf_cgroup_dev_ctx`.
mod ctx {
    /// Access and type, packed as `(access << 16) | type`.
    pub const ACCESS_TYPE: i16 = 0;
    /// Major number.
    pub const MAJOR: i16 = 4;
    /// Minor number.
    pub const MINOR: i16 = 8;
}

/// One rule, resolved to numbers.
#[derive(Clone, Copy, Debug)]
struct Rule {
    allow: bool,
    /// Device type, or `None` for any.
    kind: Option<u32>,
    /// Major number, or `None` for any.
    major: Option<u32>,
    /// Minor number, or `None` for any.
    minor: Option<u32>,
    /// Access bits the rule covers.
    access: u32,
}

impl Rule {
    /// True when the rule matches every device and every access, so nothing
    /// after it in the reverse scan can be reached.
    const fn is_catch_all(&self) -> bool {
        self.kind.is_none()
            && self.major.is_none()
            && self.minor.is_none()
            && self.access == ACC_ALL
    }
}

fn resolve(source: &DeviceRule<'_>) -> Result<Rule> {
    let kind = match source.kind {
        None | Some("a" | "") => None,
        Some("b") => Some(DEV_BLOCK),
        Some("c" | "u") => Some(DEV_CHAR),
        Some(_) => return Err(Error::msg("devices: unknown device type")),
    };
    let number = |value: Option<i64>| -> Result<Option<u32>> {
        match value {
            // The specification uses a negative number for "any", and some
            // tooling leaves the field out entirely for the same meaning.
            None => Ok(None),
            Some(v) if v < 0 => Ok(None),
            Some(v) => u32::try_from(v)
                .map(Some)
                .map_err(|_| Error::msg("devices: number out of range")),
        }
    };
    let mut access = 0u32;
    match source.access {
        None | Some("") => access = ACC_ALL,
        Some(text) => {
            for byte in text.bytes() {
                access |= match byte {
                    b'r' => ACC_READ,
                    b'w' => ACC_WRITE,
                    b'm' => ACC_MKNOD,
                    _ => {
                        return Err(Error::msg("devices: unknown access mode"));
                    }
                };
            }
        }
    }
    Ok(Rule {
        allow: source.allow,
        kind,
        major: number(source.major)?,
        minor: number(source.minor)?,
        access,
    })
}

/// Device access added to every rule list a configuration states.
///
/// These are the nodes the specification requires a container to have, plus
/// the ability to create device nodes at all. Every runtime grants them, and a
/// container without them fails in ways that look like anything but a device
/// rule: `/dev/null` refusing to open is not a diagnosis anybody reaches
/// quickly.
///
/// A configuration that states no rules at all is left alone rather than
/// given these: with nothing to deny, the container inherits its parent's
/// access, which already includes every node here.
///
/// They take precedence over the configuration's own rules, which matters
/// because a stock bundle opens with a deny-all and never names them again.
/// crun and runc both behave this way, and a container that did not would not
/// be a drop-in replacement.
const DEFAULT_RULES: [(u8, Option<u32>, Option<u32>, u32); 12] = [
    // Creating a device node of any kind, which the runtime itself needs.
    (b'c', None, None, ACC_MKNOD),
    (b'b', None, None, ACC_MKNOD),
    (b'c', Some(1), Some(3), ACC_ALL), // /dev/null
    (b'c', Some(1), Some(5), ACC_ALL), // /dev/zero
    (b'c', Some(1), Some(7), ACC_ALL), // /dev/full
    (b'c', Some(1), Some(8), ACC_ALL), // /dev/random
    (b'c', Some(1), Some(9), ACC_ALL), // /dev/urandom
    (b'c', Some(5), Some(0), ACC_ALL), // /dev/tty
    (b'c', Some(5), Some(1), ACC_ALL), // /dev/console
    (b'c', Some(5), Some(2), ACC_ALL), // /dev/ptmx
    (b'c', Some(136), None, ACC_ALL),  // the pseudo-terminals themselves
    (b'c', Some(10), Some(200), ACC_ALL), // /dev/net/tun
];

/// Resolves the configuration's rules and appends the defaults.
///
/// The defaults go last because the emitted program checks rules in reverse:
/// the last rule is tested first, so the end of the list is where precedence
/// lies.
fn resolve_all(rules: &[DeviceRule<'_>]) -> Result<Vec<Rule>> {
    let mut out = Vec::with_capacity(rules.len() + DEFAULT_RULES.len());
    for rule in rules {
        out.push(resolve(rule)?);
    }
    for &(kind, major, minor, access) in &DEFAULT_RULES {
        out.push(Rule {
            allow: true,
            kind: Some(if kind == b'b' { DEV_BLOCK } else { DEV_CHAR }),
            major,
            minor,
            access,
        });
    }
    Ok(out)
}

/// How a hierarchy expresses its device rules.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// An eBPF program attached to the container's cgroup.
    Program,
    /// Text lines written into the legacy `devices` controller.
    Rules,
}

/// The form a layout calls for.
///
/// A hybrid host answers with the legacy form: its controllers live in the
/// legacy trees, which is where the manager puts every other limit there
/// too, and the unified node it also has holds no device controller to
/// attach a program to.
#[must_use]
pub const fn form(layout: Layout) -> Form {
    if layout.has_legacy() {
        Form::Rules
    } else {
        Form::Program
    }
}

/// Builds the eBPF program for a rule list.
///
/// `out` is the caller's buffer, reused across containers.
pub fn program(rules: &[DeviceRule<'_>], out: &mut Vec<Insn>) -> Result<()> {
    let resolved = resolve_all(rules)?;

    out.clear();
    // Unpack the context once. Everything after this is register work.
    out.push(load(reg::ACCESS, ctx::ACCESS_TYPE));
    out.push(Insn::new(op::MOV64_REG, reg::KIND, reg::ACCESS, 0, 0));
    out.push(Insn::new(op::ALU32_AND_IMM, reg::KIND, 0, 0, 0xffff));
    out.push(Insn::new(op::ALU32_RSH_IMM, reg::ACCESS, 0, 0, 16));
    out.push(load(reg::MAJOR, ctx::MAJOR));
    out.push(load(reg::MINOR, ctx::MINOR));

    // The scan runs backwards, so the last rule to name a device decides it.
    let mut default_allow = true;
    for rule in resolved.iter().rev() {
        if rule.is_catch_all() {
            // Nothing before this can be reached, so the rest of the list is
            // dead and the trailing default becomes this rule's answer.
            default_allow = rule.allow;
            break;
        }
        emit_rule(rule, out)?;
    }

    verdict(default_allow, out);
    Ok(())
}

/// Loads a word from the device context into a register.
const fn load(register: u8, offset: i16) -> Insn {
    Insn::new(op::LDX_MEM_W, register, reg::CTX, offset, 0)
}

/// Emits the answer a matching rule gives, and the exit that returns it.
fn verdict(allow: bool, out: &mut Vec<Insn>) {
    out.push(Insn::new(
        op::MOV64_IMM,
        reg::RESULT,
        0,
        0,
        i32::from(allow),
    ));
    out.push(Insn::new(op::EXIT, 0, 0, 0, 0));
}

/// Emits the test and verdict for one rule.
fn emit_rule(rule: &Rule, out: &mut Vec<Insn>) -> Result<()> {
    // Build the rule's body first so the branch offsets over it are known, and
    // this stays a single pass.
    let mut body: Vec<Insn> = Vec::with_capacity(8);
    if let Some(kind) = rule.kind {
        body.push(Insn::new(op::JMP_JNE_IMM, reg::KIND, 0, 0, as_imm(kind)?));
    }
    if let Some(major) = rule.major {
        body.push(Insn::new(op::JMP_JNE_IMM, reg::MAJOR, 0, 0, as_imm(major)?));
    }
    if let Some(minor) = rule.minor {
        body.push(Insn::new(op::JMP_JNE_IMM, reg::MINOR, 0, 0, as_imm(minor)?));
    }
    if rule.access != ACC_ALL {
        // The request matches when every bit it asks for is one the rule
        // grants, that is, when nothing is left after masking the rule's bits
        // away.
        body.push(Insn::new(op::MOV64_REG, reg::CTX, reg::ACCESS, 0, 0));
        body.push(Insn::new(
            op::ALU32_AND_IMM,
            reg::CTX,
            0,
            0,
            as_imm(!rule.access & ACC_ALL)?,
        ));
        body.push(Insn::new(op::JMP_JNE_IMM, reg::CTX, 0, 0, 0));
    }

    // Two instructions follow the tests: the verdict and the exit.
    let verdict_len = 2i16;
    let total = i16::try_from(body.len())
        .map_err(|_| Error::msg("devices: rule too long"))?;
    let mut emitted = 0i16;
    for mut insn in body {
        emitted += 1;
        if insn.code == op::JMP_JNE_IMM {
            // A failed test skips the rest of the tests and the verdict.
            insn.off = total - emitted + verdict_len;
        }
        out.push(insn);
    }
    verdict(rule.allow, out);
    Ok(())
}

fn as_imm(value: u32) -> Result<i32> {
    i32::try_from(value).map_err(|_| Error::msg("devices: value out of range"))
}

/// Lowers a rule list into the legacy hierarchy's text writes.
pub fn lower_legacy(
    rules: &[DeviceRule<'_>],
    out: &mut Writes<'_>,
) -> Result<()> {
    out.controller("devices");
    // The legacy hierarchy applies rules in the order they are written, with a
    // later one overriding an earlier one, so the defaults go last here for
    // the same reason they go last in the program above.
    for rule in resolve_all(rules)? {
        let file = if rule.allow {
            "devices.allow"
        } else {
            "devices.deny"
        };
        out.build_append(file, |buf| {
            buf.push_str(match rule.kind {
                None => "a",
                Some(DEV_BLOCK) => "b",
                _ => "c",
            })?;
            buf.push_str(" ")?;
            match rule.major {
                Some(major) => buf.push_u64(u64::from(major))?,
                None => buf.push_str("*")?,
            }
            buf.push_str(":")?;
            match rule.minor {
                Some(minor) => buf.push_u64(u64::from(minor))?,
                None => buf.push_str("*")?,
            }
            buf.push_str(" ")?;
            if rule.access & ACC_READ != 0 {
                buf.push_str("r")?;
            }
            if rule.access & ACC_WRITE != 0 {
                buf.push_str("w")?;
            }
            if rule.access & ACC_MKNOD != 0 {
                buf.push_str("m")?;
            }
            Ok(())
        })?;
    }
    out.controller("");
    Ok(())
}
