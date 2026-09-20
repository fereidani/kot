//! Collapsing two-instruction branches into one where the distance allows.
//!
//! The emitter keeps every conditional branch one instruction long so that a
//! single forward patch resolves the program. That costs an extra
//! unconditional jump per branch. Most of those jumps land within the eight
//! bits a conditional branch has, so this pass folds the pair back into one
//! instruction.
//!
//! The work happens on a form that carries absolute targets rather than
//! displacements, which keeps the bookkeeping honest: removing an instruction
//! shifts every displacement after it, but leaves every absolute target alone
//! except for a single index remapping.
//!
//! The pass only ever removes instructions, so distances only ever shrink,
//! which means a fold that fits before a pass still fits after it. Each pass
//! removes at least one instruction or reports no change, so it terminates.

use crate::{
    seccomp::insn::JMP_JA,
    sys::{
        error::{Error, Result},
        seccomp::SockFilter,
    },
};

/// Instruction class mask, and the value that marks a branch.
const CLASS_MASK: u16 = 0x07;
const CLASS_JMP: u16 = 0x05;

/// Largest displacement a conditional branch can carry.
const MAX_SHORT: usize = u8::MAX as usize;

/// How many shrinking passes to run.
///
/// Each pass either removes an instruction or reports no change, so the bound
/// is a guard against a bug in the marking below rather than a real limit.
const MAX_PASSES: u32 = 16;

/// Reusable storage for the shrinking pass.
#[derive(Default)]
pub(crate) struct Scratch {
    nodes: Vec<Node>,
    mapping: Vec<usize>,
    targeted: Vec<bool>,
}

impl Scratch {
    /// Prepares every buffer for a program of `len` instructions.
    fn reserve(&mut self, len: usize) {
        reserve_buffer(&mut self.nodes, len);
        reserve_buffer(&mut self.mapping, len + 1);
        reserve_buffer(&mut self.targeted, len + 1);
    }
}

fn reserve_buffer<T>(buffer: &mut Vec<T>, len: usize) {
    buffer.clear();
    buffer.reserve(len);
}

/// One instruction with its destinations named absolutely.
#[derive(Clone, Copy, Debug)]
struct Node {
    code: u16,
    k: u32,
    /// Where a true comparison goes, or where an unconditional jump goes.
    on_true: usize,
    /// Where a false comparison goes.
    on_false: usize,
}

/// Folds `branch; jump` pairs whose target is close enough to inline.
pub(crate) fn relax(
    insns: &mut Vec<SockFilter>,
    scratch: &mut Scratch,
) -> Result<()> {
    scratch.reserve(insns.len());
    to_nodes(insns, &mut scratch.nodes);

    for _ in 0..MAX_PASSES {
        if !fold(scratch) {
            break;
        }
    }

    to_insns(&scratch.nodes, insns)
}

/// Converts displacements into absolute targets.
fn to_nodes(insns: &[SockFilter], out: &mut Vec<Node>) {
    out.clear();
    for (index, insn) in insns.iter().enumerate() {
        let next = index + 1;
        let (k, on_true, on_false) = if insn.code == JMP_JA {
            let away = next + insn.k as usize;
            (0, away, away)
        } else if is_branch(insn.code) {
            (
                insn.k,
                next + usize::from(insn.jt),
                next + usize::from(insn.jf),
            )
        } else {
            // Anything else continues at the instruction below, so both of
            // its arms point there.
            (insn.k, next, next)
        };
        out.push(Node {
            code: insn.code,
            k,
            on_true,
            on_false,
        });
    }
}

/// Converts absolute targets back into displacements.
fn to_insns(nodes: &[Node], out: &mut Vec<SockFilter>) -> Result<()> {
    out.clear();
    out.reserve(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        let next = index + 1;
        let (jt, jf, k) = if node.code == JMP_JA {
            (0, 0, far(node.on_true, next)?)
        } else if is_branch(node.code) {
            (
                short(node.on_true, next)?,
                short(node.on_false, next)?,
                node.k,
            )
        } else {
            (0, 0, node.k)
        };
        out.push(SockFilter::new(node.code, jt, jf, k));
    }
    Ok(())
}

/// Runs one shrinking pass. Returns true when it changed anything.
fn fold(scratch: &mut Scratch) -> bool {
    let Scratch {
        nodes,
        mapping,
        targeted,
    } = scratch;

    // Only an explicit jump counts as reaching an instruction. Falling in
    // from the instruction above does not, because folding a pair removes the
    // instruction that would have fallen through anyway.
    targeted.clear();
    targeted.resize(nodes.len() + 1, false);
    for (index, node) in nodes.iter().enumerate() {
        if node.code != JMP_JA && !is_branch(node.code) {
            continue;
        }
        let through = index + 1;
        for arm in [node.on_true, node.on_false] {
            if arm != through {
                mark(targeted, arm);
            }
        }
    }

    mapping.clear();
    let mut read = 0usize;
    let mut write = 0usize;
    let old_len = nodes.len();
    // Compaction never lets the write index pass the read index, so every
    // store lands after its original instruction has been consumed.
    while let Some(&current) = nodes.get(read) {
        debug_assert!(write <= read, "compaction preserves unread nodes");
        mapping.push(write);
        let pair = nodes
            .get(read + 1)
            .copied()
            .filter(|&next| can_fold(current, next, read, targeted));
        let Some(next) = pair else {
            nodes[write] = current;
            write += 1;
            read += 1;
            continue;
        };

        // The branch absorbs the jump: the arm that fell through keeps
        // naming the instruction after the pair, and the other one goes
        // where the jump went.
        let through = read + 2;
        let away = next.on_true;
        let (on_true, on_false) = if current.on_true == through {
            (through, away)
        } else {
            (away, through)
        };
        nodes[write] = Node {
            code: current.code,
            k: current.k,
            on_true,
            on_false,
        };
        // The removed jump maps onto the instruction that replaced the pair,
        // so anything still naming it resolves sensibly.
        mapping.push(write);
        write += 1;
        read += 2;
    }
    // One past the end, so a target at the end of the program still resolves.
    mapping.push(write);
    nodes.truncate(write);

    if write == old_len {
        return false;
    }

    for node in nodes.iter_mut() {
        node.on_true = mapping.get(node.on_true).copied().unwrap_or(0);
        node.on_false = mapping.get(node.on_false).copied().unwrap_or(0);
    }
    true
}

/// True when the branch at `index` and the jump below it collapse into one
/// instruction.
///
/// That needs a branch whose two arms are "fall through" and "the very next
/// instruction", followed by an unconditional jump nothing else can reach.
/// The distance test is conservative: the pass only removes instructions, so
/// a jump that fits now still fits after the rebuild.
fn can_fold(
    current: Node,
    next: Node,
    index: usize,
    targeted: &[bool],
) -> bool {
    let arms = (current.on_true, current.on_false);
    is_branch(current.code)
        && next.code == JMP_JA
        && (arms == (index + 2, index + 1) || arms == (index + 1, index + 2))
        && targeted.get(index + 1) != Some(&true)
        && next.on_true.saturating_sub(index + 1) <= MAX_SHORT
}

fn mark(targeted: &mut [bool], at: usize) {
    if let Some(slot) = targeted.get_mut(at) {
        *slot = true;
    }
}

/// Displacement for a conditional branch, which has eight bits of reach.
fn short(target: usize, from: usize) -> Result<u8> {
    let displacement = target
        .checked_sub(from)
        .ok_or_else(|| Error::msg("seccomp: backward branch"))?;
    u8::try_from(displacement)
        .map_err(|_| Error::msg("seccomp: branch displacement overflow"))
}

/// Displacement for an unconditional jump, which has a full word of reach.
fn far(target: usize, from: usize) -> Result<u32> {
    let displacement = target
        .checked_sub(from)
        .ok_or_else(|| Error::msg("seccomp: backward jump"))?;
    u32::try_from(displacement)
        .map_err(|_| Error::msg("seccomp: jump displacement overflow"))
}

/// True for any conditional branch.
fn is_branch(code: u16) -> bool {
    code & CLASS_MASK == CLASS_JMP && code != JMP_JA
}
