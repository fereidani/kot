//! Classic BPF instruction encoding and the program builder the emitter
//! writes through.
//!
//! The builder exists to make one invariant impossible to violate: every
//! conditional branch in an emitted filter skips either zero or one
//! instruction, and every longer jump is an unconditional `BPF_JA` with a
//! 32-bit displacement. Classic BPF gives conditional branches only 8 bits of
//! displacement, so a filter built any other way needs an iterative pass that
//! inserts trampolines until offsets stabilise. Keeping branches short by
//! construction turns that into a single forward patch.

use crate::{
    seccomp::relax::Scratch,
    sys::{
        error::{Error, Result},
        seccomp::{MAX_INSNS, SockFilter},
    },
};

/// Instruction class: load into the accumulator.
const LD: u16 = 0x00;
/// Instruction class: arithmetic on the accumulator.
const ALU: u16 = 0x04;
/// Instruction class: branch.
const JMP: u16 = 0x05;
/// Instruction class: return.
const RET: u16 = 0x06;

/// Operand size: word.
const W: u16 = 0x00;
/// Addressing mode: absolute offset into the input.
const ABS: u16 = 0x20;
/// Operand source: the immediate field.
const K: u16 = 0x00;

/// Branch: unconditional.
const JA: u16 = 0x00;
/// Branch: equal.
const JEQ: u16 = 0x10;
/// Branch: greater than.
const JGT: u16 = 0x20;
/// Branch: greater than or equal.
const JGE: u16 = 0x30;
/// Arithmetic: bitwise and.
const AND: u16 = 0x50;

/// Load a word from an absolute offset in `seccomp_data`.
const LD_W_ABS: u16 = LD | W | ABS;
/// Mask the accumulator with an immediate.
const ALU_AND_K: u16 = ALU | AND | K;
/// Return an immediate action.
pub const RET_K: u16 = RET | K;
/// Unconditional branch.
pub const JMP_JA: u16 = JMP | JA;
/// Branch when the accumulator equals an immediate.
pub(crate) const JMP_JEQ_K: u16 = JMP | JEQ | K;
/// Branch when the accumulator is above an immediate.
pub(crate) const JMP_JGT_K: u16 = JMP | JGT | K;
/// Branch when the accumulator is at or above an immediate.
pub(crate) const JMP_JGE_K: u16 = JMP | JGE | K;

/// A forward jump target, resolved once the program is complete.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Label(u32);

/// A classic BPF program under construction.
///
/// The caller owns the buffers and reuses them across containers, so emitting
/// a filter allocates nothing after the first call.
#[derive(Default)]
pub struct Program {
    insns: Vec<SockFilter>,
    /// Reusable storage for the branch-folding pass.
    scratch: Scratch,
    /// Instruction index of each label, or `u32::MAX` while unplaced.
    labels: Vec<u32>,
    /// Indices of the `BPF_JA` instructions awaiting a label.
    fixups: Vec<(u32, Label)>,
}

impl Program {
    /// Discards the contents, keeping the buffers for reuse.
    pub fn clear(&mut self) {
        self.insns.clear();
        self.labels.clear();
        self.fixups.clear();
    }

    /// Reserves a label that must be placed before the program is finished.
    pub fn label(&mut self) -> Label {
        self.labels.push(u32::MAX);
        #[allow(clippy::cast_possible_truncation)]
        Label(self.labels.len() as u32 - 1)
    }

    /// Fixes `label` at the next instruction to be emitted.
    pub fn place(&mut self, label: Label) -> Result<()> {
        let here = self.here()?;
        let Some(slot) = self.labels.get_mut(label.0 as usize) else {
            return Err(Error::msg("seccomp: unknown label"));
        };
        if *slot != u32::MAX {
            return Err(Error::msg("seccomp: label placed twice"));
        }
        *slot = here;
        Ok(())
    }

    /// Emits one instruction.
    pub fn emit(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> Result<()> {
        if self.insns.len() >= MAX_INSNS {
            return Err(Error::msg(
                "seccomp: filter exceeds 4096 instructions",
            ));
        }
        self.insns.push(SockFilter::new(code, jt, jf, k));
        Ok(())
    }

    /// Loads the word at `offset` in `seccomp_data`.
    pub(crate) fn load(&mut self, offset: u32) -> Result<()> {
        self.emit(LD_W_ABS, 0, 0, offset)
    }

    /// Masks the accumulator with `mask`.
    pub(crate) fn and(&mut self, mask: u32) -> Result<()> {
        self.emit(ALU_AND_K, 0, 0, mask)
    }

    /// Returns `action` to the kernel.
    pub(crate) fn ret(&mut self, action: u32) -> Result<()> {
        self.emit(RET_K, 0, 0, action)
    }

    /// Emits an unconditional jump to `label`.
    pub fn jump(&mut self, label: Label) -> Result<()> {
        let here = self.here()?;
        self.fixups.push((here, label));
        self.emit(JMP_JA, 0, 0, 0)
    }

    /// Emits a comparison followed by a jump to `label` on the outcome that
    /// should abandon the current path.
    ///
    /// When `continue_if` is true, the program falls through on a successful
    /// comparison and jumps to `label` otherwise. When it is false, the sense
    /// is reversed. Either way the conditional itself moves by at most one
    /// instruction, so every branch stays representable.
    pub fn guard(
        &mut self,
        code: u16,
        k: u32,
        continue_if: bool,
        label: Label,
    ) -> Result<()> {
        let (jt, jf) = if continue_if { (1, 0) } else { (0, 1) };
        self.emit(code, jt, jf, k)?;
        self.jump(label)
    }

    /// Emits a comparison that jumps to `label` when it succeeds and falls
    /// through when it does not.
    pub fn branch(&mut self, code: u16, k: u32, label: Label) -> Result<()> {
        self.guard(code, k, false, label)
    }

    /// Resolves every jump and hands back the finished program.
    ///
    /// Fails when a label was never placed, or when a jump would have to go
    /// backwards, which classic BPF forbids and which would indicate a bug in
    /// the emitter rather than in the profile.
    pub fn finish(&mut self) -> Result<&[SockFilter]> {
        debug_assert!(
            self.fixups.len() <= self.insns.len(),
            "every fixup refers to an emitted instruction"
        );
        for &(at, label) in &self.fixups {
            let Some(&target) = self.labels.get(label.0 as usize) else {
                return Err(Error::msg("seccomp: unknown label in fixup"));
            };
            if target == u32::MAX {
                return Err(Error::msg("seccomp: label never placed"));
            }
            if target <= at {
                return Err(Error::msg("seccomp: backward jump"));
            }
            let Some(insn) = self.insns.get_mut(at as usize) else {
                return Err(Error::msg("seccomp: fixup out of range"));
            };
            insn.k = target - at - 1;
        }
        // Every branch is one instruction plus a jump at this point. Folding
        // the pairs whose target is near enough is worth about a third of the
        // program on a stock profile, and a smaller program both verifies
        // faster and evaluates faster for the container's whole life.
        crate::seccomp::relax::relax(&mut self.insns, &mut self.scratch)?;
        Ok(&self.insns)
    }

    fn here(&self) -> Result<u32> {
        u32::try_from(self.insns.len())
            .map_err(|_| Error::msg("seccomp: program too long"))
    }
}
