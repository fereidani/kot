//! Turning a [`Profile`](crate::seccomp::Profile) into a classic BPF program.
//!
//! The emitted program has three parts:
//!
//! ```text
//!   ld  [arch]                     architecture dispatch
//!   jeq AUDIT_X86_64 -> block A
//!   jeq AUDIT_I386   -> block B
//!   ja  default
//!
//! block A:
//!   ld  [nr]                       one balanced search per architecture
//!   <binary search over entries>
//! block B:
//!   ...
//!
//! default:
//!   ret <default action>           one shared return per distinct action
//!   ret <action 1>
//!   ret <action 2>
//! ```
//!
//! Entries in the search are either a range of consecutive syscall numbers
//! that share an action, or a single syscall carrying argument conditions.
//! Coalescing ranges keeps the program small: in a stock container profile the
//! allowed syscalls are dense, so a few hundred names collapse into a few
//! dozen ranges.

use crate::{
    seccomp::{
        Action, ArgCmp, Op, Profile,
        arch::{self, Arch},
        insn::{JMP_JEQ_K, JMP_JGE_K, JMP_JGT_K, Label, Program},
        tables,
    },
    sys::{
        error::{Error, Result},
        seccomp::{SockFilter, data},
    },
};

/// Upper bound on the recursion depth of the binary search.
///
/// The search halves its input at every level and a program can hold at most
/// `MAX_INSNS` instructions, so no profile the kernel would accept can drive
/// the recursion deeper than this. Stack use is therefore bounded at compile
/// time, and the depth assertion in [`Compiler::dispatch`] checks that bound.
const MAX_DEPTH: u32 = 16;

/// How many entries a leaf of the search scans linearly.
///
/// Every level of the search costs two instructions for the split, and every
/// leaf costs one instruction for the jump that follows a miss. Scanning a
/// handful of entries at the bottom amortises both across those entries
/// instead of paying them per entry, which is worth roughly a factor of two on
/// a stock profile. Four is where the two costs balance for the range sizes
/// real profiles produce.
const LEAF_MAX: usize = 4;

/// One leaf of the search.
#[derive(Clone, Copy, Debug)]
enum Entry {
    /// Every syscall in `lo..=hi` takes `action`.
    Range { lo: u32, hi: u32, action: Action },
    /// One syscall whose action depends on its arguments.
    ///
    /// `start..end` index the compiler's `resolved` list, which holds the
    /// rules in the order the configuration gave them.
    Checked { nr: u32, start: u32, end: u32 },
}

impl Entry {
    const fn low(self) -> u32 {
        match self {
            Self::Range { lo, .. } => lo,
            Self::Checked { nr, .. } => nr,
        }
    }
}

/// One rule, resolved to a concrete syscall number on one architecture.
#[derive(Clone, Copy, Debug)]
struct Resolved {
    nr: u32,
    /// Position of the originating rule in the configuration, which decides
    /// precedence when several rules name the same syscall.
    seq: u32,
    action: Action,
    /// Index of this rule's conditions in `conditions`.
    first: u32,
    /// Number of conditions; zero means the rule matches unconditionally.
    count: u32,
}

/// One syscall name, resolved to a position in the shared table.
#[derive(Clone, Copy, Debug)]
struct NameRef {
    /// Position of the originating rule in the configuration.
    seq: u32,
    /// Position of the name in `tables::NAMES`.
    slot: u32,
}

/// The bit the x32 interface sets in every one of its syscall numbers.
const X32_BIT: u32 = 0x4000_0000;

/// The error a kernel that never had a syscall reports for it.
const ENOSYS: u16 = 38;

/// The highest argument a condition can compare, since a syscall takes six.
const MAX_ARG_INDEX: u8 = 5;

/// A reusable seccomp filter compiler.
///
/// The caller owns one of these and reuses it, so compiling a filter after the
/// first one allocates nothing.
#[derive(Default)]
pub struct Compiler {
    program: Program,
    /// Every syscall name in the profile, resolved to a table slot once and
    /// reused for each architecture group.
    names: Vec<NameRef>,
    /// Action and condition span of each rule, indexed by rule position.
    rules: Vec<(Action, u32, u32)>,
    /// Flattened conditions referenced by `rules`.
    conditions: Vec<ArgCmp>,
    /// Rules resolved to numbers for the architecture group being emitted,
    /// sorted by syscall number and then by configuration order.
    resolved: Vec<Resolved>,
    /// The search entries for that group.
    entries: Vec<Entry>,
    /// One shared return instruction per distinct action.
    returns: Vec<(u32, Label)>,
}

impl Compiler {
    /// A compiler with empty buffers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compiles `profile` and returns the finished program.
    ///
    /// The result borrows the compiler, so it stays valid until the next
    /// call.
    pub fn compile(&mut self, profile: &Profile<'_>) -> Result<&[SockFilter]> {
        self.program.clear();
        self.returns.clear();

        let native = [Arch::native()];
        let arches = if profile.arches.is_empty() {
            &native[..]
        } else {
            profile.arches
        };
        Self::validate_names(profile)?;
        self.resolve_names(profile)?;

        let groups = group_by_token(arches)?;
        // Both are shared with any rule asking for the same action, so the
        // dispatch guard costs an instruction only when nothing else kills.
        let default = self.action_label(profile.default_action);
        let foreign = self.action_label(Action::KillProcess);

        // Architecture dispatch. A call arriving on an architecture the
        // profile does not name cannot be judged by the profile at all: the
        // syscall numbers it was written against mean other calls on that
        // ABI, so every rule in it is about something else. Handing such a
        // call the profile's default action would let a profile whose default
        // is permissive drop its own restrictions for any process that
        // switches ABI, which is the one outcome a filter must never have.
        // The process is killed instead.
        self.program.load(data::ARCH)?;
        let mut blocks: [Option<(u32, Label)>; MAX_GROUPS] = [None; MAX_GROUPS];
        for (slot, token) in blocks.iter_mut().zip(groups.iter().flatten()) {
            let label = self.program.label();
            self.program.branch(JMP_JEQ_K, *token, label)?;
            *slot = Some((*token, label));
        }
        self.program.jump(foreign)?;

        for &(token, label) in blocks.iter().flatten() {
            self.program.place(label)?;
            self.program.load(data::NR)?;
            self.emit_unborn_guard(arches, token, profile.default_action)?;
            self.build_entries(arches, token, profile.default_action)?;
            self.emit_group(default)?;
        }

        // Split the borrow: the returns are read while the program is written.
        let (program, returns) = (&mut self.program, &self.returns);
        for &(ret, label) in returns {
            program.place(label)?;
            program.ret(ret)?;
        }

        self.program.finish()
    }

    /// Answers a call the tables have never heard of with `ENOSYS`.
    ///
    /// A syscall number above everything the tables carry is one the kernel
    /// gained after they were generated, so no rule in the profile is about
    /// it and the profile's author never decided anything for it. Answering
    /// with the default denial tells a caller the call exists and is
    /// forbidden, and a library probing for a newer interface takes that as
    /// a permanent refusal rather than as an old kernel: it stops instead of
    /// falling back to the interface it has been using all along. `ENOSYS`
    /// is what an older kernel says, which is the truth here.
    ///
    /// Nothing is emitted when the default allows, because then the new call
    /// is allowed and there is nothing to tell apart.
    ///
    /// One group can hold two architectures that share an audit token and
    /// number their calls in different ranges: the x32 interface sets the
    /// bit below, so its numbers all sit above every ordinary one. Taking
    /// the highest of the two would put the bound above every number the
    /// ordinary interface will ever use, and the guard would never fire for
    /// the architecture it was written for. The two ranges are therefore
    /// bounded separately.
    fn emit_unborn_guard(
        &mut self,
        arches: &[Arch],
        token: u32,
        default_action: Action,
    ) -> Result<()> {
        if matches!(default_action, Action::Allow | Action::Log) {
            return Ok(());
        }
        let (mut plain, mut extended) = (0, 0);
        for arch in arches {
            if arch.audit_token() != token {
                continue;
            }
            let highest = arch.highest_number();
            if highest & X32_BIT == 0 {
                plain = plain.max(highest);
            } else {
                extended = extended.max(highest);
            }
        }
        if plain == 0 && extended == 0 {
            return Ok(());
        }
        let unborn = self.action_label(Action::Errno(ENOSYS));

        // Only one range in the group: one comparison answers for it.
        if plain == 0 || extended == 0 {
            return self.program.branch(JMP_JGT_K, plain.max(extended), unborn);
        }

        let wide = self.program.label();
        let joined = self.program.label();
        self.program.branch(JMP_JGE_K, X32_BIT, wide)?;
        self.program.branch(JMP_JGT_K, plain, unborn)?;
        self.program.jump(joined)?;
        self.program.place(wide)?;
        self.program.branch(JMP_JGT_K, extended, unborn)?;
        self.program.place(joined)
    }

    /// Rejects names no architecture implements, when the profile asks for it.
    fn validate_names(profile: &Profile<'_>) -> Result<()> {
        if !profile.fail_unknown_syscall {
            return Ok(());
        }
        for rule in profile.rules {
            for name in rule.names {
                if !arch::is_known_name(name) {
                    return Err(Error::msg("seccomp: unknown syscall name"));
                }
            }
        }
        Ok(())
    }

    /// Resolves every syscall name to a table slot, once per compile.
    ///
    /// Name resolution is a binary search over the shared table, and a stock
    /// profile names several hundred syscalls across two or three
    /// architecture groups. Doing it once here rather than once per group is
    /// what keeps emission in the microsecond range.
    fn resolve_names(&mut self, profile: &Profile<'_>) -> Result<()> {
        self.names.clear();
        self.rules.clear();
        self.conditions.clear();

        for (index, rule) in profile.rules.iter().enumerate() {
            let seq = u32::try_from(index)
                .map_err(|_| Error::msg("seccomp: too many rules"))?;
            let first = u32::try_from(self.conditions.len())
                .map_err(|_| Error::msg("seccomp: too many conditions"))?;
            for arg in rule.args {
                if arg.index > MAX_ARG_INDEX {
                    return Err(Error::msg(
                        "seccomp: argument index out of range",
                    ));
                }
                self.conditions.push(*arg);
            }
            let count = u32::try_from(rule.args.len())
                .map_err(|_| Error::msg("seccomp: too many conditions"))?;
            self.rules.push((rule.action, first, count));

            for name in rule.names {
                if let Some(slot) = arch::slot_of(name) {
                    let slot = u32::try_from(slot)
                        .map_err(|_| Error::msg("seccomp: table overflow"))?;
                    self.names.push(NameRef { seq, slot });
                }
            }
        }
        Ok(())
    }

    /// Turns the resolved names into search entries for one architecture
    /// group.
    fn build_entries(
        &mut self,
        arches: &[Arch],
        token: u32,
        default_action: Action,
    ) -> Result<()> {
        self.resolved.clear();
        self.entries.clear();

        for &arch in arches {
            if arch.audit_token() != token {
                continue;
            }
            let numbers = arch.numbers();
            for &NameRef { seq, slot } in &self.names {
                let Some(&number) = numbers.get(slot as usize) else {
                    continue;
                };
                if number == tables::ABSENT {
                    continue;
                }
                let Some(&(action, first, count)) =
                    self.rules.get(seq as usize)
                else {
                    continue;
                };
                self.resolved.push(Resolved {
                    nr: number.unsigned_abs(),
                    seq,
                    action,
                    first,
                    count,
                });
            }
        }

        // Sorting by number and then by configuration order puts each
        // syscall's rules together, in the order precedence requires.
        self.resolved.sort_unstable_by_key(|r| (r.nr, r.seq));
        self.group_resolved(default_action)?;
        Ok(())
    }

    /// Splits the resolved rules into unconditional ranges and per-syscall
    /// condition groups.
    ///
    /// Within one syscall the first rule wins, so a rule with no conditions
    /// ends its group: anything the configuration listed after it for the
    /// same syscall can never be reached.
    ///
    /// The entries stay sorted: the resolved rules arrive in number order,
    /// and a checked number closes the current range first.
    fn group_resolved(&mut self, default_action: Action) -> Result<()> {
        let mut run: Option<(u32, u32, Action)> = None;
        let mut index = 0usize;
        while let Some(&head) = self.resolved.get(index) {
            let start = index;
            let mut end = index;
            let mut unconditional = None;
            while let Some(&rule) = self.resolved.get(end) {
                if rule.nr != head.nr {
                    break;
                }
                // The first unconditional rule decides the syscall, so later
                // ones only widen the group that gets skipped.
                if rule.count == 0 && unconditional.is_none() {
                    unconditional = Some(rule.action);
                }
                end += 1;
            }
            debug_assert!(end > start, "a group always covers its own head");
            index = end;

            // A lone unconditional rule that restates the default action
            // cannot change anything: a syscall it does not name reaches the
            // same action by falling through. Stock profiles are full of
            // these, and dropping them removes both their own range check and
            // the split they would force in the range around them.
            if unconditional == Some(default_action) && end - start == 1 {
                continue;
            }

            // A single unconditional rule extends the run being built, when
            // it is the next number and takes the same action.
            if let (Some(action), 1) = (unconditional, end - start) {
                match run {
                    Some((lo, hi, previous))
                        if previous == action && head.nr == hi + 1 =>
                    {
                        run = Some((lo, head.nr, action));
                    }
                    _ => {
                        close_run(&mut self.entries, &mut run);
                        run = Some((head.nr, head.nr, action));
                    }
                }
            } else {
                close_run(&mut self.entries, &mut run);
                let start = u32::try_from(start)
                    .map_err(|_| Error::msg("seccomp: index overflow"))?;
                let end = u32::try_from(end)
                    .map_err(|_| Error::msg("seccomp: index overflow"))?;
                self.entries.push(Entry::Checked {
                    nr: head.nr,
                    start,
                    end,
                });
            }
        }
        close_run(&mut self.entries, &mut run);
        Ok(())
    }

    /// Emits the search for the entries collected by `build_entries`.
    fn emit_group(&mut self, default: Label) -> Result<()> {
        let len = self.entries.len();
        self.dispatch(0, len, default, 0)
    }

    /// Emits a balanced search over `entries[lo..hi]`.
    ///
    /// Every conditional branch here moves by one instruction at most, and the
    /// long jumps are all unconditional, so a single forward patch resolves
    /// the program.
    fn dispatch(
        &mut self,
        lo: usize,
        hi: usize,
        default: Label,
        depth: u32,
    ) -> Result<()> {
        debug_assert!(depth <= MAX_DEPTH, "search depth is bounded");
        if depth > MAX_DEPTH {
            return Err(Error::msg("seccomp: search too deep"));
        }
        let len = hi.saturating_sub(lo);
        if len == 0 {
            return self.program.jump(default);
        }
        if len <= LEAF_MAX {
            return self.emit_leaf(lo, hi, default);
        }
        let mid = lo + len / 2;
        let Some(&pivot) = self.entries.get(mid) else {
            return Err(Error::msg("seccomp: pivot out of range"));
        };
        let lower = self.program.label();
        self.program.guard(JMP_JGE_K, pivot.low(), true, lower)?;
        self.dispatch(mid, hi, default, depth + 1)?;
        self.program.place(lower)?;
        self.dispatch(lo, mid, default, depth + 1)
    }

    /// Emits a linear scan over a few entries, falling through to the default
    /// once none of them matched.
    ///
    /// The entries are disjoint and sorted, so at most one can match and the
    /// scan can stop reasoning as soon as one does.
    fn emit_leaf(
        &mut self,
        from: usize,
        to: usize,
        default: Label,
    ) -> Result<()> {
        for index in from..to {
            let Some(&entry) = self.entries.get(index) else {
                return Err(Error::msg("seccomp: entry out of range"));
            };
            match entry {
                Entry::Range { lo, hi, action } => {
                    let target = self.action_label(action);
                    if lo == hi {
                        self.program.branch(JMP_JEQ_K, lo, target)?;
                    } else {
                        let next = self.program.label();
                        self.program.guard(JMP_JGE_K, lo, true, next)?;
                        self.program.guard(JMP_JGT_K, hi, false, next)?;
                        self.program.jump(target)?;
                        self.program.place(next)?;
                    }
                }
                Entry::Checked { nr, start, end } => {
                    let next = self.program.label();
                    self.program.guard(JMP_JEQ_K, nr, true, next)?;
                    self.emit_checks(start, end, default)?;
                    self.program.place(next)?;
                }
            }
        }
        self.program.jump(default)
    }

    /// Emits the conditional rules attached to one syscall, in order.
    ///
    /// The first rule whose conditions all hold decides the action. When none
    /// do, the syscall takes the default action, which is the whole point of
    /// attaching conditions in the OCI configuration.
    fn emit_checks(
        &mut self,
        start: u32,
        end: u32,
        default: Label,
    ) -> Result<()> {
        for index in start..end {
            let Some(&rule) = self.resolved.get(index as usize) else {
                return Err(Error::msg("seccomp: rule out of range"));
            };
            let target = self.action_label(rule.action);
            if rule.count == 0 {
                // An unconditional rule ends the group.
                return self.program.jump(target);
            }
            let miss = self.program.label();
            self.emit_rule_conditions(rule.first, rule.count, miss)?;
            self.program.jump(target)?;
            self.program.place(miss)?;
        }
        self.program.jump(default)
    }

    /// Emits the conditions of one rule, jumping to `miss` when the rule does
    /// not apply.
    ///
    /// Conditions on different arguments all have to hold: a rule naming both
    /// a file descriptor and a flag describes one call, not two. Conditions
    /// on the same argument are alternatives instead, because a configuration
    /// listing two values for one argument is asking for either of them; read
    /// as a conjunction they would describe an argument equal to two
    /// different values, which no call can satisfy, and the rule would be
    /// dead text that silently never fires.
    fn emit_rule_conditions(
        &mut self,
        first: u32,
        count: u32,
        miss: Label,
    ) -> Result<()> {
        for index in 0..=MAX_ARG_INDEX {
            let alternatives = self.count_conditions(first, count, index)?;
            if alternatives == 0 {
                continue;
            }
            // One alternative needs no rejoining point: failing it fails the
            // rule, and `miss` already means that.
            let satisfied = (alternatives > 1).then(|| self.program.label());
            let mut seen = 0;
            for offset in 0..count {
                let cond = self.condition_at(first, offset)?;
                if cond.index != index {
                    continue;
                }
                seen += 1;
                if seen == alternatives {
                    self.emit_condition(&cond, miss)?;
                    break;
                }
                let next = self.program.label();
                self.emit_condition(&cond, next)?;
                if let Some(satisfied) = satisfied {
                    self.program.jump(satisfied)?;
                }
                self.program.place(next)?;
            }
            if let Some(satisfied) = satisfied {
                self.program.place(satisfied)?;
            }
        }
        Ok(())
    }

    /// How many of a rule's conditions compare the given argument.
    fn count_conditions(
        &self,
        first: u32,
        count: u32,
        index: u8,
    ) -> Result<u32> {
        let mut total = 0;
        for offset in 0..count {
            if self.condition_at(first, offset)?.index == index {
                total += 1;
            }
        }
        Ok(total)
    }

    /// One of a rule's conditions, by position within the rule.
    fn condition_at(&self, first: u32, offset: u32) -> Result<ArgCmp> {
        self.conditions
            .get((first + offset) as usize)
            .copied()
            .ok_or_else(|| Error::msg("seccomp: condition out of range"))
    }

    /// Emits one argument comparison, jumping to `miss` when it fails.
    fn emit_condition(&mut self, cond: &ArgCmp, miss: Label) -> Result<()> {
        let index = u32::from(cond.index);
        let high = data::arg_high(index);
        let low = data::arg_low(index);
        let (mask_hi, mask_lo) = split(cond.value);
        let (value_hi, value_lo) = match cond.op {
            Op::MaskedEqual => split(cond.value_two),
            _ => (mask_hi, mask_lo),
        };

        match cond.op {
            Op::EqualTo | Op::MaskedEqual => {
                // Both halves have to match, so either one failing is a miss.
                let masked = cond.op == Op::MaskedEqual;
                for (word, mask, want) in
                    [(high, mask_hi, value_hi), (low, mask_lo, value_lo)]
                {
                    self.program.load(word)?;
                    if masked {
                        self.program.and(mask)?;
                    }
                    self.program.guard(JMP_JEQ_K, want, true, miss)?;
                }
                Ok(())
            }
            Op::NotEqual => {
                // Differs when either half differs, so a mismatch in the high
                // half already satisfies the rule.
                let satisfied = self.program.label();
                self.program.load(high)?;
                self.program.guard(JMP_JEQ_K, value_hi, true, satisfied)?;
                self.program.load(low)?;
                self.program.guard(JMP_JEQ_K, value_lo, false, miss)?;
                self.program.place(satisfied)
            }
            Op::GreaterOrEqual
            | Op::GreaterThan
            | Op::LessThan
            | Op::LessOrEqual => self.emit_order(cond, high, low, miss),
        }
    }

    /// Emits a 64-bit unsigned comparison for one of the four ordered
    /// operators, jumping to `miss` when it fails.
    ///
    /// All four reduce to one three-way comparison against a threshold:
    /// above `v` is at or above `v + 1`, and at or below `v` is below
    /// `v + 1`. When that increment overflows there is no threshold to
    /// compare against, because nothing is above the largest representable
    /// value and everything is at or below it.
    fn emit_order(
        &mut self,
        cond: &ArgCmp,
        high: u32,
        low: u32,
        miss: Label,
    ) -> Result<()> {
        let at_or_above =
            matches!(cond.op, Op::GreaterOrEqual | Op::GreaterThan);
        let bump =
            u64::from(matches!(cond.op, Op::GreaterThan | Op::LessOrEqual));
        let Some(threshold) = cond.value.checked_add(bump) else {
            return if at_or_above {
                self.program.jump(miss)
            } else {
                Ok(())
            };
        };
        let (value_hi, value_lo) = split(threshold);

        let satisfied = self.program.label();
        let (on_greater, on_less) = if at_or_above {
            (satisfied, miss)
        } else {
            (miss, satisfied)
        };

        self.program.load(high)?;
        self.program.branch(JMP_JGT_K, value_hi, on_greater)?;
        self.program.guard(JMP_JEQ_K, value_hi, true, on_less)?;
        self.program.load(low)?;
        self.program.branch(JMP_JGE_K, value_lo, on_greater)?;
        self.program.jump(on_less)?;
        self.program.place(satisfied)
    }

    /// Returns the shared return instruction for `action`, creating it on
    /// first use.
    fn action_label(&mut self, action: Action) -> Label {
        let ret = action.to_ret();
        if let Some(&(_, label)) = self.returns.iter().find(|&&(r, _)| r == ret)
        {
            return label;
        }
        let label = self.program.label();
        self.returns.push((ret, label));
        label
    }
}

/// Closes the run of consecutive syscall numbers being accumulated, if any,
/// by turning it into a range entry.
fn close_run(entries: &mut Vec<Entry>, run: &mut Option<(u32, u32, Action)>) {
    if let Some((lo, hi, action)) = run.take() {
        entries.push(Entry::Range { lo, hi, action });
    }
}

/// Maximum number of distinct architecture dispatch blocks.
const MAX_GROUPS: usize = 4;

/// Collects the distinct `AUDIT_ARCH_*` tokens the architectures map to,
/// keeping the order they were given in.
fn group_by_token(arches: &[Arch]) -> Result<[Option<u32>; MAX_GROUPS]> {
    let mut groups = [None; MAX_GROUPS];
    for arch in arches {
        let token = arch.audit_token();
        if groups.contains(&Some(token)) {
            continue;
        }
        // Dropping one would leave its architecture with no dispatch block,
        // so every syscall on it would fall through to the default action.
        // A filter that is quietly weaker than the profile asked for is worse
        // than one that does not compile.
        let Some(slot) = groups.iter_mut().find(|g| g.is_none()) else {
            return Err(Error::msg("seccomp: too many architecture groups"));
        };
        *slot = Some(token);
    }
    Ok(groups)
}

/// Splits a 64-bit value into the two 32-bit halves classic BPF can compare.
const fn split(value: u64) -> (u32, u32) {
    #[allow(clippy::cast_possible_truncation)]
    ((value >> 32) as u32, value as u32)
}
