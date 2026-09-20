//! A classic-BPF seccomp filter compiler.
//!
//! This exists because `libseccomp` is slow enough to distort container
//! startup: emitting the filter for a stock container profile costs it about
//! 18 ms of CPU, which is why other runtimes cache compiled filters on disk.
//! Emitting the same filter directly costs microseconds, so there is nothing
//! worth caching, and the cache and its failure modes go away.
//!
//! Two properties beyond speed matter:
//!
//! - **Determinism.** The same profile always produces byte-identical output,
//!   so a filter can be diffed against a reference and audited.
//! - **Size.** The emitter coalesces runs of consecutive syscalls that share an
//!   action into range checks and gives every distinct action a single shared
//!   `ret`. A smaller program verifies faster when it is installed and
//!   evaluates faster on every syscall the container makes afterwards.
//!
//! The input types here deliberately do not mention the OCI configuration:
//! lowering converts a configuration into a [`Profile`], and the compiler
//! stays independently testable against `libseccomp`'s output.

#![deny(missing_docs)]

pub mod arch;
mod emit;
pub mod insn;
mod relax;
pub mod tables;

pub use arch::Arch;
pub use emit::Compiler;
pub use insn::Program;

use crate::sys;

/// What the kernel does when a filter rule matches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Kill the whole thread group.
    KillProcess,
    /// Kill the calling thread.
    KillThread,
    /// Raise `SIGSYS`.
    Trap,
    /// Fail the call with the given errno.
    Errno(u16),
    /// Notify an attached tracer, passing the given datum.
    Trace(u16),
    /// Hand the call to a user-space supervisor.
    Notify,
    /// Log the call and allow it.
    Log,
    /// Allow the call.
    Allow,
}

impl Action {
    /// Resolves an `SCMP_ACT_*` token.
    ///
    /// `errno` supplies the datum for the two actions that carry one; the
    /// OCI configuration provides it in a separate field.
    #[must_use]
    pub fn by_name(name: &str, errno: Option<u16>) -> Option<Self> {
        let bare = name.strip_prefix("SCMP_ACT_").unwrap_or(name);
        match bare.to_ascii_uppercase().as_str() {
            "KILL_PROCESS" => Some(Self::KillProcess),
            "KILL" | "KILL_THREAD" => Some(Self::KillThread),
            "TRAP" => Some(Self::Trap),
            "ERRNO" => Some(Self::Errno(errno.unwrap_or(EPERM))),
            "TRACE" => Some(Self::Trace(errno.unwrap_or(0))),
            "NOTIFY" => Some(Self::Notify),
            "LOG" => Some(Self::Log),
            "ALLOW" => Some(Self::Allow),
            _ => None,
        }
    }

    /// The `SECCOMP_RET_*` value a filter returns for this action.
    #[must_use]
    pub const fn to_ret(self) -> u32 {
        const DATA: u32 = 0x0000_ffff;
        match self {
            Self::KillProcess => 0x8000_0000,
            Self::KillThread => 0x0000_0000,
            Self::Trap => 0x0003_0000,
            Self::Errno(e) => 0x0005_0000 | (e as u32 & DATA),
            Self::Trace(d) => 0x7ff0_0000 | (d as u32 & DATA),
            Self::Notify => 0x7fc0_0000,
            Self::Log => 0x7ffc_0000,
            Self::Allow => 0x7fff_0000,
        }
    }
}

/// The default errno for `SCMP_ACT_ERRNO` when the profile does not say.
const EPERM: u16 = 1;

/// How a syscall argument is compared against a value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    /// The argument differs from the value.
    NotEqual,
    /// The argument is below the value.
    LessThan,
    /// The argument is at or below the value.
    LessOrEqual,
    /// The argument equals the value.
    EqualTo,
    /// The argument is at or above the value.
    GreaterOrEqual,
    /// The argument is above the value.
    GreaterThan,
    /// The argument masked by `value` equals `value_two`.
    MaskedEqual,
}

impl Op {
    /// Resolves an `SCMP_CMP_*` token.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        let bare = name.strip_prefix("SCMP_CMP_").unwrap_or(name);
        match bare.to_ascii_uppercase().as_str() {
            "NE" => Some(Self::NotEqual),
            "LT" => Some(Self::LessThan),
            "LE" => Some(Self::LessOrEqual),
            "EQ" => Some(Self::EqualTo),
            "GE" => Some(Self::GreaterOrEqual),
            "GT" => Some(Self::GreaterThan),
            "MASKED_EQ" => Some(Self::MaskedEqual),
            _ => None,
        }
    }
}

/// One comparison against one syscall argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArgCmp {
    /// Which argument, counted from zero.
    pub index: u8,
    /// The value compared against, or the mask for `MaskedEqual`.
    pub value: u64,
    /// The second operand, used only by `MaskedEqual`.
    pub value_two: u64,
    /// How the comparison is made.
    pub op: Op,
}

/// One rule: a set of syscall names, an action, and optional argument
/// conditions that all have to hold for the action to apply.
#[derive(Clone, Copy, Debug)]
pub struct Rule<'a> {
    /// Syscall names this rule covers.
    pub names: &'a [&'a str],
    /// What happens when the rule matches.
    pub action: Action,
    /// Conditions on the arguments, combined with logical and.
    pub args: &'a [ArgCmp],
}

/// A complete filter description.
#[derive(Clone, Copy, Debug)]
pub struct Profile<'a> {
    /// What happens to a syscall no rule names.
    pub default_action: Action,
    /// Architectures the filter covers. Empty means the native one.
    pub arches: &'a [Arch],
    /// Rules, in the order the configuration listed them.
    ///
    /// For a given syscall, the first rule that names it wins.
    pub rules: &'a [Rule<'a>],
    /// Fail rather than skip when a rule names a syscall no architecture
    /// implements, which is usually a typo in the profile.
    pub fail_unknown_syscall: bool,
}

/// Flags for `seccomp(SECCOMP_SET_MODE_FILTER)`, resolved from the profile's
/// `SCMP_FLTATR_*` tokens.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Flags(u32);

/// Every `SECCOMP_FILTER_FLAG_*` token a profile may name, with the bit it
/// stands for.
///
/// [`Flags::add`] and the features report are both built from this one table,
/// so a flag the runtime accepts cannot go unreported and a flag it reports
/// cannot be refused.
///
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` is deliberately absent: the runtime adds
/// it itself for a profile with a notify action, and on its own it produces a
/// descriptor with nobody to hand it to.
pub const FLAGS: [(&str, u32); 5] = [
    ("SECCOMP_FILTER_FLAG_TSYNC", sys::seccomp::FLAG_TSYNC),
    ("SECCOMP_FILTER_FLAG_LOG", sys::seccomp::FLAG_LOG),
    (
        "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
        sys::seccomp::FLAG_SPEC_ALLOW,
    ),
    (
        "SECCOMP_FILTER_FLAG_TSYNC_ESRCH",
        sys::seccomp::FLAG_TSYNC_ESRCH,
    ),
    (
        "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
        sys::seccomp::FLAG_WAIT_KILLABLE_RECV,
    ),
];

impl Flags {
    /// No flags.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Adds the flag a `SECCOMP_FILTER_FLAG_*` token names.
    ///
    /// Unknown tokens are rejected rather than ignored, because silently
    /// dropping a requested hardening flag is a security failure.
    pub fn add(&mut self, name: &str) -> bool {
        let Some((_, bit)) = FLAGS.iter().find(|(token, _)| *token == name)
        else {
            return false;
        };
        self.0 |= bit;
        true
    }

    /// The raw flag word.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}
