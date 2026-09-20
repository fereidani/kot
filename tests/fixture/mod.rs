//! Shared loader for the realistic profile fixtures.
//!
//! The fixtures are the stock container profile that ships on Fedora, reduced
//! to what applies unconditionally on x86-64. Using real data rather than a
//! synthetic list is the point: program size and emission cost both depend on
//! how densely the allowed syscall numbers pack, and a made-up profile would
//! not reproduce that.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use kot::seccomp::{Action, ArgCmp, Op, Rule};

/// Syscall names the stock profile allows, one per line.
pub const ALLOWED: &str = include_str!("../data/seccomp/allowed-syscalls.txt");

/// Conditional rules from the same profile.
pub const ARG_RULES: &str = include_str!("../data/seccomp/arg-rules.txt");

/// Strips comments and blank lines from a fixture.
pub fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The allowed syscall names.
pub fn allowed_names() -> Vec<&'static str> {
    lines(ALLOWED).collect()
}

/// One conditional rule, with its name kept separate so the caller can build
/// the borrowed `Rule` that the compiler takes.
pub struct ArgRule {
    pub name: [&'static str; 1],
    pub action: Action,
    pub args: [ArgCmp; 1],
}

/// The conditional rules, parsed.
pub fn arg_rules() -> Vec<ArgRule> {
    let mut out = Vec::new();
    for line in lines(ARG_RULES) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (
            Some(name),
            Some(index),
            Some(value),
            Some(value_two),
            Some(op),
            Some(action),
        ) = (f.first(), f.get(1), f.get(2), f.get(3), f.get(4), f.get(5))
        else {
            panic!("malformed fixture line: {line}");
        };
        out.push(ArgRule {
            name: [name],
            action: Action::by_name(action, Some(1))
                .unwrap_or_else(|| panic!("bad action {action}")),
            args: [ArgCmp {
                index: index.parse().expect("bad index"),
                value: value.parse().expect("bad value"),
                value_two: value_two.parse().expect("bad valueTwo"),
                op: Op::by_name(op).unwrap_or_else(|| panic!("bad op {op}")),
            }],
        });
    }
    out
}

/// Builds the realistic profile: one allow rule covering every allowed name,
/// plus the conditional rules, over the three x86 architectures.
pub fn realistic_rules<'a>(
    names: &'a [&'a str],
    arg_rules: &'a [ArgRule],
) -> Vec<Rule<'a>> {
    let mut rules = vec![Rule {
        names,
        action: Action::Allow,
        args: &[],
    }];
    for rule in arg_rules {
        rules.push(Rule {
            names: &rule.name,
            action: rule.action,
            args: &rule.args,
        });
    }
    rules
}
