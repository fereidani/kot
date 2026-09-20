//! Diagnostic: report how a profile's instructions are spent.
//!
//! Prints the entry count per architecture group and the emitted size, which
//! is how to tell a coalescing problem from a conditional-rule problem. Run
//! with `cargo run --example filter-stats`.

// A diagnostic, not production code: failing loudly at the first problem is
// the point, so the crate's ban on panicking constructs does not apply.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation
)]

use kot::seccomp::{Action, Arch, Compiler, Profile, Rule, arch};

fn main() {
    let names: Vec<&str> =
        include_str!("../tests/data/seccomp/allowed-syscalls.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();

    for arches in [
        &[Arch::X86_64][..],
        &[Arch::X86_64, Arch::X32][..],
        &[Arch::X86_64, Arch::X86, Arch::X32][..],
    ] {
        report(&names, arches);
    }
}

fn report(names: &[&str], arches: &[Arch]) {
    let rules = [Rule {
        names,
        action: Action::Allow,
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches,
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");

    // Count how many coalesced ranges each architecture contributes, which is
    // what the search size is driven by.
    for &a in arches {
        let mut numbers: Vec<u32> =
            names.iter().filter_map(|n| a.syscall(n)).collect();
        numbers.sort_unstable();
        numbers.dedup();
        let mut ranges = 0usize;
        let mut previous: Option<u32> = None;
        for n in &numbers {
            if previous != Some(n.wrapping_sub(1)) {
                ranges += 1;
            }
            previous = Some(*n);
        }
        println!(
            "  {:<20} {:>4} numbers -> {:>3} ranges",
            a.name(),
            numbers.len(),
            ranges
        );
    }
    let tokens: Vec<u32> = {
        let mut t: Vec<u32> = arches.iter().map(|a| a.audit_token()).collect();
        t.sort_unstable();
        t.dedup();
        t
    };
    println!(
        "arches {:?}: {} groups, {} instructions\n",
        arches.iter().map(|a| a.name()).collect::<Vec<_>>(),
        tokens.len(),
        program.len()
    );
    let _ = arch::is_known_name("read");
}
