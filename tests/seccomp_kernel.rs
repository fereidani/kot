//! Behavioural tests against the running kernel.
//!
//! A filter the verifier accepts can still enforce the wrong thing, which is
//! the failure mode that matters: a container that silently keeps a syscall
//! its profile meant to deny. These tests install real filters and check what
//! the kernel actually does.
//!
//! Each case runs in a fresh child process, because installing a filter is
//! irreversible. The child is this same test binary re-executed with
//! `KOT_SECCOMP_CASE` set, which avoids forking a process the test harness
//! has already made multi-threaded.

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

mod fixture;

use std::process::Command;

use kot::{
    seccomp::{Action, Arch, ArgCmp, Compiler, Op, Profile, Rule},
    sys::{
        prctl,
        raw::{nr, syscall5},
        seccomp,
    },
};

/// Exit code meaning the probe returned what the filter should have made it
/// return.
const PASS: i32 = 0;
/// Exit code meaning the probe returned something else.
const MISMATCH: i32 = 3;
/// Exit code meaning the filter could not be built or installed.
const SETUP_FAILED: i32 = 4;

/// An option number `prctl` will never implement, so an unfiltered call
/// reliably fails with `EINVAL` and any other result came from the filter.
const UNUSED_OPTION: u64 = 0x0dea_dbee;
/// A second unused option, for checking that a rule does not match too much.
const OTHER_OPTION: u64 = 0x0baa_df00;

const EINVAL: i32 = 22;
const EPERM: i32 = 1;
const EACCES: i32 = 13;

/// Calls `prctl` directly, bypassing any wrapper that might reject the
/// arguments before the kernel sees them.
fn probe(option: u64, arg: u64) -> i32 {
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: `prctl` with an option it does not implement reads none of its
    // remaining arguments and returns `EINVAL`, so passing scalars is sound.
    let r =
        unsafe { syscall5(nr::PRCTL, option as usize, arg as usize, 0, 0, 0) };
    if r < 0 {
        #[allow(clippy::cast_possible_truncation)]
        return -r as i32;
    }
    0
}

/// Builds the profile for a named case.
///
/// Every case denies by exception rather than by default, so the child can
/// still make the syscalls it needs to report a result.
fn profile_for(case: &str, args: &mut Vec<ArgCmp>) -> Option<Action> {
    args.clear();
    match case {
        "plain_errno" => Some(Action::Errno(EPERM as u16)),
        "arg_equal" => {
            args.push(ArgCmp {
                index: 0,
                value: UNUSED_OPTION,
                value_two: 0,
                op: Op::EqualTo,
            });
            Some(Action::Errno(EPERM as u16))
        }
        "arg_not_equal" => {
            args.push(ArgCmp {
                index: 0,
                value: OTHER_OPTION,
                value_two: 0,
                op: Op::NotEqual,
            });
            Some(Action::Errno(EPERM as u16))
        }
        "arg_less_than" => {
            args.push(ArgCmp {
                index: 0,
                value: UNUSED_OPTION + 1,
                value_two: 0,
                op: Op::LessThan,
            });
            Some(Action::Errno(EACCES as u16))
        }
        "arg_greater_equal" => {
            args.push(ArgCmp {
                index: 0,
                value: UNUSED_OPTION,
                value_two: 0,
                op: Op::GreaterOrEqual,
            });
            Some(Action::Errno(EACCES as u16))
        }
        "arg_masked_equal" => {
            args.push(ArgCmp {
                index: 0,
                value: 0xff,
                value_two: 0xee,
                op: Op::MaskedEqual,
            });
            Some(Action::Errno(EPERM as u16))
        }
        "arg_high_word" => {
            // Argument one carries a value that only differs from zero above
            // the 32-bit boundary, which exercises the two-word comparison.
            args.push(ArgCmp {
                index: 1,
                value: 0x1_0000_0000,
                value_two: 0,
                op: Op::EqualTo,
            });
            Some(Action::Errno(EPERM as u16))
        }
        "kill_process" => {
            args.push(ArgCmp {
                index: 0,
                value: UNUSED_OPTION,
                value_two: 0,
                op: Op::EqualTo,
            });
            Some(Action::KillProcess)
        }
        _ => None,
    }
}

/// Builds and installs the full stock profile, which is the case that proves
/// the verifier accepts what the emitter produces at realistic size.
fn run_realistic() -> i32 {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(EPERM as u16),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let Ok(program) = compiler.compile(&profile) else {
        eprintln!("realistic: compile failed");
        return SETUP_FAILED;
    };
    if prctl::set_no_new_privs().is_err() {
        return SETUP_FAILED;
    }
    if let Err(e) = seccomp::set_mode_filter(program, 0) {
        eprintln!("realistic: install failed: {e}");
        return SETUP_FAILED;
    }
    // Reaching here means the kernel verified and installed the filter, and
    // that the syscalls needed to get this far are still permitted.
    PASS
}

/// Installs a notifying filter that also asks for every thread to be
/// synchronised.
///
/// The kernel refuses that pair unless a `TSYNC` failure may come back as an
/// errno, because the call's answer is already the listener descriptor. The
/// runtime adds the listener itself, so it has to add the flag that keeps the
/// pair legal; without it the install fails with `EINVAL` and the container
/// never starts.
fn run_tsync_listener() -> i32 {
    let names = ["prctl"];
    let rules = [Rule {
        names: &names,
        action: Action::Notify,
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Allow,
        arches: &[Arch::native()],
        rules: &rules,
        fail_unknown_syscall: true,
    };
    let mut compiler = Compiler::new();
    let Ok(program) = compiler.compile(&profile) else {
        eprintln!("tsync_listener: compile failed");
        return SETUP_FAILED;
    };
    if prctl::set_no_new_privs().is_err() {
        return SETUP_FAILED;
    }
    match seccomp::set_mode_filter_listener(program, seccomp::FLAG_TSYNC) {
        Ok(listener) => {
            drop(listener);
            PASS
        }
        Err(e) => {
            eprintln!("tsync_listener: install failed: {e}");
            SETUP_FAILED
        }
    }
}

/// Runs the child side of a case: install the filter, probe, report.
fn run_case(case: &str) -> i32 {
    if case == "realistic" {
        return run_realistic();
    }
    if case == "tsync_listener" {
        return run_tsync_listener();
    }
    let mut args = Vec::new();
    let Some(action) = profile_for(case, &mut args) else {
        return SETUP_FAILED;
    };
    let names = ["prctl"];
    let rules = [Rule {
        names: &names,
        action,
        args: &args,
    }];
    let profile = Profile {
        default_action: Action::Allow,
        arches: &[Arch::native()],
        rules: &rules,
        fail_unknown_syscall: true,
    };

    let mut compiler = Compiler::new();
    let Ok(program) = compiler.compile(&profile) else {
        return SETUP_FAILED;
    };
    if prctl::set_no_new_privs().is_err() {
        return SETUP_FAILED;
    }
    if seccomp::set_mode_filter(program, 0).is_err() {
        return SETUP_FAILED;
    }

    let (matching, non_matching, expected) = match case {
        "plain_errno" => (probe(UNUSED_OPTION, 0), EINVAL, EPERM),
        "arg_equal" | "kill_process" | "arg_not_equal" => {
            (probe(UNUSED_OPTION, 0), probe(OTHER_OPTION, 0), EPERM)
        }
        "arg_less_than" => {
            (probe(UNUSED_OPTION, 0), probe(UNUSED_OPTION + 1, 0), EACCES)
        }
        "arg_greater_equal" => {
            (probe(UNUSED_OPTION, 0), probe(UNUSED_OPTION - 1, 0), EACCES)
        }
        "arg_masked_equal" => (probe(0x1ee, 0), probe(0x1ef, 0), EPERM),
        "arg_high_word" => (
            probe(UNUSED_OPTION, 0x1_0000_0000),
            probe(UNUSED_OPTION, 0),
            EPERM,
        ),
        _ => return SETUP_FAILED,
    };

    if matching != expected {
        eprintln!("{case}: matching call gave {matching}, want {expected}");
        return MISMATCH;
    }
    if non_matching != EINVAL {
        eprintln!(
            "{case}: non-matching call gave {non_matching}, want {EINVAL}"
        );
        return MISMATCH;
    }
    PASS
}

/// Re-executes this binary to run `case` in a fresh process.
fn spawn_case(case: &str) -> std::process::Output {
    let exe = std::env::current_exe().expect("current exe");
    Command::new(exe)
        .args(["--exact", "child_harness", "--nocapture"])
        .env("KOT_SECCOMP_CASE", case)
        .output()
        .expect("spawn child")
}

/// The child side. Does nothing unless the environment selects a case, so the
/// normal test run passes over it.
///
/// A killing action ends the child with `SIGSYS`, whose default is to dump
/// core, and a core of the test binary would land in whichever directory the
/// tests were run from. Refusing the dump up front keeps the repository free
/// of them, whether the kernel writes dumps to files or hands them to a
/// collector, since both honour a zero limit.
#[test]
fn child_harness() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let Ok(case) = std::env::var("KOT_SECCOMP_CASE") else {
        return;
    };
    let no_core = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if setrlimit(Resource::Core, no_core).is_err() {
        std::process::exit(SETUP_FAILED);
    }
    std::process::exit(run_case(&case));
}

/// Asserts that a case's child exited cleanly.
fn assert_case(case: &str) {
    let out = spawn_case(case);
    let code = out.status.code();
    assert_eq!(
        code,
        Some(PASS),
        "{case}: exit {code:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn errno_action_is_enforced() {
    assert_case("plain_errno");
}

#[test]
fn equality_on_an_argument_is_enforced() {
    assert_case("arg_equal");
}

#[test]
fn inequality_on_an_argument_is_enforced() {
    assert_case("arg_not_equal");
}

#[test]
fn less_than_on_an_argument_is_enforced() {
    assert_case("arg_less_than");
}

#[test]
fn greater_or_equal_on_an_argument_is_enforced() {
    assert_case("arg_greater_equal");
}

#[test]
fn masked_equality_on_an_argument_is_enforced() {
    assert_case("arg_masked_equal");
}

/// The comparison has to look at both halves of a 64-bit argument.
///
/// A filter that only compared the low word would let this through.
#[test]
fn the_high_word_of_an_argument_is_compared() {
    assert_case("arg_high_word");
}

/// A killing action must actually kill, and with `SIGSYS`.
#[test]
fn kill_process_action_is_enforced() {
    let out = spawn_case("kill_process");
    assert_eq!(out.status.code(), None, "child should die from a signal");
    let signal = std::os::unix::process::ExitStatusExt::signal(&out.status);
    assert_eq!(signal, Some(31), "child should die from SIGSYS");
}

/// The realistic profile must install on this kernel.
///
/// If the verifier rejects it, the program is malformed in a way the
/// structural tests cannot see.
#[test]
fn realistic_profile_installs() {
    let out = spawn_case("realistic");
    assert_eq!(
        out.status.code(),
        Some(PASS),
        "realistic profile failed to build or install: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A filter that both notifies and synchronises threads has to install.
///
/// The two together are legal only when a `TSYNC` failure may be reported as
/// an errno. The runtime is the one adding the listener, so it is the one that
/// has to say so; a profile naming `SECCOMP_FILTER_FLAG_TSYNC` beside a notify
/// action used to fail with a bare `EINVAL`.
#[test]
fn a_notifying_filter_can_also_synchronise_threads() {
    assert_case("tsync_listener");
}

/// The flag probe has to tell a flag the kernel knows from one it does not,
/// or the features report is just a list of everything.
#[test]
fn the_flag_probe_refuses_a_bit_the_kernel_has_no_flag_for() {
    assert!(
        seccomp::flags_available(seccomp::FLAG_TSYNC),
        "TSYNC has been in every kernel this runtime supports"
    );
    assert!(
        !seccomp::flags_available(1 << 30),
        "a bit the kernel defines no flag for must report as unsupported"
    );
}
