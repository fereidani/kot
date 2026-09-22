//! Structural tests for the filter emitter.
//!
//! These check the two properties the emitter is built for, program size and
//! emission cost, plus the correctness of the pieces that are easy to get
//! subtly wrong: range coalescing, jump resolution, and argument comparisons.

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

use std::time::Instant;

use kot::{
    seccomp::{
        Action, Arch, ArgCmp, Compiler, Op, Profile, Rule,
        insn::{JMP_JA, RET_K},
        tables,
    },
    sys::seccomp::{SockFilter, data},
};

/// The syscall tables must stay in step with the profiles real tooling emits.
///
/// Knowing a name is not the same as implementing it. `recv` and `send` reach
/// the kernel through `socketcall` on i386, and the `pciconfig_*` calls exist
/// only on Arm, so a profile naming them on an x86 host is correct and simply
/// matches nothing.
///
/// A name no architecture implements is different: it is either a typo or a
/// gap in the tables. `syscall` is the one legitimate case, an Arm OABI
/// trampoline that the EABI tables do not carry and that `libseccomp` maps
/// anyway, so profiles copied from tooling built against it still name it.
/// Anything beyond that list means the tables need regenerating.
#[test]
fn fixture_names_resolve() {
    const EXPECTED_UNKNOWN: [&str; 1] = ["syscall"];

    let mut unknown = Vec::new();
    let mut absent_on_x86 = Vec::new();
    for name in fixture::allowed_names() {
        if !kot::seccomp::arch::is_known_name(name) {
            unknown.push(name);
        } else if Arch::X86_64.syscall(name).is_none()
            && Arch::X86.syscall(name).is_none()
            && Arch::X32.syscall(name).is_none()
        {
            absent_on_x86.push(name);
        }
    }
    println!("known but absent on x86: {absent_on_x86:?}");
    assert_eq!(
        unknown, EXPECTED_UNKNOWN,
        "unexpected names no architecture implements; regenerate the tables"
    );
}

/// A name the tables do not carry is skipped, so one stale entry in a profile
/// cannot stop a container from starting.
#[test]
fn unknown_names_do_not_block_the_rest() {
    let names = ["read", "definitely_not_a_syscall", "write"];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    // read and write are numbers 0 and 1, so they coalesce into one range and
    // the unknown name contributes nothing.
    assert!(!program.is_empty());
}

/// The emitted program must stay well inside the kernel's limit and must not
/// be larger than what libseccomp produces for the same profile, which was
/// measured at 1161 instructions.
#[test]
fn realistic_profile_is_compact() {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let len = program.len();

    println!("emitted {len} instructions for {} names", names.len());
    assert!(len < 4096, "filter must fit the kernel limit, got {len}");
    assert!(
        len <= 1161,
        "filter must not be larger than libseccomp's 1161, got {len}"
    );

    // The last instruction has to be a return: the verifier rejects a program
    // whose final instruction is a jump, and every path must terminate.
    let last = program.last().expect("non-empty");
    assert_eq!(last.code, RET_K, "program must end in a return");
}

/// Emission has to be fast enough that caching compiled filters on disk, as
/// other runtimes do, buys nothing.
#[test]
fn emission_is_fast() {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    // Warm the buffers so the measurement reflects steady state, where a
    // runtime handling many containers spends its time.
    for _ in 0..8 {
        compiler.compile(&profile).expect("compile");
    }

    let mut best = f64::MAX;
    for _ in 0..64 {
        let start = Instant::now();
        let program = compiler.compile(&profile).expect("compile");
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        std::hint::black_box(program);
        best = best.min(elapsed);
    }

    // The budget is a release-build figure: it is the number that decides
    // whether caching compiled filters on disk is worth anything, and an
    // unoptimised build says nothing about that. Debug builds still get a
    // loose bound so that an accidental quadratic loop shows up here rather
    // than in a benchmark run much later.
    let budget = if cfg!(debug_assertions) {
        2_000.0
    } else {
        200.0
    };
    println!("best emission: {best:.1} us (budget {budget:.0} us)");
    assert!(
        best < budget,
        "emission must stay under {budget:.0} us, took {best:.1} us"
    );
}

/// The same profile must always produce byte-identical output, so a filter can
/// be diffed against a reference.
#[test]
fn emission_is_deterministic() {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut first = Compiler::new();
    let a: Vec<_> = first.compile(&profile).expect("compile").to_vec();
    let mut second = Compiler::new();
    let b: Vec<_> = second.compile(&profile).expect("compile").to_vec();
    assert_eq!(a, b, "emission must be deterministic");

    // A reused compiler must produce the same thing as a fresh one.
    let c: Vec<_> = first.compile(&profile).expect("compile").to_vec();
    assert_eq!(a, c, "reuse must not change the output");
}

/// Consecutive syscall numbers sharing an action collapse into one range,
/// which keeps the program small.
#[test]
fn consecutive_syscalls_coalesce() {
    // read, write, open, close are numbers 0, 1, 2, 3 on x86-64.
    let names = ["read", "write", "open", "close"];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &[],
    }];
    let coalesced = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    // Two syscalls far apart cannot merge.
    let scattered_names = ["read", "execve"];
    let scattered_rules = [Rule {
        names: &scattered_names,
        action: Action::Allow,
        args: &[],
    }];
    let scattered = Profile {
        rules: &scattered_rules,
        ..coalesced
    };

    let mut compiler = Compiler::new();
    let merged = compiler.compile(&coalesced).expect("compile").len();
    let separate = compiler.compile(&scattered).expect("compile").len();
    assert!(
        merged <= separate,
        "four consecutive numbers ({merged}) must not cost more than two \
         scattered ones ({separate})"
    );
}

/// Every distinct action gets exactly one return instruction, shared by every
/// rule that uses it.
#[test]
fn actions_share_one_return() {
    let allow = ["read", "write"];
    let deny = ["ptrace", "mount"];
    let rules = [
        Rule {
            names: &allow,
            action: Action::Allow,
            args: &[],
        },
        Rule {
            names: &deny,
            action: Action::Errno(13),
            args: &[],
        },
    ];
    let profile = Profile {
        default_action: Action::KillProcess,
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let returns = program.iter().filter(|i| i.code == RET_K).count();
    assert_eq!(
        returns, 4,
        "one return for the default, one per distinct action, and one for \
         the syscalls too new for the tables"
    );
}

/// Classic BPF cannot jump backwards, and the emitter must never produce one.
#[test]
fn every_jump_goes_forward_and_lands_inside() {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let len = program.len();

    for (index, insn) in program.iter().enumerate() {
        let next = index + 1;
        if insn.code == JMP_JA {
            let target = next + insn.k as usize;
            assert!(
                target < len,
                "unconditional jump at {index} lands outside the program"
            );
        } else if insn.code & 0x07 == 0x05 {
            // Any other jump class: both arms must stay inside.
            assert!(
                next + usize::from(insn.jt) < len,
                "true arm of branch at {index} lands outside"
            );
            assert!(
                next + usize::from(insn.jf) < len,
                "false arm of branch at {index} lands outside"
            );
        }
    }
}

/// A profile naming a syscall no architecture implements is a typo, and the
/// configuration can ask for it to be fatal.
#[test]
fn unknown_syscall_names_can_be_fatal() {
    let names = ["definitely_not_a_syscall"];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &[],
    }];
    let lenient = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let strict = Profile {
        fail_unknown_syscall: true,
        ..lenient
    };

    let mut compiler = Compiler::new();
    assert!(
        compiler.compile(&lenient).is_ok(),
        "unknown names are skipped"
    );
    assert!(
        compiler.compile(&strict).is_err(),
        "unless asked to be fatal"
    );
}

/// Every comparison operator has to emit a program the verifier accepts, with
/// jumps that resolve.
///
/// Behaviour is checked separately against the kernel.
#[test]
fn every_operator_emits() {
    let ops = [
        Op::NotEqual,
        Op::LessThan,
        Op::LessOrEqual,
        Op::EqualTo,
        Op::GreaterOrEqual,
        Op::GreaterThan,
        Op::MaskedEqual,
    ];
    let names = ["ioctl"];
    let mut compiler = Compiler::new();
    for op in ops {
        for value in [0u64, 1, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
            let args = [ArgCmp {
                index: 1,
                value,
                value_two: 0,
                op,
            }];
            let rules = [Rule {
                names: &names,
                action: Action::Allow,
                args: &args,
            }];
            let profile = Profile {
                default_action: Action::Errno(1),
                arches: &[Arch::X86_64],
                rules: &rules,
                fail_unknown_syscall: false,
            };
            let program = compiler
                .compile(&profile)
                .unwrap_or_else(|e| panic!("{op:?} value {value:#x}: {e}"));
            assert!(!program.is_empty());
        }
    }
}

/// An argument index the kernel does not have must be rejected rather than
/// silently reading past the end of `seccomp_data`.
#[test]
fn argument_index_is_bounded() {
    let names = ["ioctl"];
    let args = [ArgCmp {
        index: 6,
        value: 0,
        value_two: 0,
        op: Op::EqualTo,
    }];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &args,
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    assert!(compiler.compile(&profile).is_err());
}

/// Branch relaxation must not change what a filter does, only how large it is.
///
/// The structural check that every jump lands inside the program covers the
/// gross failure; this one pins the saving, so a regression that quietly
/// disables folding shows up as a test failure rather than as a slow
/// container.
#[test]
fn branch_relaxation_shrinks_the_program() {
    let names = fixture::allowed_names();
    let args = fixture::arg_rules();
    let rules = fixture::realistic_rules(&names, &args);
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let len = program.len();

    // Without folding the same profile needs about 676 instructions, and
    // libseccomp needs 1161. Anything near either number means the pass
    // stopped working.
    assert!(
        len < 500,
        "folding should bring the program well under 500 instructions, got {len}"
    );

    // A folded branch has a displacement on exactly one arm, and the other arm
    // falls through. Check that at least some branches ended up that way, or
    // the pass ran without doing anything.
    let folded = program
        .iter()
        .filter(|i| i.code & 0x07 == 0x05 && i.code != JMP_JA)
        .filter(|i| i.jt > 1 || i.jf > 1)
        .count();
    assert!(folded > 0, "no branch carries a folded displacement");
}

/// Classic BPF opcodes the emitter produces, encoded as the kernel defines
/// them. The emitter's own copies are internal, and a test that borrowed them
/// would agree with the emitter by construction rather than checking it.
mod opcode {
    pub const LD_W_ABS: u16 = 0x20;
    pub const ALU_AND_K: u16 = 0x54;
    pub const JMP_JA: u16 = 0x05;
    pub const JMP_JEQ_K: u16 = 0x15;
    pub const JMP_JGT_K: u16 = 0x25;
    pub const JMP_JGE_K: u16 = 0x35;
    pub const RET_K: u16 = 0x06;
}

/// The word a load at `offset` reads out of `seccomp_data`.
fn word_at(offset: u32, arch: u32, nr: u32, args: &[u64; 6]) -> u32 {
    if offset == data::NR {
        return nr;
    }
    if offset == data::ARCH {
        return arch;
    }
    for (index, value) in args.iter().enumerate() {
        let index = index as u32;
        if offset == data::arg_low(index) {
            return *value as u32;
        }
        if offset == data::arg_high(index) {
            return (*value >> 32) as u32;
        }
    }
    panic!("unexpected load offset {offset}")
}

/// Runs a compiled filter the way the kernel would, returning its action.
///
/// Every jump the emitter produces goes forward, so the program cannot run
/// for more steps than it has instructions.
fn evaluate(
    program: &[SockFilter],
    arch: u32,
    nr: u32,
    args: &[u64; 6],
) -> u32 {
    let mut acc: u32 = 0;
    let mut pc: usize = 0;
    for _ in 0..program.len() {
        let insn = program.get(pc).expect("the program ran off its end");
        pc += 1;
        match insn.code {
            opcode::LD_W_ABS => acc = word_at(insn.k, arch, nr, args),
            opcode::ALU_AND_K => acc &= insn.k,
            opcode::RET_K => return insn.k,
            opcode::JMP_JA => pc += insn.k as usize,
            opcode::JMP_JEQ_K | opcode::JMP_JGT_K | opcode::JMP_JGE_K => {
                let taken = match insn.code {
                    opcode::JMP_JEQ_K => acc == insn.k,
                    opcode::JMP_JGT_K => acc > insn.k,
                    _ => acc >= insn.k,
                };
                pc += usize::from(if taken { insn.jt } else { insn.jf });
            }
            other => panic!("unexpected opcode {other:#x}"),
        }
    }
    panic!("the program never returned");
}

/// A call arriving on an architecture the profile does not name is killed.
///
/// The syscall numbers a profile was written against name other calls on
/// another ABI, so none of its rules describe what arrived. Answering with
/// the profile's default action would mean a profile whose default is
/// permissive stops restricting anything at all for a process that switches
/// ABI, and every deny rule in it would be skipped.
#[test]
fn a_call_from_an_unnamed_architecture_is_killed() {
    let allow = ["read", "write"];
    let rules = [Rule {
        names: &allow,
        action: Action::Allow,
        args: &[],
    }];
    for default_action in [Action::Allow, Action::Errno(1)] {
        let profile = Profile {
            default_action,
            arches: &[Arch::X86_64],
            rules: &rules,
            fail_unknown_syscall: false,
        };
        let mut compiler = Compiler::new();
        let program = compiler.compile(&profile).expect("compile");

        for foreign in [Arch::X86, Arch::Aarch64, Arch::Arm] {
            assert_eq!(
                evaluate(program, foreign.audit_token(), 0, &[0; 6]),
                Action::KillProcess.to_ret(),
                "a call on {foreign:?} cannot be judged by this profile"
            );
        }
    }
}

/// The architecture the profile does name still gets the profile's answers.
///
/// Without this the check above would hold for a filter that killed
/// everything.
#[test]
fn a_named_architecture_still_gets_the_default_action() {
    let allow = ["read", "write"];
    let rules = [Rule {
        names: &allow,
        action: Action::Allow,
        args: &[],
    }];
    for default_action in [Action::Allow, Action::Errno(1)] {
        let profile = Profile {
            default_action,
            arches: &[Arch::X86_64],
            rules: &rules,
            fail_unknown_syscall: false,
        };
        let mut compiler = Compiler::new();
        let program = compiler.compile(&profile).expect("compile");

        // A syscall the tables know and no rule names reaches the default
        // action. It has to be one the tables carry: a number above all of
        // them is a call that did not exist when the profile was written,
        // which the filter answers separately.
        let unnamed = syscall_number(Arch::X86_64, "mount");
        assert_eq!(
            evaluate(program, Arch::X86_64.audit_token(), unnamed, &[0; 6]),
            default_action.to_ret(),
            "the named architecture keeps the profile's default"
        );
    }
}

/// The syscall number a name has on one architecture.
fn syscall_number(arch: Arch, name: &str) -> u32 {
    let slot = tables::NAMES
        .iter()
        .position(|known| *known == name)
        .expect("the tables should know this name");
    let number = arch.numbers()[slot];
    u32::try_from(number).expect("implemented on this architecture")
}

/// Two conditions on the same argument are alternatives, not a conjunction.
///
/// A configuration listing two allowed values for one argument is asking for
/// either of them. Requiring both would describe an argument equal to two
/// different values at once, so the rule could never fire and the action it
/// names would silently never apply.
#[test]
fn conditions_on_one_argument_are_alternatives() {
    let names = ["personality"];
    let args = [
        ArgCmp {
            index: 0,
            value: 1,
            value_two: 0,
            op: Op::EqualTo,
        },
        ArgCmp {
            index: 0,
            value: 2,
            value_two: 0,
            op: Op::EqualTo,
        },
    ];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &args,
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let nr = syscall_number(Arch::X86_64, "personality");
    let arch = Arch::X86_64.audit_token();

    for value in [1, 2] {
        let mut args = [0u64; 6];
        args[0] = value;
        assert_eq!(
            evaluate(program, arch, nr, &args),
            Action::Allow.to_ret(),
            "either listed value should satisfy the rule"
        );
    }
    let mut args = [0u64; 6];
    args[0] = 3;
    assert_eq!(
        evaluate(program, arch, nr, &args),
        Action::Errno(1).to_ret(),
        "a value the rule does not list still takes the default"
    );
}

/// Conditions on different arguments still all have to hold.
///
/// The alternative reading would turn a rule describing one call into one
/// that fires on any of its parts, which would widen every profile that
/// constrains two arguments at once.
#[test]
fn conditions_on_different_arguments_must_all_hold() {
    let names = ["personality"];
    let args = [
        ArgCmp {
            index: 0,
            value: 1,
            value_two: 0,
            op: Op::EqualTo,
        },
        ArgCmp {
            index: 1,
            value: 7,
            value_two: 0,
            op: Op::EqualTo,
        },
    ];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &args,
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };

    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let nr = syscall_number(Arch::X86_64, "personality");
    let arch = Arch::X86_64.audit_token();

    let cases = [
        ([1u64, 7], Action::Allow.to_ret()),
        ([1, 8], Action::Errno(1).to_ret()),
        ([2, 7], Action::Errno(1).to_ret()),
    ];
    for (values, expected) in cases {
        let mut args = [0u64; 6];
        args[0] = values[0];
        args[1] = values[1];
        assert_eq!(
            evaluate(program, arch, nr, &args),
            expected,
            "arguments {values:?} should decide the rule together"
        );
    }
}

/// A syscall newer than the tables is reported as one the kernel lacks.
///
/// The profile's author decided nothing about a call that did not exist when
/// they wrote it. Answering with the profile's denial tells a library the
/// call is there and forbidden, and a library probing for a newer interface
/// treats that as final rather than falling back to the one it has always
/// used. `ENOSYS` is what an older kernel says, and it is the truth.
#[test]
fn a_syscall_newer_than_the_tables_reports_as_absent() {
    const ENOSYS: u16 = 38;

    let names = ["read", "write"];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let arch = Arch::X86_64.audit_token();
    let highest = Arch::X86_64.highest_number();

    assert_eq!(
        evaluate(program, arch, highest + 1, &[0; 6]),
        Action::Errno(ENOSYS).to_ret(),
        "a number above the tables is a call the kernel did not have"
    );
    assert_eq!(
        evaluate(
            program,
            arch,
            syscall_number(Arch::X86_64, "mount"),
            &[0; 6]
        ),
        Action::Errno(1).to_ret(),
        "a call the tables know still takes the profile's default"
    );
}

/// A profile that allows by default says nothing new about a new syscall.
///
/// The call is allowed either way, so there is nothing to tell apart and no
/// guard is emitted.
#[test]
fn an_allowing_profile_gets_no_absent_syscall_guard() {
    let names = ["ptrace"];
    let rules = [Rule {
        names: &names,
        action: Action::Errno(1),
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Allow,
        arches: &[Arch::X86_64],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");

    assert_eq!(
        evaluate(
            program,
            Arch::X86_64.audit_token(),
            Arch::X86_64.highest_number() + 1,
            &[0; 6]
        ),
        Action::Allow.to_ret(),
        "an allowing profile allows a call it has never heard of"
    );
}

/// The guard still fires when the profile lists the architectures a stock
/// one does.
///
/// Two of them share an audit token and number their calls in different
/// ranges: the x32 interface sets a high bit, so every one of its numbers
/// sits above every ordinary one. A single bound taken across both would be
/// above everything x86-64 will ever use, and the guard would never fire
/// for the architecture it was written for.
#[test]
fn the_absent_syscall_guard_survives_a_shared_token() {
    const ENOSYS: u16 = 38;
    const X32_BIT: u32 = 0x4000_0000;

    let names = ["read", "write"];
    let rules = [Rule {
        names: &names,
        action: Action::Allow,
        args: &[],
    }];
    let profile = Profile {
        default_action: Action::Errno(1),
        arches: &[Arch::X86_64, Arch::X86, Arch::X32],
        rules: &rules,
        fail_unknown_syscall: false,
    };
    let mut compiler = Compiler::new();
    let program = compiler.compile(&profile).expect("compile");
    let arch = Arch::X86_64.audit_token();

    let beyond = Arch::X86_64.highest_number() + 1;
    assert!(beyond < X32_BIT, "the ordinary range is the low one");
    assert_eq!(
        evaluate(program, arch, beyond, &[0; 6]),
        Action::Errno(ENOSYS).to_ret(),
        "a new x86-64 call is still reported as one the kernel lacks"
    );

    // The other range keeps its own bound: a call it does carry is judged
    // by the profile rather than reported absent.
    let known = syscall_number(Arch::X32, "mount");
    assert!(known >= X32_BIT, "that range is the high one");
    assert_eq!(
        evaluate(program, arch, known, &[0; 6]),
        Action::Errno(1).to_ret(),
        "a call the tables carry takes the profile's default"
    );
    assert_eq!(
        evaluate(program, arch, Arch::X32.highest_number() + 1, &[0; 6]),
        Action::Errno(ENOSYS).to_ret(),
        "and a number above that range is absent too"
    );
}
