//! What the command line accepts and refuses.
//!
//! These drive the binary and never the parser directly, because the
//! contract lives in what a caller sees: the exit status and the message on
//! standard error. None of
//! them need privileges, since nothing here reaches a container.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::process::{Command, Output};

/// The runtime under test.
const RUNTIME: &str = env!("CARGO_BIN_EXE_kot");

/// Runs the runtime and collects what it reported.
fn run(args: &[&str]) -> Output {
    Command::new(RUNTIME)
        .args(args)
        .output()
        .expect("running the runtime")
}

/// The output's standard error, as text.
fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// An option that takes a value must say so when it is given none.
///
/// Accepting the bare option and carrying on is worse than refusing: `update`
/// would then apply nothing and report success, so a caller adjusting a
/// container's limits would believe the new limits were in force.
#[test]
fn update_refuses_a_resources_option_with_no_value() {
    let output = run(&["update", "some-container", "--resources"]);
    assert!(
        !output.status.success(),
        "a value-taking option with no value must fail"
    );
    assert!(
        stderr(&output).contains("--resources needs a value"),
        "the failure should name the option, got: {}",
        stderr(&output)
    );
}

/// The same for the short spelling, which shares the code path.
#[test]
fn update_refuses_a_short_resources_option_with_no_value() {
    let output = run(&["update", "some-container", "-r"]);
    assert!(!output.status.success(), "the short spelling must fail too");
    assert!(
        stderr(&output).contains("needs a value"),
        "the failure should say a value is missing, got: {}",
        stderr(&output)
    );
}

/// A failure of `exec` is reported with the code callers reserve for it.
///
/// `exec` exits with the status of the process it ran, so its own failures
/// need a code no payload status can be confused with. Every other command
/// fails with the ordinary one, which a supervisor reads as a runtime
/// failure rather than as a payload that chose a high status.
#[test]
fn a_failing_command_exits_with_the_code_for_its_kind() {
    let argv = |words: &[&str]| -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    };

    assert_eq!(
        kot::failure_code(&argv(&["kot", "exec", "some-container", "/bin/sh"])),
        kot::EXEC_FAILURE
    );
    for command in [
        argv(&["kot", "state", "some-container"]),
        argv(&["kot", "delete", "some-container"]),
        argv(&["kot", "create", "some-container"]),
        argv(&["kot"]),
        argv(&["kot", "not-a-command"]),
    ] {
        assert_eq!(
            kot::failure_code(&command),
            kot::FAILURE,
            "{command:?} is not exec and fails with the ordinary code"
        );
    }
}

/// A long option may carry its value in the same word.
///
/// Both spellings are in use by the engines that drive a runtime, and a
/// runtime that takes only one of them is not a drop-in for the other. The
/// two forms have to reach exactly the same place, which is what comparing
/// the reports checks.
#[test]
fn a_long_option_may_carry_its_value_in_the_same_word() {
    let root = "/tmp/kot-no-such-state-root";
    let attached = run(&["--root=/tmp/kot-no-such-state-root", "state", "x"]);
    let separate = run(&["--root", root, "state", "x"]);

    assert_eq!(
        stderr(&attached),
        stderr(&separate),
        "the two spellings must be read the same way"
    );
    assert_eq!(attached.status.code(), separate.status.code());
    assert!(
        stderr(&attached).contains("does not exist"),
        "both should get past the option and fail on the container, got: {}",
        stderr(&attached)
    );
}

/// The same for an option of a command rather than a global one.
#[test]
fn a_command_option_may_carry_its_value_too() {
    let attached = run(&["exec", "--cwd=/tmp", "x", "/bin/true"]);
    let separate = run(&["exec", "--cwd", "/tmp", "x", "/bin/true"]);

    assert_eq!(stderr(&attached), stderr(&separate));
    assert!(
        !stderr(&attached).contains("unknown"),
        "the option should be recognised, got: {}",
        stderr(&attached)
    );
}

/// Checkpoint and restore have to say what is missing.
///
/// They are deliberately absent, and an operator who calls one is running an
/// engine or a bundle that needs it. Naming CRIU tells them which runtime to
/// go back to; a generic unknown-command error leaves them wondering whether
/// they mistyped.
#[test]
fn checkpoint_and_restore_name_what_they_need() {
    for command in ["checkpoint", "restore"] {
        let output = run(&[command, "some-container"]);
        assert!(!output.status.success(), "{command} must fail");
        assert!(
            stderr(&output).contains("CRIU"),
            "{command} should name CRIU, got: {}",
            stderr(&output)
        );
    }
}

/// The cache and bandwidth schema options reach the container.
///
/// They were refused while the allocation was unimplemented. Now that it is
/// implemented, a command line written for another runtime has to get past
/// the parser and fail on the container rather than on the flag.
#[test]
fn the_schema_options_are_accepted() {
    for flag in ["--l3-cache-schema", "--mem-bw-schema"] {
        let output = run(&["update", flag, "L3:0=f", "some-container"]);
        let message = stderr(&output);
        assert!(
            !message.contains("does not implement"),
            "{flag} is implemented now, got: {message}"
        );
        assert!(
            !message.contains("unknown resource"),
            "{flag} should be accepted, got: {message}"
        );
        assert!(
            message.contains("does not exist"),
            "{flag} should get as far as the container, got: {message}"
        );
    }
}

/// The resource options a caller expects reach the lowering.
///
/// Each of these was refused as an unknown resource before, so a command
/// line written for another runtime failed outright. Getting past the
/// parser to the container lookup is what says they are accepted.
#[test]
fn the_resource_options_are_accepted() {
    for (flag, value) in [
        ("--blkio-weight", "500"),
        ("--cpu-idle", "1"),
        ("--kernel-memory", "1048576"),
        ("--kernel-memory-tcp", "1048576"),
        ("--memory", "1048576"),
        ("--cpu-shares", "1024"),
    ] {
        let output = run(&["update", flag, value, "some-container"]);
        let message = stderr(&output);
        assert!(
            !message.contains("unknown resource"),
            "{flag} should be accepted, got: {message}"
        );
        assert!(
            message.contains("does not exist"),
            "{flag} should get as far as the container, got: {message}"
        );
    }
}

/// Every memory policy the report advertises has to be one a configuration
/// can actually use.
///
/// A caller reads this report to decide whether to send a configuration at
/// all. A mode listed here and refused by the parser is worse than one that
/// was never advertised: the caller builds a bundle around it and finds out
/// when the container fails to start.
#[test]
fn the_reported_memory_policies_are_the_ones_accepted() {
    use kot::oci::lower::tables;

    let output = run(&["features"]);
    assert!(output.status.success(), "features must report");
    let report = String::from_utf8_lossy(&output.stdout);

    // The names are the quoted words inside the two arrays, which is enough
    // structure to pull them out without a parser.
    let section = report
        .split_once("\"memoryPolicy\"")
        .map(|(_, rest)| rest)
        .expect("the report should carry a memoryPolicy section");
    let modes = section
        .split_once("\"modes\"")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(body, _)| body)
        .expect("modes");
    let flags = section
        .split_once("\"flags\"")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(body, _)| body)
        .expect("flags");

    let names = |body: &str| -> Vec<String> {
        body.split('"')
            .filter(|word| word.starts_with("MPOL"))
            .map(str::to_owned)
            .collect()
    };

    let modes = names(modes);
    assert!(!modes.is_empty(), "at least one mode should be reported");
    for mode in &modes {
        assert!(
            tables::mempolicy_mode(mode).is_some(),
            "the report offers {mode}, which a configuration cannot use"
        );
    }
    let flags = names(flags);
    assert!(!flags.is_empty(), "at least one flag should be reported");
    for flag in &flags {
        assert!(
            tables::mempolicy_flag(flag).is_some(),
            "the report offers {flag}, which a configuration cannot use"
        );
    }
}

/// A bundle may hold more than one configuration, named on the command line.
#[test]
fn a_named_configuration_is_read_instead_of_the_default() {
    let bundle =
        std::env::temp_dir().join(format!("kot-config-{}", std::process::id()));
    std::fs::create_dir_all(&bundle).expect("bundle");
    let path = bundle.to_string_lossy().into_owned();

    // Neither file exists, so the failure names whichever one was looked
    // for, which is what says the option was honoured.
    let default = run(&["create", "-b", &path, "some-container"]);
    assert!(
        stderr(&default).contains("config.json"),
        "the default should be config.json, got: {}",
        stderr(&default)
    );

    let named =
        run(&["create", "-b", &path, "--config", "other.json", "some-c"]);
    assert!(
        stderr(&named).contains("other.json"),
        "the named configuration should be read, got: {}",
        stderr(&named)
    );

    std::fs::remove_dir_all(&bundle).expect("cleaning up");
}

/// A word passed through to the container's own program keeps its shape.
///
/// The runtime splits `--name=value` for its own options. An argument meant
/// for the program a container runs, or for `ps`, is not the runtime's to
/// rewrite: handing that program two words where the caller wrote one
/// changes what it was asked to do.
#[test]
fn a_passed_through_argument_is_not_split() {
    let argv = |words: &[&str]| -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    };

    let line = argv(&["kot", "exec", "c", "/bin/ls", "--color=auto", "-l"]);
    let (_, command) = kot::cli::parse(&line).expect("parse");
    let kot::cli::Command::Exec(options) = command else {
        panic!("exec should parse as exec");
    };
    assert_eq!(options.id, "c");
    assert_eq!(
        options.args,
        vec!["/bin/ls", "--color=auto", "-l"],
        "the program's own arguments arrive as they were written"
    );

    // The runtime's own options are still split.
    let line = argv(&["kot", "exec", "--cwd=/tmp", "c", "/bin/ls"]);
    let (_, command) = kot::cli::parse(&line).expect("parse");
    let kot::cli::Command::Exec(options) = command else {
        panic!("exec should parse as exec");
    };
    assert_eq!(options.cwd.as_deref(), Some("/tmp"));
    assert_eq!(options.args, vec!["/bin/ls"]);

    // And a passthrough argument to `ps` keeps its shape too.
    let line = argv(&["kot", "ps", "c", "--sort=-pid"]);
    let (_, command) = kot::cli::parse(&line).expect("parse");
    let kot::cli::Command::Ps { args, .. } = command else {
        panic!("ps should parse as ps");
    };
    assert_eq!(args, vec!["--sort=-pid"]);
}
