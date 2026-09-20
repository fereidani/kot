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
