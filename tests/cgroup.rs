//! Where a container's limits and device rules are written.
//!
//! The two hierarchies keep their controllers in different places, and a
//! manager that reaches for the wrong one applies nothing at all while
//! reporting success, which is the failure these guard against.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use kot::cgroup::{
    Kind, Layout, Manager,
    devices::{self, Form},
};

/// Device rules follow the controllers, not the unified node.
///
/// A hybrid host has both trees, but its controllers live in the legacy one,
/// so a device program attached to its unified node would constrain nothing
/// and the rules have to be written as text instead.
#[test]
fn a_hybrid_host_writes_legacy_device_rules() {
    assert_eq!(devices::form(Layout::Unified), Form::Program);
    assert_eq!(devices::form(Layout::Legacy), Form::Rules);
    assert_eq!(devices::form(Layout::Hybrid), Form::Rules);
}

/// A created cgroup has somewhere to write device rules.
///
/// On the legacy hierarchy the container's directory is not the one the
/// device rules go in: each controller has its own tree, and only the
/// controller lookup finds the right one. A manager that answered `None` here
/// would skip every device rule the configuration asked for.
#[test]
fn a_created_cgroup_has_a_device_directory() {
    if !rustix::process::geteuid().is_root() {
        println!("skipping: making a cgroup needs root");
        return;
    }
    let id = format!("kot-device-directory-{}", std::process::id());
    let mut manager = Manager::new(Kind::Cgroupfs, None, &id).expect("manager");
    manager.begin_create(0, None).expect("create the cgroup");
    manager.wait_ready().expect("wait for the cgroup");

    assert!(
        manager.place("devices").is_some(),
        "a created cgroup must name a directory for its device rules"
    );

    manager.destroy().expect("remove the cgroup");
}

/// A command naming a container that has gone must not wait for its cgroup.
///
/// Waiting for a scope to appear is right while one has been asked for and
/// wrong afterwards. A manager rebuilt from a state record is answering for a
/// container somebody else created, and once that container has gone the
/// directory never comes back, so the wait ran to its deadline. Every
/// `state`, `kill` and `delete` of a stopped container paid a full second for
/// it, which is longer than starting the container took.
#[test]
fn a_manager_that_asked_for_nothing_does_not_wait() {
    use std::time::{Duration, Instant};

    let id = format!("gone-{}", std::process::id());
    let Ok(mut manager) = Manager::new(Kind::Systemd, None, &id) else {
        println!("skipping: no cgroup hierarchy to detect");
        return;
    };

    // Nothing was ever requested through this manager, so nothing is on its
    // way and there is nothing to wait for.
    let start = Instant::now();
    let outcome = manager.wait_ready();
    let took = start.elapsed();

    assert!(
        outcome.is_ok(),
        "answering about a missing cgroup is not an error: {outcome:?}"
    );
    assert!(
        took < Duration::from_millis(200),
        "waited {took:?} for a cgroup nobody asked for"
    );
}
