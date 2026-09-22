//! What a configuration has to say before any of it is applied.
//!
//! These drive the checker directly rather than the binary. A configuration
//! that would restructure the caller's own filesystem is exactly the one that
//! must never reach a real container to be tested, so the refusal is asserted
//! where no container is built.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use bumpalo::Bump;
use kot::{oci::parse, validate};

/// Builds a configuration whose `linux` section is the given text.
fn config(linux: &str) -> String {
    format!(
        r#"{{
        "ociVersion": "1.0.0",
        "process": {{"args": ["/true"], "cwd": "/"}},
        "root": {{"path": "rootfs"}},
        "linux": {linux}
    }}"#
    )
}

/// Checks one configuration, returning the failure text when it is refused.
fn check(text: &str) -> Result<(), String> {
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    validate::spec(&spec).map_err(|e| format!("{e:#}"))
}

/// A configuration with no mount namespace has to be refused.
///
/// The runtime installs the configured mounts and then changes the root, both
/// in whatever mount namespace it was handed. With no private one that is the
/// caller's: the container's filesystem is assembled on the host and the old
/// root is detached out from under processes that are not in any container.
/// Refusing is the only outcome that leaves the caller's namespace as it was.
#[test]
fn a_configuration_without_a_mount_namespace_is_refused() {
    let text = config(r#"{"namespaces": [{"type": "pid"}, {"type": "uts"}]}"#);
    let failure = check(&text).expect_err("this must not be accepted");
    assert!(
        failure.contains("mount namespace"),
        "the failure should name what is missing, got: {failure}"
    );
}

/// The same refusal when the configuration has no `linux` section at all.
#[test]
fn a_configuration_with_no_linux_section_is_refused() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "process": {"args": ["/true"], "cwd": "/"},
        "root": {"path": "rootfs"}
    }"#;
    let failure = check(text).expect_err("this must not be accepted");
    assert!(
        failure.contains("mount namespace"),
        "the failure should name what is missing, got: {failure}"
    );
}

/// A configuration that asks for a mount namespace is accepted.
///
/// Without this the check above would pass just as well for a runtime that
/// refuses everything.
#[test]
fn a_configuration_with_a_mount_namespace_is_accepted() {
    let text = config(r#"{"namespaces": [{"type": "mount"}]}"#);
    check(&text).expect("a private mount namespace is what the check wants");
}

/// Joining an existing mount namespace is accepted too.
///
/// A configuration that names a namespace to enter has said where the mounts
/// belong. The check is for the case where nobody said anything, not for
/// private namespaces only.
#[test]
fn joining_a_mount_namespace_is_accepted() {
    let text = config(
        r#"{"namespaces": [{"type": "mount", "path": "/proc/1/ns/mnt"}]}"#,
    );
    check(&text).expect("a joined mount namespace is still a mount namespace");
}

/// Naming the container with no UTS namespace to name would rename the host.
///
/// `sethostname` acts on the UTS namespace the caller is in. Without a
/// private one the container's requested name becomes the host's, for every
/// process on it.
#[test]
fn a_hostname_without_a_uts_namespace_is_refused() {
    for field in ["hostname", "domainname"] {
        let text = format!(
            r#"{{
            "ociVersion": "1.0.0",
            "process": {{"args": ["/true"], "cwd": "/"}},
            "root": {{"path": "rootfs"}},
            "{field}": "named",
            "linux": {{"namespaces": [{{"type": "mount"}}]}}
        }}"#
        );
        let failure = check(&text).expect_err("this must not be accepted");
        assert!(
            failure.contains("UTS namespace"),
            "the failure should name what is missing, got: {failure}"
        );
    }
}

/// With a UTS namespace the name is the container's own, and accepted.
#[test]
fn a_hostname_with_a_uts_namespace_is_accepted() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "process": {"args": ["/true"], "cwd": "/"},
        "root": {"path": "rootfs"},
        "hostname": "named",
        "domainname": "example",
        "linux": {"namespaces": [{"type": "mount"}, {"type": "uts"}]}
    }"#;
    check(text).expect("a private UTS namespace is what the check wants");
}

/// A configuration that names nothing needs no UTS namespace.
#[test]
fn no_name_needs_no_uts_namespace() {
    let text = config(r#"{"namespaces": [{"type": "mount"}]}"#);
    check(&text).expect("nothing was named, so nothing would be renamed");
}

/// Clock offsets need a time namespace this container owns.
///
/// They are written while the namespace holds one process and no others, so
/// a namespace joined by path is already too late, and without one at all
/// there is nothing to offset.
#[test]
fn clock_offsets_need_a_time_namespace() {
    let offsets = r#""timeOffsets": {"monotonic": {"secs": 60}}"#;
    let without = config(&format!(
        r#"{{"namespaces": [{{"type": "mount"}}], {offsets}}}"#
    ));
    let failure = check(&without).expect_err("nowhere to apply the offsets");
    assert!(
        failure.contains("time namespace"),
        "the failure should name what is missing, got: {failure}"
    );

    let joined = config(&format!(
        r#"{{"namespaces": [
            {{"type": "mount"}},
            {{"type": "time", "path": "/proc/1/ns/time"}}
        ], {offsets}}}"#
    ));
    assert!(
        check(&joined).is_err(),
        "a namespace somebody else owns already has processes in it"
    );

    let created = config(&format!(
        r#"{{"namespaces": [{{"type": "mount"}}, {{"type": "time"}}],
            {offsets}}}"#
    ));
    check(&created).expect("a time namespace of its own is what is needed");
}

/// Only the two clocks the kernel offsets may be named.
#[test]
fn an_unknown_clock_is_refused() {
    let text = config(
        r#"{"namespaces": [{"type": "mount"}, {"type": "time"}],
            "timeOffsets": {"realtime": {"secs": 60}}}"#,
    );
    let failure = check(&text).expect_err("realtime cannot be offset");
    assert!(
        failure.contains("realtime"),
        "the failure should name the clock, got: {failure}"
    );
}

/// A section this build does not implement is refused, not ignored.
///
/// The report says these are unavailable. A configuration that asks for one
/// anyway would otherwise start a container without the interface it was
/// meant to be given, and the payload would use the host's instead.
#[test]
fn an_unimplemented_section_is_refused() {
    let text = config(
        r#"{"namespaces": [{"type": "mount"}],
            "netDevices": {"eth0": {"name": "eth1"}}}"#,
    );
    let failure = check(&text).expect_err("this must not be accepted");
    assert!(
        failure.contains("netDevices"),
        "the failure should name the section, got: {failure}"
    );
}

/// The cache allocation a configuration states is the one written.
///
/// Whole schema lines and the two named fields are two ways of saying the
/// same thing, and a configuration that uses both means the lines: they are
/// the general form, and a caller that wrote them wrote them deliberately.
#[test]
fn a_cache_allocation_renders_the_lines_it_was_given() {
    use kot::{oci::spec::IntelRdt, rdt};

    let mut out = String::new();

    let named = IntelRdt {
        l3_cache_schema: Some("L3:0=f;1=f"),
        mem_bw_schema: Some("MB:0=20;1=20"),
        ..IntelRdt::default()
    };
    rdt::schemata(&named, &mut out);
    assert_eq!(out, "L3:0=f;1=f\nMB:0=20;1=20\n");

    let both = IntelRdt {
        schemata: vec!["L3:0=ff"],
        l3_cache_schema: Some("L3:0=f"),
        ..IntelRdt::default()
    };
    rdt::schemata(&both, &mut out);
    assert_eq!(out, "L3:0=ff\n", "the lines win over the named fields");

    // A class with no allocation is legitimate: the point was the grouping.
    rdt::schemata(&IntelRdt::default(), &mut out);
    assert!(out.is_empty());
}

/// A container joins the class it names, or one of its own.
#[test]
fn a_container_without_a_named_class_gets_its_own() {
    use kot::{oci::spec::IntelRdt, rdt};

    let named = IntelRdt {
        clos_id: Some("shared"),
        ..IntelRdt::default()
    };
    assert_eq!(rdt::class_of(&named, "abc"), "shared");

    // Blank counts as unnamed: an empty directory name is not a class.
    let blank = IntelRdt {
        clos_id: Some("  "),
        ..IntelRdt::default()
    };
    assert_eq!(rdt::class_of(&blank, "abc"), "abc");
    assert_eq!(rdt::class_of(&IntelRdt::default(), "abc"), "abc");
}
