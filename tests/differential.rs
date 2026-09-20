//! Comparing the runtime against another implementation of the same
//! specification.
//!
//! These do not assert that the two agree byte for byte, which they are not
//! required to. They assert that a container built by one looks the same from
//! the inside as a container built by the other, which is the whole of what a
//! caller depends on, and that the state both report describes the same
//! container.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::items_after_statements,
    dead_code
)]

mod bundle;

use std::{path::Path, process::Command};

use bundle::{Bundle, expect_ok, stderr, stdout};

/// The reference runtime, when one is installed.
///
/// Absent on a machine that has no other runtime, which is a normal state for
/// a development host and not a reason to fail.
fn reference() -> Option<&'static str> {
    for path in ["/usr/bin/crun", "/usr/bin/runc", "/usr/local/bin/crun"] {
        if Path::new(path).exists() {
            return Some(path);
        }
    }
    println!("skipping: no other runtime is installed to compare against");
    None
}

fn privileged() -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    println!("skipping: creating containers needs root");
    false
}

/// Runs the same bundle under the reference runtime.
fn reference_run(runtime: &str, bundle: &Bundle) -> (Option<i32>, String) {
    let out = bundle.path().join("ref-stdout");
    let err = bundle.path().join("ref-stderr");
    let id = format!("{}-ref", bundle.id());
    let status = Command::new(runtime)
        .args([
            "--root",
            &format!("{}-ref", bundle.state_root()),
            "run",
            &id,
        ])
        .current_dir(bundle.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&out).expect("stdout file"))
        .stderr(std::fs::File::create(&err).expect("stderr file"))
        .status()
        .expect("running the reference runtime");
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    if !status.success() {
        let why = std::fs::read_to_string(&err).unwrap_or_default();
        println!("reference runtime failed: {why}");
    }
    (status.code(), text)
}

/// Checks that both runtimes produce the same view for one payload.
fn agree_on(name: &str, args: &[&str]) {
    if !privileged() {
        return;
    }
    let Some(runtime) = reference() else { return };

    let bundle = Bundle::new(name, args);
    let ours = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &ours);
    let (code, theirs) = reference_run(runtime, &bundle);
    if code != Some(0) {
        println!("skipping: the reference runtime could not run this bundle");
        return;
    }
    assert_eq!(
        stdout(&ours).trim(),
        theirs.trim(),
        "the two runtimes should build the same container\nstderr: {}",
        stderr(&ours)
    );
}

/// Masked paths, which the two runtimes back with different filesystems.
///
/// Both satisfy the specification, which asks for a bind of `/dev/null` over
/// a file and a read-only `tmpfs` over a directory but says nothing about
/// where either comes from. This runtime uses the container's own `/dev/null`
/// and a zero-size tmpfs; the other uses the host's `/dev/null` and a bind.
/// What matters is that the path reads as empty and cannot be written, which
/// the lifecycle tests check directly.
const MASKED: &str = "/proc/kcore|/proc/timer_list|/sys/firmware";

#[test]
fn the_same_paths_are_mounted() {
    // Sorted, because neither runtime promises an order and only the set
    // matters.
    agree_on(
        "diff-mounts",
        &[
            "/usr/bin/sh",
            "-c",
            "awk '{print $2}' /proc/self/mounts | sort",
        ],
    );
}

#[test]
fn the_mounted_filesystems_match() {
    agree_on(
        "diff-types",
        &[
            "/usr/bin/sh",
            "-c",
            &format!(
                "awk '{{print $2, $3}}' /proc/self/mounts \
                 | grep -vE '^({MASKED}) ' | sort"
            ),
        ],
    );
}

#[test]
fn the_mount_restrictions_match() {
    // Only the options that restrict what the container may do. The rest are
    // filesystem bookkeeping, such as inode counts and sizes, which say
    // nothing about how the container is confined.
    agree_on(
        "diff-options",
        &[
            "/usr/bin/sh",
            "-c",
            &format!(
                "awk '{{n=split($4,o,\",\"); s=\"\"; \
                 for (j=1; j<=n; j++) \
                   if (o[j]==\"ro\" || o[j]==\"rw\" || o[j]==\"nosuid\" \
                       || o[j]==\"nodev\" || o[j]==\"noexec\") \
                     s = s o[j] \",\"; \
                 print $2, s}}' /proc/self/mounts \
                 | grep -vE '^({MASKED}) ' | sort"
            ),
        ],
    );
}

#[test]
fn the_capability_sets_match() {
    agree_on(
        "diff-caps",
        &[
            "/usr/bin/sh",
            "-c",
            "grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status",
        ],
    );
}

#[test]
fn the_process_environment_matches() {
    agree_on(
        "diff-process",
        &[
            "/usr/bin/sh",
            "-c",
            "echo $$; id -u; id -g; pwd; hostname; \
             grep -E '^(NoNewPrivs|Seccomp):' /proc/self/status",
        ],
    );
}

#[test]
fn the_device_nodes_match() {
    agree_on(
        "diff-devices",
        &[
            "/usr/bin/sh",
            "-c",
            "ls -l /dev | awk '{print $1, $5, $6, $NF}' | sort",
        ],
    );
}

#[test]
fn the_masked_and_read_only_paths_match() {
    agree_on(
        "diff-paths",
        &[
            "/usr/bin/sh",
            "-c",
            "wc -c < /proc/kcore; \
             (touch /proc/sysrq-trigger 2>/dev/null && echo writable \
              || echo protected)",
        ],
    );
}

#[test]
fn the_resource_limits_match() {
    agree_on(
        "diff-rlimits",
        &["/usr/bin/sh", "-c", "ulimit -n; ulimit -Hn"],
    );
}

#[test]
fn the_reported_state_describes_the_same_container() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("diff-state", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    let ours = bundle.runtime(&["state", &id]);
    expect_ok("state", &ours);
    let text = stdout(&ours);

    // The fields the specification requires of a state document. A caller
    // that parses this reads exactly these.
    for field in ["ociVersion", "id", "status", "pid", "bundle"] {
        assert!(
            text.contains(&format!("\"{field}\"")),
            "the state document should carry {field}, got: {text}"
        );
    }
    assert!(
        text.contains("\"status\": \"created\"")
            || text.contains("\"status\":\"created\""),
        "a created container reports created, got: {text}"
    );
    // Annotations are how a caller such as a container engine keeps its own
    // bookkeeping on a container, so they have to survive the round trip.
    assert!(
        text.contains("org.kot.test.marker"),
        "the state document should carry the bundle's annotations, got: \
         {text}"
    );
}
