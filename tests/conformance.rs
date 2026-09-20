//! What the OCI Runtime Specification requires of this runtime.
//!
//! Each test here names the requirement it holds the runtime to, so that a
//! change which drifts from the specification fails with the sentence it broke
//! instead of with a diff. The specification text quoted in the comments is
//! from version 1.3.0, which is the version this build reports as the newest
//! it implements.
//!
//! These drive the binary, never the library, because conformance lives in
//! what a caller observes: the exit status, the state document, and what the
//! container process actually sees.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::items_after_statements,
    dead_code
)]

mod bundle;

use bundle::{Bundle, expect_ok, stderr};

/// True when this process can create containers.
fn privileged() -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    println!("skipping: creating containers needs root");
    false
}

/// A failure to apply the configuration has to fail the create operation.
///
/// "If the runtime cannot apply a property as specified in the configuration,
/// it MUST generate an error and a new container MUST NOT be created."
///
/// The process settings are applied after the container's filesystem exists,
/// so a runtime that stops listening once the filesystem is ready reports
/// success for a container whose process could never start. The caller then
/// finds a container that is already stopped, and the reason is gone.
#[test]
fn create_fails_when_the_process_cannot_be_configured() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("conf-payload", &["/usr/bin/definitely-not-here"]);
    let id = bundle.id();
    let output = bundle.runtime(&["create", &id]);
    assert!(
        !output.status.success(),
        "create must fail when the payload cannot be opened"
    );
    assert!(
        stderr(&output).contains("no such file"),
        "the failure should say what could not be applied, got: {}",
        stderr(&output)
    );

    // "a new container MUST NOT be created": nothing may be left to query.
    let state = bundle.runtime(&["state", &id]);
    assert!(
        !state.status.success(),
        "a failed create must leave no container behind, got: {}",
        String::from_utf8_lossy(&state.stdout)
    );
}

/// The same failure reported through `run`, which creates and starts at once.
#[test]
fn run_fails_when_the_payload_is_absent() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("conf-run", &["/usr/bin/definitely-not-here"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    assert!(!output.status.success(), "run must fail");
}

/// A container that can be built still is.
///
/// The check above is only meaningful if the handshake it rests on does not
/// stop an ordinary container from starting.
#[test]
fn a_container_that_can_be_built_still_starts() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("conf-ok", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    expect_ok("kill", &bundle.runtime(&["kill", &id, "KILL"]));
}

/// A create that fails leaves nothing of the container behind.
///
/// "Generating an error MUST leave the state of the environment as if the
/// operation were never attempted."
///
/// The cgroup is made before the container's filesystem is built, so a
/// failure after that point used to leave an empty cgroup directory on the
/// host for every container that could not start.
#[test]
fn a_failed_create_leaves_no_cgroup_behind() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "conf-leak",
        &["/usr/bin/true"],
        |config| {
            // A filesystem type the kernel does not have cannot be mounted,
            // which fails the create while the cgroup already exists.
            *config = config.replace(
                r#"{ "destination": "/proc", "type": "proc", "source": "proc" }"#,
                r#"{ "destination": "/proc", "type": "proc", "source": "proc" },
    { "destination": "/nope", "type": "nosuchfstype", "source": "x" }"#,
            );
        },
    );
    let id = bundle.id();
    let output = bundle.runtime(&["create", &id]);
    assert!(
        !output.status.success(),
        "a mount the kernel cannot make must fail the create"
    );
    let cgroup = std::path::Path::new("/sys/fs/cgroup/kot").join(&id);
    assert!(
        !cgroup.exists(),
        "a failed create must not leave {} behind",
        cgroup.display()
    );
}

/// An out-of-memory score adjustment has to reach the container's process.
///
/// "If `oomScoreAdj` is set, the runtime MUST set `oom_score_adj` to the
/// given value. If `oomScoreAdj` is not set, the runtime MUST NOT change the
/// value of `oom_score_adj`."
#[test]
fn the_oom_score_adjustment_is_applied() {
    if !privileged() {
        return;
    }
    const ASKED: i32 = 555;
    let bundle = Bundle::with_config(
        "conf-oom",
        &["/usr/bin/sh", "-c", "cat /proc/self/oom_score_adj"],
        |config| {
            *config = config.replace(
                r#""noNewPrivileges": true"#,
                &format!(r#""noNewPrivileges": true, "oomScoreAdj": {ASKED}"#),
            );
        },
    );
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        ASKED.to_string(),
        "the container process should carry the adjustment it asked for"
    );

    // A configuration that says nothing about it leaves it alone.
    let plain = Bundle::new(
        "conf-oom-absent",
        &["/usr/bin/sh", "-c", "cat /proc/self/oom_score_adj"],
    );
    let output = plain.runtime(&["run", &plain.id()]);
    expect_ok("run", &output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "0",
        "an unstated adjustment must not be changed"
    );
}

/// The two hooks that belong inside the container have to run there.
///
/// "The `createContainer` hooks MUST be called ... before the `pivot_root` or
/// any equivalent operation has been executed. The `createContainer` hooks'
/// path MUST resolve in the runtime namespace. The `createContainer` hooks
/// MUST be executed in the container namespace."
///
/// "The `startContainer` hooks MUST be called before the user-specified
/// process is executed ... The `startContainer` hooks' path MUST resolve in
/// the container namespace."
#[test]
fn the_container_hooks_run_inside_the_container() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new(
        "conf-hooks",
        &["/usr/bin/sh", "-c", "echo payload >> /tmp/order.txt"],
    );
    let root = bundle.path().to_path_buf();
    std::fs::create_dir_all(root.join("rootfs/tmp")).expect("a place to write");

    // Resolved on the host, so it is written beside the bundle, and it
    // records which mount namespace it was run in.
    let outside = root.join("createContainer.txt");
    std::fs::write(
        root.join("hook.sh"),
        format!(
            "#!/bin/sh\nreadlink /proc/self/ns/mnt > {}\n",
            outside.display()
        ),
    )
    .expect("host hook");
    // Resolved inside the container, so it is written in the rootfs.
    std::fs::write(
        root.join("rootfs/hook.sh"),
        "#!/usr/bin/sh\necho startContainer >> /tmp/order.txt\n",
    )
    .expect("container hook");
    for hook in ["hook.sh", "rootfs/hook.sh"] {
        let path = root.join(hook);
        let mut mode = std::fs::metadata(&path).expect("hook").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        std::fs::set_permissions(&path, mode).expect("hook is executable");
    }

    let config = root.join("config.json");
    let text = std::fs::read_to_string(&config).expect("config");
    let hooks = format!(
        r#""hooks": {{
    "createContainer": [{{ "path": "{}/hook.sh" }}],
    "startContainer": [{{ "path": "/hook.sh" }}]
  }},
  "linux": {{"#,
        root.display()
    );
    std::fs::write(&config, text.replacen(r#""linux": {"#, &hooks, 1))
        .expect("config with hooks");

    expect_ok("run", &bundle.runtime(&["run", &bundle.id()]));

    // The hook ran in a mount namespace that is not this process's, which is
    // what "in the container namespace" means here.
    let seen = std::fs::read_to_string(&outside)
        .expect("the createContainer hook did not run");
    let ours = std::fs::read_link("/proc/self/ns/mnt").expect("our own");
    assert_ne!(
        seen.trim(),
        ours.display().to_string(),
        "the createContainer hook must run in the container's namespaces"
    );

    // The startContainer hook ran inside the container, before the payload.
    let order = std::fs::read_to_string(root.join("rootfs/tmp/order.txt"))
        .expect("the startContainer hook did not run");
    let lines: Vec<&str> = order.split_whitespace().collect();
    assert_eq!(
        lines,
        vec!["startContainer", "payload"],
        "the hook must run before the payload it prepares for"
    );
}

/// The working directory has to be one the container can change to.
///
/// "**`cwd`** (string, REQUIRED) is the working directory that will be set
/// for the executable. This value MUST be an absolute path."
#[test]
fn a_relative_working_directory_is_refused() {
    let output = refuse("conf-cwd", |c| {
        *c = c.replace(r#""cwd": "/""#, r#""cwd": "relative/path""#);
    });
    assert!(
        stderr(&output).contains("absolute"),
        "the failure should say what is wrong with it, got: {}",
        stderr(&output)
    );
}

/// There has to be a program to run.
///
/// "This specification extends the IEEE standard in that at least one entry
/// is REQUIRED (non-Windows), and that entry is used with the same semantics
/// as `execvp`'s *file*."
#[test]
fn an_empty_argument_list_is_refused() {
    let output = refuse("conf-args", |c| {
        let at = c.find(r#""args": ["#).expect("args");
        let end = c[at..].find(']').expect("args end") + at;
        c.replace_range(at..=end, r#""args": []"#);
    });
    assert!(
        stderr(&output).contains("args"),
        "the failure should name the field, got: {}",
        stderr(&output)
    );
}

/// One limit of a kind, or the last one silently decides it.
///
/// "If `rlimits` contains duplicated entries with same `type`, the runtime
/// MUST generate an error."
#[test]
fn duplicate_resource_limits_are_refused() {
    let output = refuse("conf-rlimit", |c| {
        *c = c.replace(
            r#""rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 }]"#,
            r#""rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 },
                 { "type": "RLIMIT_NOFILE", "hard": 8192, "soft": 8192 }]"#,
        );
    });
    assert!(
        stderr(&output).contains("RLIMIT_NOFILE"),
        "the failure should name the limit, got: {}",
        stderr(&output)
    );
}

/// An annotation has to be named.
///
/// "Keys MUST be strings. Keys MUST NOT be an empty string."
#[test]
fn an_empty_annotation_key_is_refused() {
    let output = refuse("conf-annotation", |c| {
        *c = c.replace(
            r#""annotations": {"#,
            r#""annotations": { "": "nameless","#,
        );
    });
    assert!(
        stderr(&output).contains("annotation"),
        "the failure should name the field, got: {}",
        stderr(&output)
    );
}

/// Builds a bundle the given way and returns what `create` reported, having
/// first insisted that it failed.
fn refuse(
    name: &str,
    adjust: impl FnOnce(&mut String),
) -> std::process::Output {
    let bundle = Bundle::with_config(name, &["/usr/bin/true"], adjust);
    let output = bundle.runtime(&["create", &bundle.id()]);
    assert!(
        !output.status.success(),
        "{name}: the configuration must be refused"
    );
    output
}

/// What the features report names, the runtime has to recognise, and what it
/// recognises it should name.
///
/// "**`mountOptions`** (array of strings, OPTIONAL) The recognized names of
/// the mount options ... The runtime MUST recognize the elements in this
/// array as the `options` of `mounts` objects in `config.json`."
///
/// A caller chooses what to ask for from this list, so an option left out of
/// it is one the runtime is told nobody can use.
#[test]
fn the_features_report_names_every_mount_option() {
    let output = std::process::Command::new(bundle::RUNTIME)
        .arg("features")
        .output()
        .expect("running the runtime");
    let report = String::from_utf8_lossy(&output.stdout);
    let options: Vec<&str> = report
        .split("\"mountOptions\"")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .map(|list| {
            list.split('"')
                .filter(|part| {
                    part.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
                    }) && !part.is_empty()
                })
                .collect()
        })
        .expect("the report should list mount options");

    // Every option the specification requires a Linux runtime to implement.
    for required in [
        "async",
        "atime",
        "bind",
        "defaults",
        "dev",
        "diratime",
        "dirsync",
        "exec",
        "iversion",
        "lazytime",
        "loud",
        "noatime",
        "nodev",
        "nodiratime",
        "noexec",
        "noiversion",
        "nolazytime",
        "norelatime",
        "nostrictatime",
        "nosuid",
        "private",
        "rbind",
        "relatime",
        "remount",
        "ro",
        "rprivate",
        "rshared",
        "rslave",
        "runbindable",
        "rw",
        "shared",
        "silent",
        "slave",
        "strictatime",
        "suid",
        "sync",
        "unbindable",
    ] {
        assert!(
            options.contains(&required),
            "the report should name {required}, which the runtime implements"
        );
    }
}
