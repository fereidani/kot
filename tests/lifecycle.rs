//! The container lifecycle, driven through the runtime binary.
//!
//! Every test here runs a real container: namespaces are created, a root
//! filesystem is assembled, a cgroup is made and a payload is executed. They
//! need privileges, so each one asks first and skips with an explanation
//! when it does not have them.

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

use std::{thread::sleep, time::Duration};

use bundle::{Bundle, expect_ok, stderr, stdout};

/// True when this process can create containers.
///
/// Namespaces, mounts and cgroups all need privilege; without it the tests
/// below would fail for a reason that has nothing to do with the runtime.
fn privileged() -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    println!("skipping: creating containers needs root");
    false
}

/// Reads a container's state as parsed fields.
///
/// The state document is the runtime's contract with its caller, so the tests
/// read it the way a caller would rather than reaching into the state
/// directory.
fn state(bundle: &Bundle) -> Option<(String, String, i64)> {
    let output = bundle.runtime(&["state", &bundle.id()]);
    if !output.status.success() {
        return None;
    }
    let text = stdout(&output);
    let field = |name: &str| -> Option<String> {
        let key = format!("\"{name}\"");
        let start = text.find(&key)? + key.len();
        let rest = text.get(start..)?.trim_start().strip_prefix(':')?;
        let rest = rest.trim_start();
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"')?;
            return quoted.get(..end).map(ToOwned::to_owned);
        }
        let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
        rest.get(..end).map(|v| v.trim().to_owned())
    };
    Some((field("id")?, field("status")?, field("pid")?.parse().ok()?))
}

/// Waits for a container to reach a status, or gives up.
///
/// Bounded by a fixed number of polls: a container that has not reached the
/// status by then is a failure, not a slow machine.
fn wait_for_status(bundle: &Bundle, want: &str) -> bool {
    for _ in 0..200u32 {
        if let Some((_, status, _)) = state(bundle) {
            if status == want {
                return true;
            }
        }
        sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn run_reports_the_payload_exit_status() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("run-status", &["/usr/bin/sh", "-c", "exit 7"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "the runtime should exit with the payload's status\nstderr: {}",
        stderr(&output)
    );
}

#[test]
fn run_passes_output_through() {
    if !privileged() {
        return;
    }
    let bundle =
        Bundle::new("run-output", &["/usr/bin/echo", "hello from inside"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "hello from inside");
}

#[test]
fn the_payload_sees_the_container_it_was_given() {
    if !privileged() {
        return;
    }
    // One payload covering several guarantees at once, because each of these
    // needs a whole container to observe and they do not interact.
    let script = "echo pid=$$; echo host=$(cat /proc/sys/kernel/hostname); \
                  echo root=$(ls /proc/1 >/dev/null 2>&1 && echo yes)";
    let bundle = Bundle::new("payload-view", &["/usr/bin/sh", "-c", script]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    let text = stdout(&output);

    // A fresh pid namespace makes the payload process number one.
    assert!(text.contains("pid=1"), "expected pid 1, got: {text}");
    // The uts namespace carries the hostname from the configuration.
    assert!(
        text.contains("host=kot-test"),
        "expected the configured hostname, got: {text}"
    );
    // A private proc was mounted, rather than the host's showing through.
    assert!(text.contains("root=yes"), "expected /proc, got: {text}");
}

#[test]
fn create_start_and_delete_move_through_the_states() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("states", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();

    expect_ok("create", &bundle.runtime(&["create", &id]));
    let Some((reported, status, pid)) = state(&bundle) else {
        panic!("state should be readable after create");
    };
    assert_eq!(reported, id);
    assert_eq!(status, "created", "a created container waits to be started");
    assert!(pid > 1, "the state should name the container's process");

    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(
        wait_for_status(&bundle, "running"),
        "the container should be running once started"
    );

    expect_ok("kill", &bundle.runtime(&["kill", &id, "KILL"]));
    assert!(
        wait_for_status(&bundle, "stopped"),
        "the container should stop once killed"
    );

    expect_ok("delete", &bundle.runtime(&["delete", &id]));
    assert!(
        state(&bundle).is_none(),
        "a deleted container should no longer have state"
    );
}

#[test]
fn a_container_must_be_created_before_it_is_started() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("start-missing", &["/usr/bin/true"]);
    let output = bundle.runtime(&["start", &bundle.id()]);
    assert!(!output.status.success(), "starting nothing should fail");
    assert!(
        stderr(&output).contains("does not exist"),
        "the error should say what is missing, got: {}",
        stderr(&output)
    );
}

#[test]
fn a_running_container_cannot_be_deleted_without_force() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("delete-guard", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let refused = bundle.runtime(&["delete", &id]);
    assert!(
        !refused.status.success(),
        "deleting a running container should be refused"
    );

    expect_ok(
        "forced delete",
        &bundle.runtime(&["delete", "--force", &id]),
    );
    assert!(state(&bundle).is_none());
}

#[test]
fn exec_joins_the_running_container() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("exec", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let output = bundle.runtime(&[
        "exec",
        &id,
        "/usr/bin/sh",
        "-c",
        "echo host=$(cat /proc/sys/kernel/hostname); echo self=$$",
    ]);
    expect_ok("exec", &output);
    let text = stdout(&output);

    // The same uts namespace as the container, so this is not the host.
    assert!(
        text.contains("host=kot-test"),
        "exec should join the container's namespaces, got: {text}"
    );
    // Joining an existing pid namespace means a small number that is not one:
    // the payload is process one and this is the next one along. A host
    // process id would be far larger, and would mean `exec` had run beside the
    // container rather than inside it.
    let self_pid: u32 = text
        .lines()
        .find_map(|line| line.strip_prefix("self="))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("exec should report its pid, got: {text}"));
    assert!(
        self_pid > 1 && self_pid < 1000,
        "exec should be in the container's pid namespace, got {self_pid}"
    );
}

#[test]
fn exec_reports_the_command_exit_status() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("exec-status", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let output = bundle.runtime(&["exec", &id, "/usr/bin/sh", "-c", "exit 13"]);
    assert_eq!(output.status.code(), Some(13));
}

/// A process that cannot be put in the container's cgroup must not run.
///
/// Reporting success for a process that escaped every limit the container
/// has is worse than refusing: the caller believes the limits apply.
#[test]
fn exec_refuses_when_the_cgroup_placement_fails() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("exec-cgroup", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    // A sub-cgroup below one that does not exist cannot be made, which is the
    // simplest placement failure to ask for.
    let output = bundle.runtime(&[
        "exec",
        "--cgroup",
        "absent/deeper",
        &id,
        "/usr/bin/true",
    ]);
    assert!(
        !output.status.success(),
        "exec must fail when the placement fails, got {:?} and {}",
        output.status.code(),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("cgroup"),
        "the failure should name the cgroup, got: {}",
        stderr(&output)
    );
}

/// A filter that hands syscalls to a supervisor needs a supervisor.
///
/// `SCMP_ACT_NOTIFY` without `listenerPath` installs a filter nothing is
/// listening to, and the kernel then fails every syscall the rule covers with
/// `ENOSYS`. Refusing the configuration says what is wrong; starting the
/// container leaves the caller with a container whose syscalls vanish.
#[test]
fn a_notify_filter_needs_a_listener_path() {
    if !privileged() {
        return;
    }
    // Every spelling the filter compiler accepts, since it takes the name
    // with or without its prefix and in any case.
    for (name, action) in [
        ("plain", "SCMP_ACT_NOTIFY"),
        ("lower", "notify"),
        ("bare", "NOTIFY"),
    ] {
        let bundle = Bundle::with_config(
            &format!("notify-no-listener-{name}"),
            &["/usr/bin/true"],
            |config| {
                let profile = format!(
                    r#""seccomp": {{
      "defaultAction": "SCMP_ACT_ALLOW",
      "syscalls": [
        {{ "names": ["mkdir"], "action": "{action}" }}
      ]
    }},
    "namespaces": ["#
                );
                *config = config.replace(r#""namespaces": ["#, &profile);
            },
        );
        let output = bundle.runtime(&["create", &bundle.id()]);
        assert!(
            !output.status.success(),
            "a {action} rule with no listener must be refused"
        );
        assert!(
            stderr(&output).contains("listenerPath"),
            "the failure should name the missing field, got: {}",
            stderr(&output)
        );
    }
}

/// A preserve count that cannot be a descriptor number must be refused.
///
/// The program the payload runs is parked immediately above the preserved
/// block before the runtime sweeps its own descriptors away. A count that
/// does not fit a descriptor number once made the slot land inside that
/// block, so parking replaced a descriptor the caller asked to keep and the
/// sweep closed the rest, all while reporting success.
#[test]
fn an_impossible_preserve_count_is_refused() {
    if !privileged() {
        return;
    }
    // Sixty-one is the first count whose block reaches the numbers the
    // runtime renumbers its own descriptors onto; the wide one does not fit a
    // descriptor number at all.
    for count in ["61", "99999999999"] {
        let bundle =
            Bundle::new(&format!("preserve-{count}"), &["/usr/bin/true"]);
        let output =
            bundle.runtime(&["run", "--preserve-fds", count, &bundle.id()]);
        assert!(
            !output.status.success(),
            "a preserve count of {count} must fail"
        );
        assert!(
            stderr(&output).contains("preserved descriptors"),
            "the failure should say the count is the problem, got: {}",
            stderr(&output)
        );
    }

    // One below that still runs, so the bound is where it belongs.
    let bundle = Bundle::new("preserve-ok", &["/usr/bin/true"]);
    expect_ok(
        "run",
        &bundle.runtime(&["run", "--preserve-fds", "60", &bundle.id()]),
    );
}

/// A container that asks for a terminal gets a real one.
///
/// The pseudo-terminal is made inside the container, from the container's own
/// `devpts`, and the controlling end is sent to whatever the caller named.
/// A failure anywhere in that sequence leaves a caller like `conmon` with no
/// terminal at all, so the descriptor that arrives has to be one.
#[test]
fn a_container_terminal_reaches_the_console_socket() {
    if !privileged() {
        return;
    }
    use std::os::unix::net::UnixListener;

    let socket = std::env::temp_dir()
        .join(format!("kot-console-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("console socket");

    // The runtime sends the terminal while `create` is still running, so the
    // receiver has to be waiting on its own thread.
    let receiver = std::thread::spawn(move || {
        use rustix::net::{
            RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg,
        };
        let (stream, _) = listener.accept().ok()?;
        let mut payload = [0u8; 64];
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); 128];
        let mut buffer = RecvAncillaryBuffer::new(&mut space);
        let mut slices = [std::io::IoSliceMut::new(&mut payload)];
        recvmsg(&stream, &mut slices, &mut buffer, RecvFlags::empty()).ok()?;
        buffer.drain().find_map(|message| match message {
            RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
            _ => None,
        })
    });

    let path = socket.display().to_string();
    let bundle =
        Bundle::with_config("console", &["/usr/bin/sleep", "30"], |config| {
            *config =
                config.replace(r#""terminal": false"#, r#""terminal": true"#);
        });
    let id = bundle.id();
    let output = bundle.runtime(&["create", "--console-socket", &path, &id]);
    expect_ok("create", &output);

    let terminal =
        receiver.join().ok().flatten().unwrap_or_else(|| {
            panic!("no terminal reached the console socket")
        });
    assert!(
        rustix::termios::isatty(&terminal),
        "the descriptor that arrived must be a terminal"
    );
    let _ = std::fs::remove_file(&socket);
}

/// A container told to manage no cgroup can still be exec'd into.
///
/// `--cgroup-manager disabled` means there is no cgroup, so placing a
/// process in one is a success that does nothing. Treating it as a placement
/// that ought to have happened reaches code that has no directory to write
/// to, which is an assertion in a debug build and a silent no-op in a release
/// one.
#[test]
fn exec_into_a_container_without_a_cgroup_succeeds() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("no-cgroup", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    let disabled = ["--cgroup-manager", "disabled"];
    expect_ok(
        "create",
        &bundle.runtime(&[&disabled[..], &["create", &id]].concat()),
    );
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    // Both spellings: the container's own cgroup, and a sub-cgroup below it.
    expect_ok("exec", &bundle.runtime(&["exec", &id, "/usr/bin/true"]));
    expect_ok(
        "exec --cgroup",
        &bundle.runtime(&["exec", "--cgroup", "sub", &id, "/usr/bin/true"]),
    );
}

/// One failure is reported once, and says both halves of what happened.
///
/// Init reports to the driver over a socket because it may have no terminal
/// of its own, and the driver reports to the caller. When init also wrote to
/// whatever terminal it happened to share, the same failure arrived two and
/// three times over, split between a step and a reason.
#[test]
fn a_container_that_fails_reports_once() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("one-report", &["/usr/bin/definitely-not-here"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    assert!(!output.status.success(), "the container cannot have run");

    let reported = stderr(&output);
    let complaints: Vec<&str> = reported
        .lines()
        .filter(|line| line.starts_with("error:"))
        .collect();
    assert_eq!(
        complaints.len(),
        1,
        "one failure should be reported once, got: {complaints:?}"
    );
    let only = complaints.first().copied().unwrap_or_default();
    assert!(
        only.contains("open payload") && only.contains("no such file"),
        "the report should carry the step and the reason, got: {only}"
    );
}

#[test]
fn pause_and_resume_freeze_the_container() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("freeze", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let paused = bundle.runtime(&["pause", &id]);
    if !paused.status.success() {
        // A host without the freezer cannot answer this question.
        println!("skipping: cannot freeze: {}", stderr(&paused));
        return;
    }
    assert!(
        wait_for_status(&bundle, "paused"),
        "a frozen container reports itself as paused"
    );

    expect_ok("resume", &bundle.runtime(&["resume", &id]));
    assert!(
        wait_for_status(&bundle, "running"),
        "a thawed container is running again"
    );
}

#[test]
fn list_shows_the_containers_that_exist() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("list", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));

    let output = bundle.runtime(&["list"]);
    expect_ok("list", &output);
    assert!(
        stdout(&output).contains(&id),
        "the container should be listed, got: {}",
        stdout(&output)
    );

    let quiet = bundle.runtime(&["list", "--quiet"]);
    expect_ok("list --quiet", &quiet);
    assert_eq!(stdout(&quiet).trim(), id, "quiet output is ids alone");
}

#[test]
fn ps_names_the_processes_in_the_container() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("ps", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let Some((_, _, pid)) = state(&bundle) else {
        panic!("state should be readable while running");
    };
    let output = bundle.runtime(&["ps", &id, "--format", "json"]);
    expect_ok("ps", &output);
    assert!(
        stdout(&output).contains(&pid.to_string()),
        "ps should report the container's process, got: {}",
        stdout(&output)
    );
}

#[test]
fn the_pid_file_names_the_container_process() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("pid-file", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    let path = bundle.path().join("pid");
    let written = path.display().to_string();

    expect_ok(
        "create",
        &bundle.runtime(&["create", "--pid-file", &written, &id]),
    );
    let text = std::fs::read_to_string(&path).expect("the pid file");
    let recorded: i64 = text.trim().parse().expect("a process number");
    let Some((_, _, pid)) = state(&bundle) else {
        panic!("state should be readable after create");
    };
    assert_eq!(recorded, pid, "the pid file and the state should agree");
}

#[test]
fn a_read_only_root_is_read_only() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "readonly",
        &["/usr/bin/sh", "-c", "touch /probe 2>&1 || echo refused"],
        |config| {
            *config = config.replace(
                r#""path": "rootfs", "readonly": false"#,
                r#""path": "rootfs", "readonly": true"#,
            );
        },
    );
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert!(
        stdout(&output).contains("refused"),
        "writing to a read-only root should fail, got: {}",
        stdout(&output)
    );
}

#[test]
fn a_seccomp_profile_is_enforced() {
    if !privileged() {
        return;
    }
    // `chmod` is denied with a distinctive error number, so the payload can
    // tell the profile working apart from any other failure.
    let bundle = Bundle::with_config(
        "seccomp",
        &["/usr/bin/sh", "-c", "chmod 700 / 2>&1; echo done"],
        |config| {
            *config = config.replace(
                r#""maskedPaths""#,
                r#""seccomp": {
      "defaultAction": "SCMP_ACT_ALLOW",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        {
          "names": ["chmod", "fchmodat", "fchmodat2"],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        }
      ]
    },
    "maskedPaths""#,
            );
        },
    );
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    let text = stdout(&output);
    assert!(text.contains("done"), "the payload should finish: {text}");
    assert!(
        text.to_lowercase().contains("not permitted"),
        "the denied call should report the configured error, got: {text}"
    );
}

#[test]
fn a_masked_path_is_hidden() {
    if !privileged() {
        return;
    }
    let bundle =
        Bundle::new("masked", &["/usr/bin/sh", "-c", "wc -c < /proc/kcore"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "0",
        "a masked path should read as empty"
    );
}

#[test]
fn a_memory_limit_reaches_the_cgroup() {
    if !privileged() {
        return;
    }
    let bundle =
        Bundle::with_config("memory", &["/usr/bin/sleep", "30"], |config| {
            *config = config.replace(
                r#""resources": { "devices""#,
                r#""resources": { "memory": { "limit": 67108864 }, "devices""#,
            );
        });
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));

    // Read the limit back from where the kernel keeps it, which is the only
    // evidence that the configuration was applied rather than accepted.
    let output = bundle.runtime(&[
        "exec",
        &id,
        "/usr/bin/sh",
        "-c",
        "cat /sys/fs/cgroup/memory.max 2>/dev/null || \
         cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || \
         echo unknown",
    ]);
    if !output.status.success() {
        println!("skipping: cannot read the cgroup: {}", stderr(&output));
        return;
    }
    let text = stdout(&output);
    if text.contains("unknown") {
        println!("skipping: the container cannot see its own cgroup");
        return;
    }
    assert!(
        text.contains("67108864"),
        "the memory limit should be set, got: {text}"
    );
}

#[test]
fn killing_a_created_container_works_before_it_starts() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("kill-created", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("kill", &bundle.runtime(&["kill", &id, "KILL"]));
    assert!(
        wait_for_status(&bundle, "stopped"),
        "a created container can be killed before it is started"
    );
    expect_ok("delete", &bundle.runtime(&["delete", &id]));
}

#[test]
fn an_id_cannot_be_used_twice() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("duplicate", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    let again = bundle.runtime(&["create", &id]);
    assert!(
        !again.status.success(),
        "an id in use should not be taken again"
    );
    assert!(
        stderr(&again).contains("exists"),
        "the error should say the id is taken, got: {}",
        stderr(&again)
    );
}

#[test]
fn the_container_sees_its_own_cgroup_as_the_root() {
    if !privileged() {
        return;
    }
    // A cgroup namespace is rooted wherever its creator sits at the moment it
    // is made, so this tells a namespace made after the move into the
    // container's cgroup apart from one made at the clone. The latter looks
    // like it worked and shows the runtime's own cgroup.
    let bundle = Bundle::new(
        "cgroupns",
        &["/usr/bin/sh", "-c", "cat /proc/self/cgroup"],
    );
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    let text = stdout(&output);
    let unified = text.lines().any(|line| line.trim() == "0::/");
    assert!(
        unified || text.contains(":/\n") || text.trim_end().ends_with(":/"),
        "the container should be at the root of its own cgroup tree, got: \
         {text}"
    );
}

#[test]
fn an_unknown_option_is_refused_rather_than_ignored() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("bad-option", &["/usr/bin/true"]);
    let output = bundle.runtime(&["create", "--nonsense", &bundle.id()]);
    assert!(
        !output.status.success(),
        "an unknown option should be refused"
    );
    assert!(
        stderr(&output).contains("--nonsense"),
        "the error should name the option, got: {}",
        stderr(&output)
    );
}

#[test]
fn exec_refuses_a_paused_container_unless_told_not_to() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("exec-paused", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    let paused = bundle.runtime(&["pause", &id]);
    if !paused.status.success() {
        println!("skipping: cannot freeze: {}", stderr(&paused));
        return;
    }
    assert!(wait_for_status(&bundle, "paused"));

    // Entering a frozen cgroup would freeze the new process too, so this has
    // to fail rather than hang.
    let refused = bundle.runtime(&["exec", &id, "/usr/bin/sh", "-c", "exit 0"]);
    assert!(
        !refused.status.success(),
        "exec into a paused container should be refused"
    );
    assert!(
        stderr(&refused).contains("paused"),
        "the error should say the container is paused, got: {}",
        stderr(&refused)
    );

    expect_ok("resume", &bundle.runtime(&["resume", &id]));
}

#[test]
fn a_hook_runs_before_the_payload() {
    if !privileged() {
        return;
    }
    let marker =
        std::env::temp_dir().join(format!("kot-hook-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let written = marker.display().to_string();

    let bundle = Bundle::with_config("hooks", &["/usr/bin/true"], |config| {
        *config = config.replace(
            r#"  "linux": {"#,
            &format!(
                r#"  "hooks": {{
    "createRuntime": [
      {{ "path": "/usr/bin/touch", "args": ["touch", "{written}"] }}
    ]
  }},
  "linux": {{"#
            ),
        );
    });
    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert!(
        marker.exists(),
        "the createRuntime hook should have run, stderr: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_file(&marker);
}

/// The hooks after creation are reached by later commands, which read whether
/// there are any back from the state record.
///
/// Each of `start` and `delete` here is a fresh run of the runtime, so what is
/// being checked is that the record carries the answer and that it is read
/// correctly.
#[test]
fn hooks_after_creation_run_from_later_commands() {
    if !privileged() {
        return;
    }
    let base = std::env::temp_dir()
        .join(format!("kot-later-hooks-{}", std::process::id()));
    let started = format!("{}-poststart", base.display());
    let stopped = format!("{}-poststop", base.display());
    let _ = std::fs::remove_file(&started);
    let _ = std::fs::remove_file(&stopped);

    let bundle = Bundle::with_config("later", &["/usr/bin/true"], |config| {
        *config = config.replace(
            r#"  "linux": {"#,
            &format!(
                r#"  "hooks": {{
    "poststart": [
      {{ "path": "/usr/bin/touch", "args": ["touch", "{started}"] }}
    ],
    "poststop": [
      {{ "path": "/usr/bin/touch", "args": ["touch", "{stopped}"] }}
    ]
  }},
  "linux": {{"#
            ),
        );
    });
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    assert!(
        !std::path::Path::new(&started).exists(),
        "poststart must not run before the container starts"
    );
    let output = bundle.runtime(&["start", &id]);
    expect_ok("start", &output);
    assert!(
        std::path::Path::new(&started).exists(),
        "the poststart hook should have run, stderr: {}",
        stderr(&output)
    );

    // The payload exits at once; give it a moment before removing it.
    for _ in 0..100 {
        if state(&bundle).is_some_and(|(status, _, _)| status == "stopped") {
            break;
        }
        sleep(Duration::from_millis(10));
    }
    assert!(
        !std::path::Path::new(&stopped).exists(),
        "poststop must not run before the container is deleted"
    );
    let output = bundle.runtime(&["delete", &id]);
    expect_ok("delete", &output);
    assert!(
        std::path::Path::new(&stopped).exists(),
        "the poststop hook should have run, stderr: {}",
        stderr(&output)
    );
    let _ = std::fs::remove_file(&started);
    let _ = std::fs::remove_file(&stopped);
}

/// A `startContainer` hook runs inside the container from the `start` command,
/// which learns from the state record that there is one to run.
///
/// A hook that fails stops the start, which is how its having run at all shows
/// from outside.
#[test]
fn a_failing_start_container_hook_stops_the_start() {
    if !privileged() {
        return;
    }
    let bundle =
        Bundle::with_config("starthook", &["/usr/bin/true"], |config| {
            *config = config.replace(
                r#"  "linux": {"#,
                r#"  "hooks": {
    "startContainer": [
      { "path": "/usr/bin/false" }
    ]
  },
  "linux": {"#,
            );
        });
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    let output = bundle.runtime(&["start", &id]);
    assert!(
        !output.status.success(),
        "a failing startContainer hook should fail the start, stdout: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("hook"),
        "the failure should name the hook, got: {}",
        stderr(&output)
    );
    expect_ok("delete", &bundle.runtime(&["delete", "--force", &id]));
}

/// Init runs from an image that cannot be written, so that an entrypoint
/// resolving to the runtime finds nothing to overwrite.
///
/// Seen from outside, its executable is not the binary on disk, and a handle
/// to it taken while it runs, which is how the attack keeps hold of the file,
/// cannot be written through once the process has gone and the file is no
/// longer being run.
#[test]
fn init_runs_from_an_image_that_cannot_be_written() {
    if !privileged() {
        return;
    }
    use std::{
        io::Write as _,
        os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
    };

    use rustix::fs::{Mode, OFlags};

    let bundle = Bundle::new("sealed", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    let Some((_, _, pid)) = state(&bundle) else {
        panic!("state should be readable after create");
    };

    let exe = format!("/proc/{pid}/exe");
    let running = std::fs::metadata(&exe).expect("the executable of init");
    let on_disk = std::fs::metadata(bundle::RUNTIME).expect("the runtime");
    assert_ne!(
        (running.dev(), running.ino()),
        (on_disk.dev(), on_disk.ino()),
        "init should run from a sealed image rather than the binary on disk"
    );

    let held =
        rustix::fs::open(&exe, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .expect("a handle to the running image");
    expect_ok("delete", &bundle.runtime(&["delete", "--force", &id]));

    let through = format!("/proc/self/fd/{}", held.as_raw_fd());
    let written = std::fs::OpenOptions::new()
        .write(true)
        .open(&through)
        .and_then(|mut file| file.write_all(b"x"));
    assert!(
        written.is_err(),
        "the sealed image should refuse to be written through a kept handle"
    );
}

#[test]
fn a_seccomp_notify_listener_reaches_its_agent() {
    if !privileged() {
        return;
    }
    use std::{io::Read as _, os::unix::net::UnixListener};

    let socket = std::env::temp_dir()
        .join(format!("kot-agent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("agent socket");

    // The agent answers on its own thread, because the runtime waits for it
    // before letting the payload run.
    let agent = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return String::new();
        };
        let mut buffer = [0u8; 4096];
        let read = stream.read(&mut buffer).unwrap_or(0);
        String::from_utf8_lossy(buffer.get(..read).unwrap_or(&[])).into_owned()
    });

    let path = socket.display().to_string();
    let bundle = Bundle::with_config("notify", &["/usr/bin/true"], |config| {
        // `mount` is notified rather than allowed. The payload never
        // calls it, so the container still finishes; what is being
        // checked is that the descriptor reached the agent at all.
        *config = config.replace(
            r#""maskedPaths""#,
            &format!(
                r#""seccomp": {{
      "defaultAction": "SCMP_ACT_ALLOW",
      "architectures": ["SCMP_ARCH_X86_64"],
      "listenerPath": "{path}",
      "listenerMetadata": "kot-test",
      "syscalls": [
        {{ "names": ["mount"], "action": "SCMP_ACT_NOTIFY" }}
      ]
    }},
    "maskedPaths""#
            ),
        );
    });

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);

    let seen = agent.join().unwrap_or_default();
    let _ = std::fs::remove_file(&socket);
    assert!(
        seen.contains("seccompFd"),
        "the agent should be told which descriptor is the listener, got: \
         {seen}"
    );
    assert!(
        seen.contains("kot-test"),
        "the agent should receive the configured metadata, got: {seen}"
    );
}

/// A tmpfs asked to copy up has to carry the directory's contents with it.
///
/// The option used to be parsed, recorded in the plan, and then ignored, so
/// the container saw an empty directory where the image had put files.
#[test]
fn tmpcopyup_carries_the_directory_forward() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "tmpcopyup",
        &[
            "/usr/bin/sh",
            "-c",
            "cat /seeded/marker; cat /seeded/deeper/nested",
        ],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/seeded",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["tmpcopyup", "nosuid", "mode=755"]
    },"#,
            );
        },
    );
    let seeded = bundle.path().join("rootfs/seeded");
    std::fs::create_dir_all(seeded.join("deeper")).expect("seed directory");
    std::fs::write(seeded.join("marker"), "carried\n").expect("seed file");
    std::fs::write(seeded.join("deeper/nested"), "deeper\n")
        .expect("seed file");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output),
        "carried\ndeeper\n",
        "the tmpfs should have been seeded with what the directory held"
    );
}

/// Without the option the tmpfs covers the directory and the contents go with
/// it, which is what makes the test above evidence of anything.
#[test]
fn a_plain_tmpfs_covers_what_was_there() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "tmpplain",
        &["/usr/bin/sh", "-c", "ls /seeded | wc -l"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/seeded",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "mode=755"]
    },"#,
            );
        },
    );
    let seeded = bundle.path().join("rootfs/seeded");
    std::fs::create_dir_all(&seeded).expect("seed directory");
    std::fs::write(seeded.join("marker"), "hidden\n").expect("seed file");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "0", "a plain tmpfs starts empty");
}

/// `dest-nofollow` puts the mount on the destination link itself.
///
/// A link is bound onto a link: without the option the destination link is
/// resolved first and the mount lands on what it names, so the two paths after
/// the run are what say which happened.
#[test]
fn dest_nofollow_mounts_onto_the_link_itself() {
    if !privileged() {
        return;
    }
    let outside = std::env::temp_dir()
        .join(format!("kot-nofollow-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("source directory");
    let source_link = outside.join("link");
    std::os::unix::fs::symlink("from-the-host", &source_link)
        .expect("source link");

    let source = source_link.display().to_string();
    let bundle = Bundle::with_config(
        "destnofollow",
        &["/usr/bin/sh", "-c", "readlink /link; cat /real/marker"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/link",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "src-nofollow", "dest-nofollow"]
    }},"#
                ),
            );
        },
    );
    let rootfs = bundle.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("real")).expect("target directory");
    std::fs::write(rootfs.join("real/marker"), "untouched\n").expect("marker");
    std::os::unix::fs::symlink("real", rootfs.join("link")).expect("link");

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&outside);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output),
        "from-the-host\nuntouched\n",
        "the mount should cover the link, leaving what it named alone"
    );
}

/// `copy-symlink` gives the container a link of its own rather than binding
/// whatever the source link points at.
#[test]
fn copy_symlink_recreates_the_link() {
    if !privileged() {
        return;
    }
    let outside = std::env::temp_dir()
        .join(format!("kot-symlink-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("source directory");
    std::fs::write(outside.join("real"), "behind the link\n").expect("target");
    let link = outside.join("link");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("real", &link).expect("source link");

    let source = link.display().to_string();
    let bundle = Bundle::with_config(
        "copysymlink",
        &["/usr/bin/sh", "-c", "readlink /copied"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/copied",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "copy-symlink"]
    }},"#
                ),
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&outside);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "real",
        "the container should have a link, not the file behind it"
    );
}

/// A mount that states its own id mapping has to arrive with ids shifted.
///
/// The mapping used to be parsed and then dropped, so the container saw the
/// host's ownership and nothing reported that the request had gone nowhere.
/// The file is owned by root outside and has to read as 1000 inside.
#[test]
fn an_id_mapped_mount_shifts_ownership() {
    if !privileged() {
        return;
    }
    let outside = std::env::temp_dir()
        .join(format!("kot-idmap-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("source directory");
    std::fs::write(outside.join("owned"), "by root\n").expect("source file");

    let source = outside.display().to_string();
    let bundle = Bundle::with_config(
        "idmap",
        &["/usr/bin/sh", "-c", "stat -c %u:%g /shifted/owned"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/shifted",
      "type": "bind",
      "source": "{source}",
      "options": ["bind"],
      "uidMappings": [{{ "containerID": 1000, "hostID": 0, "size": 1 }}],
      "gidMappings": [{{ "containerID": 1000, "hostID": 0, "size": 1 }}]
    }},"#
                ),
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&outside);

    // A host whose kernel or source filesystem cannot carry an id-mapped mount
    // reports so and starts nothing, which is the honest answer and not a
    // result this test can judge.
    let complaint = stderr(&output);
    if !output.status.success() && complaint.contains("mount") {
        println!(
            "skipping: id-mapped mounts unavailable: {}",
            complaint.trim()
        );
        return;
    }
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "1000:1000",
        "the mapping should have shifted the file's owner"
    );
}

/// A mount that asks to be shared has to arrive shared.
///
/// The mode was parsed into the plan and then never applied, so every mount
/// kept whatever it inherited and a bundle asking for propagation got silence.
/// `/proc/self/mountinfo` names the peer group, which only a shared mount has.
#[test]
fn a_mount_propagation_mode_is_applied() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "propagation",
        &[
            "/usr/bin/sh",
            "-c",
            "grep ' /shared ' /proc/self/mountinfo | grep -c shared:",
        ],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/shared",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["shared", "nosuid", "mode=755"]
    },"#,
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "1",
        "the mount should carry a peer group, which is what shared means"
    );
}

/// The container-wide mount label has to reach the mounts that take one.
///
/// `/proc/self/mountinfo` reports a superblock's options, so a tmpfs mounted
/// with a context names it there and one mounted without does not.
#[test]
fn a_mount_label_reaches_the_kernel() {
    if !privileged() {
        return;
    }
    let label = "system_u:object_r:tmp_t:s0";
    let bundle = Bundle::with_config(
        "mountlabel",
        &[
            "/usr/bin/sh",
            "-c",
            "grep ' /labelled ' /proc/self/mountinfo | grep -o 'context=[^,\" ]*' | head -1",
        ],
        |config| {
            *config = config.replace(
                r#"  "linux": {"#,
                &format!(
                    r#"  "linux": {{
    "mountLabel": "{label}","#
                ),
            );
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/labelled",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "mode=755"]
    },"#,
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    let complaint = stderr(&output);
    if !output.status.success() && complaint.contains("selinux") {
        println!("skipping: this policy has no {label}: {}", complaint.trim());
        return;
    }
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        format!("context={label}"),
        "the tmpfs should carry the label the configuration named"
    );
}

/// A destination the kernel answers for may not be covered unfollowed.
///
/// Following a link puts the mount wherever the link leads, which the
/// confinement already bounds. Not following it puts the mount on the link,
/// and `/proc/self` is a link the kernel resolves per process, so covering it
/// would shadow a name the kernel means to answer itself.
#[test]
fn dest_nofollow_refuses_a_destination_the_kernel_owns() {
    if !privileged() {
        return;
    }
    let outside = std::env::temp_dir()
        .join(format!("kot-owned-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("source directory");
    let source_link = outside.join("link");
    std::os::unix::fs::symlink("elsewhere", &source_link).expect("source link");

    let source = source_link.display().to_string();
    let bundle = Bundle::with_config(
        "owneddest",
        &["/usr/bin/sh", "-c", "true"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/proc/self",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "src-nofollow", "dest-nofollow"]
    }},"#
                ),
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&outside);
    assert!(
        !output.status.success(),
        "covering a kernel-owned destination should be refused"
    );
    assert!(
        stderr(&output).contains("kernel answers for this destination"),
        "the refusal should say why: {}",
        stderr(&output).trim()
    );
}

/// `copy-symlink` onto something that is not the link it would have made has
/// to say so.
///
/// Treating whatever is already there as success would leave the container
/// without the link it asked for and nothing reporting it.
#[test]
fn copy_symlink_refuses_a_destination_that_is_not_the_link() {
    if !privileged() {
        return;
    }
    let outside = std::env::temp_dir()
        .join(format!("kot-clash-source-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(&outside).expect("source directory");
    std::fs::write(outside.join("real"), "behind\n").expect("target");
    let link = outside.join("link");
    std::os::unix::fs::symlink("real", &link).expect("source link");

    let source = link.display().to_string();
    let bundle = Bundle::with_config(
        "clashsymlink",
        &["/usr/bin/sh", "-c", "true"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/taken",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "copy-symlink"]
    }},"#
                ),
            );
        },
    );
    // The image already ships a plain file under that name.
    std::fs::write(bundle.path().join("rootfs/taken"), "in the way\n")
        .expect("occupy the destination");

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&outside);
    assert!(
        !output.status.success(),
        "a destination that is not the link should be reported"
    );
    assert!(
        stderr(&output).contains("destination is not a link"),
        "the refusal should say why: {}",
        stderr(&output).trim()
    );
}
