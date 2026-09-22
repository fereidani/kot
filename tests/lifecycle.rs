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

use bundle::{Bundle, RUNTIME, expect_ok, stderr, stdout};

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

/// A record the runtime cannot read still names a container.
///
/// A state file left empty by a crash, or by a filesystem that lost the
/// write, gives `delete` nothing to act on. Answering that the container is
/// gone while its process keeps running and its directory stays behind
/// holds the id for good and strands the process: the next `create` of that
/// name is refused by a directory nobody can explain, and nothing is left
/// that names what is still running.
#[test]
fn a_forced_delete_removes_a_record_it_cannot_read() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("delete-unreadable", &["/usr/bin/sleep", "30"]);
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));
    let (_, _, pid) = state(&bundle).expect("the container's state");

    let record = std::path::Path::new(&bundle.state_root())
        .join(&id)
        .join("state.json");
    std::fs::write(&record, b"").expect("emptying the state record");

    expect_ok(
        "forced delete",
        &bundle.runtime(&["delete", "--force", &id]),
    );
    assert!(
        !record.parent().is_some_and(std::path::Path::exists),
        "the state directory should be gone with the record"
    );
    let cgroup = std::path::PathBuf::from("/sys/fs/cgroup/kot").join(&id);
    assert!(
        !cgroup.exists(),
        "the cgroup should be gone with the record"
    );
    assert!(
        stopped(pid),
        "the container's process should not outlive its record"
    );
    expect_ok("create again", &bundle.runtime(&["create", &id]));
    bundle.cleanup();
}

/// Whether a process has stopped running.
///
/// A process killed a moment ago is still in `/proc` until whoever waits on
/// it does, which for a container the runtime has removed is whatever
/// adopted it. What matters is that it is no longer running.
fn stopped(pid: i64) -> bool {
    // Bounded: a killed process reaches this state at once, and the wait is
    // here only for the moment between the signal and the kernel acting.
    for _ in 0..1000 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        else {
            return true;
        };
        // The state follows the command name, which is the one field that
        // can hold a space and is parenthesised for that reason.
        let state = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().next());
        if state.is_none_or(|state| state == "Z") {
            return true;
        }
        sleep(Duration::from_millis(2));
    }
    false
}

/// A payload is handed three standard descriptors, open or not.
///
/// A caller may start the runtime with one of its own closed. Passing that
/// on gives the payload a free number below three, which the first file it
/// opens takes: everything it then prints goes into that file instead.
#[test]
fn a_payload_is_given_the_null_device_for_a_stream_the_caller_closed() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new(
        "closed-stream",
        &[
            "/usr/bin/sh",
            "-c",
            // The copy is taken before the redirection claims the
            // number, so what is read is the descriptor the payload was
            // started with.
            "exec 4>&1; readlink /proc/self/fd/4 > /answer.txt",
        ],
    );
    let mut command = std::process::Command::new(bundle::RUNTIME);
    command
        .args(["--root", &bundle.state_root(), "run", &bundle.id()])
        .current_dir(bundle.path())
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: the closure calls nothing but `close`, which is
    // async-signal-safe, and closing standard output is the condition under
    // test.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut command, || {
            // SAFETY: the descriptor is this process's own and the child
            // is about to be executed, so nothing else uses it.
            rustix::io::close(1);
            Ok(())
        });
    }
    let status = command.status().expect("running the runtime");
    assert!(status.success(), "the container should run: {status}");

    let answer =
        std::fs::read_to_string(bundle.path().join("rootfs/answer.txt"))
            .expect("the payload wrote nothing");
    assert_eq!(
        answer.trim(),
        "/dev/null",
        "a closed standard stream should reach the payload as the null device"
    );
}

/// Hooks at both container stages release init on the `create` and `start`
/// path, not only on `run`.
///
/// Init stops at each stage only when the plan says hooks run there, and the
/// driver sends the message that releases it under the same condition. The
/// two halves disagreeing is a container that never starts.
#[test]
fn container_hooks_release_init_on_the_create_and_start_path() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new(
        "staged-hooks",
        &["/usr/bin/sh", "-c", "echo payload >> /tmp/order.txt"],
    );
    let root = bundle.path().to_path_buf();
    std::fs::create_dir_all(root.join("rootfs/tmp")).expect("a place to write");
    // A `createContainer` hook is named in the runtime's own namespace and
    // runs in the container's before the root changes, so both its own
    // path and the file it writes are the ones outside. A `startContainer`
    // hook runs after the change, so both of its are inside.
    let outside = root.join("rootfs/tmp/order.txt");
    let record = [
        ("hook.sh", "created", outside.display().to_string()),
        ("rootfs/hook.sh", "starting", "/tmp/order.txt".to_owned()),
    ];
    for (where_, line, file) in record {
        let path = root.join(where_);
        let script = format!("#!/bin/sh\necho {line} >> {file}\n");
        std::fs::write(&path, script).expect("hook");
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

    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "stopped"));

    let order = std::fs::read_to_string(root.join("rootfs/tmp/order.txt"))
        .expect("nothing ran");
    let lines: Vec<&str> = order.split_whitespace().collect();
    assert_eq!(
        lines,
        vec!["created", "starting", "payload"],
        "each stage runs in turn and the payload comes last"
    );
}

/// A process `exec` puts in a container gets the same filter, and a filter
/// that notifies needs its listener delivered like any other.
///
/// The container's profile applies to whatever runs inside it. Installing
/// the filter and leaving the descriptor with the process suspends the first
/// syscall the profile hands over, with nothing on the other end to answer
/// it; the runtime instead stops with the two ends of its handshake reading
/// past each other.
#[test]
fn a_notify_filter_reaches_its_agent_for_an_exec_too() {
    if !privileged() {
        return;
    }
    // A name of its own: another test has an agent of its own, and the two
    // run at the same time.
    let socket = std::env::temp_dir()
        .join(format!("kot-agent-exec-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("agent socket");
    let agent = std::thread::spawn(move || {
        use std::io::Read;

        listener.set_nonblocking(true).expect("agent socket");
        // Two connections: one for the container, one for the process
        // `exec` adds to it. Bounded, so a runtime that delivers neither
        // fails the assertion below rather than holding the suite.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut seen = Vec::new();
        while seen.len() < 2 && std::time::Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                sleep(Duration::from_millis(20));
                continue;
            };
            stream.set_nonblocking(false).expect("agent connection");
            let mut payload = String::new();
            let _ = stream.read_to_string(&mut payload);
            seen.push(payload);
        }
        seen
    });

    let path = socket.display().to_string();
    let bundle = Bundle::with_config(
        "notify-exec",
        &["/usr/bin/sleep", "30"],
        |config| {
            let profile = format!(
                r#""seccomp": {{
      "defaultAction": "SCMP_ACT_ALLOW",
      "listenerPath": "{path}",
      "syscalls": [
        {{ "names": ["mkdir"], "action": "SCMP_ACT_NOTIFY" }}
      ]
    }},
    "namespaces": ["#
            );
            *config = config.replace(r#""namespaces": ["#, &profile);
        },
    );
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(wait_for_status(&bundle, "running"));

    expect_ok("exec", &bundle.runtime(&["exec", &id, "/usr/bin/true"]));
    bundle.cleanup();

    let seen = agent.join().expect("the agent thread");
    assert_eq!(
        seen.len(),
        2,
        "the container and the exec both owe the agent a listener"
    );
    for payload in &seen {
        assert!(
            payload.contains("\"seccompFd\""),
            "the agent is told which descriptor is the listener, got: {payload}"
        );
    }
    let _ = std::fs::remove_file(&socket);
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
    // Both spellings the filter compiler accepts. The prefix is part of the
    // name the specification defines and is required; the case is not.
    for (name, action) in
        [("plain", "SCMP_ACT_NOTIFY"), ("lower", "scmp_act_notify")]
    {
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
    // Five hundred and nine is the first count whose block reaches the
    // numbers the runtime renumbers its own descriptors onto; the wide one
    // does not fit a descriptor number at all.
    for count in ["509", "99999999999"] {
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
    //
    // It chmods a file it makes itself rather than a directory that exists
    // on the host as well. The filter is what this test is about, and the
    // isolation it runs behind is what other tests are about: if that
    // isolation is broken, this payload should leave a stray empty file
    // somewhere, not change the mode of a system directory.
    let bundle = Bundle::with_config(
        "seccomp",
        &[
            "/usr/bin/sh",
            "-c",
            "touch /seccomp-probe 2>/dev/null; \
             chmod 700 /seccomp-probe 2>&1; echo done",
        ],
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
///
/// The mapping converts the ids the source filesystem holds into the ids
/// the mount shows, so a file owned by the id the mapping calls the
/// container's reads as the one it calls the host's. Here the file belongs
/// to root outside and has to read as 1000 inside.
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
      "uidMappings": [{{ "containerID": 0, "hostID": 1000, "size": 1 }}],
      "gidMappings": [{{ "containerID": 0, "hostID": 1000, "size": 1 }}]
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

/// Detaching the old root after the pivot must not reach the host.
///
/// The namespace init starts in is a copy of the host's, and every mount in
/// the copy is a peer of the one it came from. An unmount propagates to the
/// peers of every mount in the tree it takes down, and detaching the old root
/// takes down the whole tree. The runtime once severed only the mount the
/// bundle sat on, and one container run then took the host's `/proc` and
/// `/tmp` with it.
///
/// The container runs inside a namespace of the test's own, made a slave of
/// the host and then shared, so the runtime's namespace is a peer of it and
/// not of the host: whatever leaks lands here, where it can be counted
/// safely. Both the default propagation and an explicitly shared tree are
/// tried, because the second keeps the peers on purpose and relies on the old
/// root being cut loose before it is detached.
#[test]
fn detaching_the_old_root_does_not_reach_the_host() {
    if !privileged() {
        return;
    }
    if std::process::Command::new("unshare")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("skipping: unshare is not available");
        return;
    }
    for mode in [None, Some("rshared")] {
        let name = mode.unwrap_or("default");
        let bundle = Bundle::with_config(
            &format!("oldroot-{name}"),
            &["/usr/bin/true"],
            |config| {
                if let Some(mode) = mode {
                    *config = config.replace(
                        r#"  "linux": {"#,
                        &format!(
                            r#"  "linux": {{
    "rootfsPropagation": "{mode}","#
                        ),
                    );
                }
            },
        );
        // `findmnt` reads `/proc/self/mountinfo`, so losing `/proc` shows up
        // as a count of nothing rather than as a smaller count.
        let script = format!(
            "mount --make-rshared / && \
             before=$(findmnt -rn -o TARGET | wc -l) && \
             {RUNTIME} --root {} run {} && \
             after=$(findmnt -rn -o TARGET | wc -l) && \
             echo \"$before $after\"",
            bundle.state_root(),
            bundle.id()
        );
        let output = std::process::Command::new("unshare")
            .args(["--mount", "--propagation", "slave", "--", "sh", "-c"])
            .arg(&script)
            .current_dir(bundle.path())
            .output()
            .expect("running the runtime in a namespace of its own");
        expect_ok(&format!("run with {name} propagation"), &output);
        let text = stdout(&output);
        let (before, after) = text.trim().split_once(' ').expect("two counts");
        assert_eq!(
            before, after,
            "with {name} propagation the namespace should keep every mount \
             it had, not go from {before} to {after}"
        );
    }
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

/// The state root has to be attempted rather than assumed.
///
/// A rootless engine runs the runtime inside a user namespace that maps the
/// caller to zero, so asking for the effective user id answers root while the
/// authority over the host's `/run` is still the caller's own. Taking that
/// answer at face value left the runtime reporting that it could not make
/// `/run/kot` and starting nothing. Here `/run` is made read-only in a mount
/// namespace of the test's own, which is the same refusal arriving at the
/// same decision.
#[test]
fn the_state_root_falls_back_when_run_refuses() {
    if !privileged() {
        return;
    }
    if std::process::Command::new("unshare")
        .arg("--version")
        .output()
        .is_err()
    {
        println!("skipping: unshare is not available");
        return;
    }

    let session = std::env::temp_dir()
        .join(format!("kot-session-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&session);
    std::fs::create_dir_all(&session).expect("session directory");

    // The namespace is private, so nothing here reaches the host's mounts.
    let script = format!(
        "mount -t tmpfs -o ro tmpfs /run && exec {RUNTIME} state absent"
    );
    let output = std::process::Command::new("unshare")
        .args(["--mount", "--propagation", "private", "--", "sh", "-c"])
        .arg(&script)
        .env("XDG_RUNTIME_DIR", &session)
        .output()
        .expect("running the runtime with /run read only");

    let complaint = String::from_utf8_lossy(&output.stderr).into_owned();
    let landed = session.join("kot").is_dir();
    let _ = std::fs::remove_dir_all(&session);

    assert!(
        !complaint.contains("state directory"),
        "the runtime should have moved on from /run, but said: {}",
        complaint.trim()
    );
    assert!(
        complaint.contains("does not exist"),
        "the store should have opened and the container be missing: {}",
        complaint.trim()
    );
    assert!(
        landed,
        "the state root should have been made in the session"
    );
}

/// A container asked to run as somebody other than root has to be able to
/// say it has started.
///
/// Init reports readiness by reopening the start fifo through
/// `/proc/self/fd`, and that reopen is checked against the fifo's own mode
/// after init has become the container's user. The mode was asked for as
/// 0622 and granted as 0600, because `mknod` takes it through the umask, so
/// the container died between `create` and `start` with nobody left to say
/// why: the driver had already reported success.
#[test]
fn a_container_running_as_another_user_can_start() {
    if !privileged() {
        return;
    }
    let bundle =
        Bundle::with_config("otheruser", &["/usr/bin/id", "-u"], |config| {
            *config = config.replace(
                r#""user": { "uid": 0, "gid": 0 },"#,
                r#""user": { "uid": 1000, "gid": 0, "additionalGids": [0] },"#,
            );
        });
    let id = bundle.id();
    expect_ok("create", &bundle.runtime(&["create", &id]));
    expect_ok("start", &bundle.runtime(&["start", &id]));
    assert!(
        wait_for_status(&bundle, "stopped"),
        "the container should have run and exited"
    );
}

/// Puts a configuration in a user namespace whose root is a host id of its
/// own, as an engine does for an image it unpacks for one user.
fn in_user_namespace(config: &mut String, mapped_root: u32) {
    *config = config.replace(
        r#"      { "type": "cgroup" }"#,
        r#"      { "type": "cgroup" },
      { "type": "user" }"#,
    );
    *config = config.replace(
        r#"    "maskedPaths""#,
        &format!(
            r#"    "uidMappings": [
      {{ "containerID": 0, "hostID": {mapped_root}, "size": 65536 }}
    ],
    "gidMappings": [
      {{ "containerID": 0, "hostID": {mapped_root}, "size": 65536 }}
    ],
    "maskedPaths""#
        ),
    );
}

/// A container whose user namespace does not map the runtime's own id
/// still gets a filesystem, and one the container owns.
///
/// An engine unpacking an image for a user namespace gives it to that
/// namespace's root, leaving the runtime's own user with no id there. The
/// kernel will not record an owner it cannot express in the namespace that
/// owns the filesystem, so a runtime building as itself gets `EOVERFLOW`
/// and the container never starts.
#[test]
fn a_user_namespace_that_excludes_the_runtime_still_builds_a_filesystem() {
    if !privileged() {
        return;
    }
    /// The host id this container's root is, well clear of any real
    /// account and with the runtime's own id outside the range.
    const MAPPED_ROOT: u32 = 100_000;

    let bundle = Bundle::with_config(
        "userns-identity",
        &["/usr/bin/sh", "-c", "stat -c %u:%g /dev/shm"],
        |config| in_user_namespace(config, MAPPED_ROOT),
    );
    // As an engine unpacking an image for this namespace would: the root
    // belongs to the container's root, which is this host id.
    std::os::unix::fs::chown(
        bundle.path().join("rootfs"),
        Some(MAPPED_ROOT),
        Some(MAPPED_ROOT),
    )
    .expect("giving the root filesystem to the container's root");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "0:0",
        "a filesystem the runtime made for the container belongs to the \
         container's root, not to a user it cannot name"
    );
}

/// A container that joins another's pid namespace is recorded, and killed,
/// as the process that runs its payload.
///
/// Entering a pid namespace puts a process's children in it and never the
/// process itself, so init forks and stays behind as a proxy. Recording the
/// proxy, which is what the clone returned, lands everything done by number
/// on the wrong process: a signal that leaves the payload running, a state
/// document naming a process outside the container, a cgroup that cannot be
/// removed.
#[test]
fn a_container_joining_a_pid_namespace_records_its_own_process() {
    if !privileged() {
        return;
    }
    let target = Bundle::new("pidns-target", &["/usr/bin/sleep", "600"]);
    expect_ok("run", &target.runtime(&["run", "--detach", &target.id()]));
    let Some((_, _, target_pid)) = state(&target) else {
        panic!("the target container should report its state");
    };

    let attached = Bundle::with_config(
        "pidns-attached",
        &["/usr/bin/sleep", "600"],
        |config| {
            *config = config.replace(
                r#"      { "type": "pid" },"#,
                &format!(
                    r#"      {{ "type": "pid", "path": "/proc/{target_pid}/ns/pid" }},"#
                ),
            );
        },
    );
    expect_ok(
        "run",
        &attached.runtime(&["run", "--detach", &attached.id()]),
    );
    let Some((_, _, pid)) = state(&attached) else {
        panic!("the attached container should report its state");
    };

    // The payload, not the process waiting on it: the program the
    // configuration named rather than the runtime's own image.
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default();
    assert_eq!(
        comm.trim(),
        "sleep",
        "the state should name the process running the payload"
    );

    expect_ok("kill", &attached.runtime(&["kill", &attached.id(), "KILL"]));
    let stopped = (0..200u32).any(|_| {
        sleep(Duration::from_millis(10));
        std::fs::read_to_string(format!("/proc/{pid}/comm")).is_err()
    });
    assert!(stopped, "killing the container should stop its payload");

    let _ = attached.runtime(&["delete", "--force", &attached.id()]);
    let _ = target.runtime(&["delete", "--force", &target.id()]);
}

/// A bind source the container's root cannot reach is still mounted.
///
/// The source is a host path the configuration named, and reaching it is
/// the runtime's business rather than the container's. Init is the
/// container's root by then and cannot open it, so the driver does and
/// sends the mount over.
#[test]
fn a_bind_source_the_container_cannot_reach_is_still_mounted() {
    if !privileged() {
        return;
    }
    const MAPPED_ROOT: u32 = 100_000;

    let secret =
        std::env::temp_dir().join(format!("kot-secret-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&secret);
    std::fs::create_dir_all(&secret).expect("a host directory");
    std::fs::write(secret.join("file"), "kept\n").expect("a host file");
    std::fs::set_permissions(
        &secret,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("closing the directory to everybody else");
    let source = secret.display().to_string();

    let bundle = Bundle::with_config(
        "userns-source",
        &[
            "/usr/bin/sh",
            "-c",
            "grep -c ' /secret ' /proc/self/mountinfo",
        ],
        |config| {
            in_user_namespace(config, MAPPED_ROOT);
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/secret",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "ro"]
    }},"#
                ),
            );
        },
    );
    std::os::unix::fs::chown(
        bundle.path().join("rootfs"),
        Some(MAPPED_ROOT),
        Some(MAPPED_ROOT),
    )
    .expect("giving the root filesystem to the container's root");

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&secret);
    expect_ok("run", &output);
    assert_eq!(
        stdout(&output).trim(),
        "1",
        "the mount should be there, whatever the container may read of it"
    );
}

/// A detached container leaves nothing of the runtime holding the caller's
/// output.
///
/// A read of what the runtime printed ends when the last copy of that pipe
/// closes. Init forks to enter a namespace `unshare` leaves it outside of,
/// and the process left waiting has no use for those streams: holding them
/// keeps the caller reading until the container exits, which for a detached
/// one may be never.
#[test]
fn a_detached_container_does_not_hold_the_caller_output_open() {
    if !privileged() {
        return;
    }
    use std::{io::Read as _, os::fd::OwnedFd, process::Command};

    // A time namespace is one of the two `unshare` cannot put this process
    // in, so the runtime forks and leaves a process behind to wait.
    let bundle = Bundle::with_config(
        "detached-streams",
        // The payload gives up the streams itself, so whatever keeps the
        // pipe open afterwards belongs to the runtime.
        &["/usr/bin/sh", "-c", "exec 1>&-; exec 2>&-; sleep 600"],
        |config| {
            *config = config.replace(
                r#"      { "type": "cgroup" }"#,
                r#"      { "type": "cgroup" },
      { "type": "time" }"#,
            );
        },
    );

    // Close on exec, or the container inherits a copy of this pipe that
    // nobody meant it to have and the test measures its own mistake.
    let (reader, writer) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .expect("a pipe");
    let second: OwnedFd = writer.try_clone().expect("the other end");
    let status = Command::new(RUNTIME)
        .args(["--root", &bundle.state_root()])
        .args(["run", "--detach", &bundle.id()])
        .current_dir(bundle.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(writer))
        .stderr(std::process::Stdio::from(second))
        .status()
        .expect("running the runtime");
    assert!(status.success(), "the container should have started");

    // Everything the runtime printed, read to the end. The container is
    // still running, so an end that never comes is the failure.
    rustix::io::ioctl_fionbio(&reader, true).expect("a non-blocking pipe");
    let mut file = std::fs::File::from(reader);
    let mut buffer = [0u8; 256];
    let closed = (0..200u32).any(|_| {
        sleep(Duration::from_millis(10));
        matches!(file.read(&mut buffer), Ok(0))
    });
    let _ = bundle.runtime(&["delete", "--force", &bundle.id()]);
    assert!(
        closed,
        "the runtime should leave no copy of the caller's output behind"
    );
}

/// A bind of a file the container cannot reach lands on a file.
///
/// A bind source inside a user namespace may be a path only the runtime's
/// own user can look at, so the driver opens it and hands the tree over. The
/// kernel refuses to move a file onto a directory, so what is made at the
/// destination has to match what is on its way there.
#[test]
fn a_bind_of_a_file_into_a_user_namespace_lands_on_a_file() {
    if !privileged() {
        return;
    }
    const MAPPED_ROOT: u32 = 100_000;

    let closed =
        std::env::temp_dir().join(format!("kot-closed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&closed);
    std::fs::create_dir_all(&closed).expect("a host directory");
    std::fs::write(closed.join("file"), "kept\n").expect("a host file");
    std::fs::set_permissions(
        &closed,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("closing the directory to everybody else");
    let source = closed.join("file").display().to_string();

    let bundle = Bundle::with_config(
        "userns-file-bind",
        &["/usr/bin/cat", "/carried"],
        |config| {
            in_user_namespace(config, MAPPED_ROOT);
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                &format!(
                    r#"    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/carried",
      "type": "bind",
      "source": "{source}",
      "options": ["bind", "ro"]
    }},"#
                ),
            );
        },
    );
    std::os::unix::fs::chown(
        bundle.path().join("rootfs"),
        Some(MAPPED_ROOT),
        Some(MAPPED_ROOT),
    )
    .expect("giving the root filesystem to the container's root");

    let output = bundle.runtime(&["run", &bundle.id()]);
    let _ = std::fs::remove_dir_all(&closed);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "kept");
}

/// A hard limit above the host's is raised for a container in a user
/// namespace.
///
/// Raising a hard limit needs privilege that namespace does not hold, so
/// the container cannot do it for itself.
#[test]
fn a_hard_limit_a_user_namespace_cannot_raise_is_raised_for_it() {
    if !privileged() {
        return;
    }
    const MAPPED_ROOT: u32 = 100_000;

    let held = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let Some(hard) = held.maximum else {
        println!("skipping: the host has no hard limit to raise above");
        return;
    };
    let wanted = hard + 1024;

    let bundle = Bundle::with_config(
        "userns-rlimit",
        &["/usr/bin/sh", "-c", "ulimit -Hn"],
        |config| {
            in_user_namespace(config, MAPPED_ROOT);
            *config = config.replace(
                r#""rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 }]"#,
                &format!(
                    r#""rlimits": [{{ "type": "RLIMIT_NOFILE", "hard": {wanted}, "soft": {wanted} }}]"#
                ),
            );
        },
    );
    std::os::unix::fs::chown(
        bundle.path().join("rootfs"),
        Some(MAPPED_ROOT),
        Some(MAPPED_ROOT),
    )
    .expect("giving the root filesystem to the container's root");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), wanted.to_string());
}

/// A limit lower than the runtime's own descriptor block still starts.
///
/// The runtime hands its descriptors over on numbers above what a container
/// may ask to be limited to, so a limit applied before that fails it.
#[test]
fn a_limit_below_the_handoff_block_still_starts_in_a_user_namespace() {
    if !privileged() {
        return;
    }
    const MAPPED_ROOT: u32 = 100_000;

    let bundle = Bundle::with_config(
        "userns-low-rlimit",
        &["/usr/bin/sh", "-c", "ulimit -n"],
        |config| {
            in_user_namespace(config, MAPPED_ROOT);
            *config = config.replace(
                r#""hard": 4096, "soft": 4096"#,
                r#""hard": 256, "soft": 256"#,
            );
        },
    );
    std::os::unix::fs::chown(
        bundle.path().join("rootfs"),
        Some(MAPPED_ROOT),
        Some(MAPPED_ROOT),
    )
    .expect("giving the root filesystem to the container's root");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "256");
}

/// A payload with an interpreter line runs through its interpreter.
///
/// The program is executed from a descriptor, which the interpreter opens
/// as `/dev/fd/<number>`. The kernel refuses a script whose descriptor would
/// close on the execution.
#[test]
fn a_script_payload_runs_through_its_interpreter() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("script-payload", &["/script"]);
    let script = bundle.path().join("rootfs").join("script");
    std::fs::write(&script, "#!/usr/bin/sh\necho interpreted\n")
        .expect("a script in the container");
    std::fs::set_permissions(
        &script,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("making the script executable");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "interpreted");
}

/// A payload that is not a regular file is refused by name.
///
/// Executing a directory fails with a reason that describes the syscall
/// rather than the configuration, which names nothing the caller wrote.
#[test]
fn a_payload_that_is_not_a_regular_file_is_refused() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("directory-payload", &["/usr"]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    assert!(!output.status.success(), "a directory is not a program");
    let text = stderr(&output);
    assert!(
        text.contains("not a regular file") && text.contains("`/usr`"),
        "the failure should name the payload: {text}"
    );
}

/// A program name with nothing in it is reported as one that was not found.
///
/// An empty name resolves to nothing, the same as any other name that
/// cannot be resolved.
#[test]
fn an_empty_program_name_is_not_found() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::new("empty-payload", &[""]);
    let output = bundle.runtime(&["run", &bundle.id()]);
    assert!(!output.status.success(), "an empty name names nothing");
    let text = stderr(&output);
    assert!(
        text.contains("not found"),
        "the failure should say the payload was not found: {text}"
    );
}

/// so the attribute belongs after everything below it exists.
#[test]
fn a_read_only_mount_takes_the_mounts_that_go_inside_it() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "read-only-dev",
        &[
            "/usr/bin/sh",
            "-c",
            "grep ' /dev ' /proc/self/mountinfo | cut -d' ' -f6; \
             grep -c ' /dev/pts ' /proc/self/mountinfo",
        ],
        |config| {
            *config = config.replace(
                r#""options": ["nosuid", "strictatime", "mode=755", "size=65536k"]"#,
                r#""options": ["nosuid", "strictatime", "mode=755", "size=65536k", "ro"]"#,
            );
        },
    );

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    let text = stdout(&output);
    let mut lines = text.lines();
    assert!(
        lines.next().is_some_and(|flags| flags.starts_with("ro")),
        "/dev should be read only: {text}"
    );
    assert_eq!(lines.next(), Some("1"), "/dev/pts should be mounted");
}

/// the directory at 0755 asked for.
#[test]
fn a_tmpfs_takes_the_mode_of_what_it_covers() {
    if !privileged() {
        return;
    }
    let bundle = Bundle::with_config(
        "tmpfs-mode",
        &["/usr/bin/stat", "-c%a", "/covered"],
        |config| {
            *config = config.replace(
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },"#,
                r#"    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/covered",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "nodev"]
    },"#,
            );
        },
    );
    let covered = bundle.path().join("rootfs").join("covered");
    std::fs::create_dir_all(&covered).expect("the directory to cover");
    std::fs::set_permissions(
        &covered,
        std::os::unix::fs::PermissionsExt::from_mode(0o750),
    )
    .expect("the mode to be taken");

    let output = bundle.runtime(&["run", &bundle.id()]);
    expect_ok("run", &output);
    assert_eq!(stdout(&output).trim(), "750");
}
