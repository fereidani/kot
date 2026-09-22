//! The D-Bus client against the real systemd on this host.
//!
//! These settle the two measurements the systemd manager is built on: how long
//! a transient scope actually takes to create and to disappear, and whether
//! the runtime can learn the cgroup is ready without waiting for the job
//! completion signal that costs other runtimes 150 ms.
//!
//! Every test skips instead of failing when systemd is not reachable, so the
//! suite still runs in a container or on a host without it.

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

use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use kot::{
    cgroup::{
        Kind, Layout, Manager,
        dbus::{
            Connection,
            systemd::{self, Mode, Property},
        },
    },
    oci::spec::{BlockIo, Memory, Resources},
};

/// Where systemd puts transient scopes started by a system-level client.
const SLICE: &str = "/sys/fs/cgroup/system.slice";

/// Longest any of these operations may take before the test gives up.
const DEADLINE: Duration = Duration::from_secs(10);

/// Opens a connection, or reports why the test is skipping.
///
/// Reaching systemd is not enough: its job engine can stop dispatching while
/// the manager still answers queries, and in that state nothing can create a
/// scope, including `systemd-run` and every other container runtime. Probing
/// for that here means such a host skips with an explanation rather than
/// reporting a runtime regression that is not one.
fn connect() -> Option<Connection> {
    let connection = match Connection::open(None) {
        Ok(connection) => connection,
        Err(e) => {
            println!("skipping: cannot reach systemd: {e}");
            return None;
        }
    };
    if !dispatches_jobs() {
        println!(
            "skipping: systemd is reachable but its job engine is not \
             dispatching; `systemd-run --scope` would hang too"
        );
        return None;
    }
    Some(connection)
}

/// Creates a throwaway scope to see whether systemd still runs jobs.
///
/// Probed once and remembered: the answer cannot change during a test run, and
/// paying for it per test would add seconds to a suite that otherwise takes
/// milliseconds.
fn dispatches_jobs() -> bool {
    use std::sync::OnceLock;
    static ANSWER: OnceLock<bool> = OnceLock::new();
    *ANSWER.get_or_init(probe_job_engine)
}

fn probe_job_engine() -> bool {
    let Ok(mut connection) = Connection::open(None) else {
        return false;
    };
    let connection = &mut connection;
    let Some(mut victim) = Victim::spawn() else {
        return false;
    };
    let name = format!("kot-probe-{}.scope", std::process::id());
    let path = scope_path(&name);
    let pids = [victim.pid()];
    let sent = systemd::start_transient_unit(
        connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot probe"),
            Property::Bool("DefaultDependencies", false),
            Property::Pids("PIDs", &pids),
        ],
    );
    // A far shorter wait than the tests themselves use: a healthy systemd
    // answers in about ten milliseconds, and a wedged one never will.
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut works = sent.is_ok();
    while works && !path.is_dir() {
        if Instant::now() > deadline {
            works = false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let _ = victim.0.kill();
    let _ = victim.0.wait();
    if works {
        cleanup(&name);
    }
    works
}

/// A child process to put inside a scope, killed when the guard drops.
struct Victim(Child);

impl Victim {
    fn spawn() -> Option<Self> {
        Command::new("sleep").arg("120").spawn().ok().map(Self)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits for `predicate` to hold, returning how long it took.
fn wait_for(mut predicate: impl FnMut() -> bool) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        if predicate() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    None
}

fn scope_path(name: &str) -> PathBuf {
    Path::new(SLICE).join(name)
}

/// Removes a unit whatever state the test left it in.
fn cleanup(name: &str) {
    let _ = Command::new("systemctl").args(["stop", name]).output();
    let _ = Command::new("systemctl")
        .args(["reset-failed", name])
        .output();
}

/// The client must be able to create a transient scope containing a running
/// process, which is the whole of what the systemd cgroup manager needs.
#[test]
fn creates_a_transient_scope() {
    let Some(mut connection) = connect() else {
        return;
    };
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let name = format!("kot-test-create-{}.scope", std::process::id());
    let path = scope_path(&name);

    let pids = [victim.pid()];
    let serial = systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot test scope"),
            Property::Bool("Delegate", true),
            Property::Bool("DefaultDependencies", false),
            Property::Pids("PIDs", &pids),
        ],
    )
    .expect("StartTransientUnit");
    assert!(serial > 0);

    let appeared = wait_for(|| path.is_dir());
    assert!(
        appeared.is_some(),
        "scope cgroup never appeared at {path:?}"
    );

    let migrated = wait_for(|| {
        std::fs::read_to_string(path.join("cgroup.procs")).is_ok_and(|s| {
            s.split_whitespace().any(|p| p == victim.pid().to_string())
        })
    });
    assert!(migrated.is_some(), "process never joined the scope");

    println!(
        "scope appeared in {:.1} ms, process joined {:.1} ms after the call",
        appeared.unwrap_or_default().as_secs_f64() * 1e3,
        migrated.unwrap_or_default().as_secs_f64() * 1e3
    );
    cleanup(&name);
}

/// An empty scope is collected by systemd on its own, quickly, with no
/// `StopUnit` call at all.
///
/// Other runtimes call `StopUnit` and then block on the job completion
/// signal, which was measured at 150.6 ms. If this test shows collection
/// happening in a fraction of that, the blocking wait is pure cost.
#[test]
fn an_empty_scope_collects_itself() {
    let Some(mut connection) = connect() else {
        return;
    };
    let Some(mut victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let name = format!("kot-test-collect-{}.scope", std::process::id());
    let path = scope_path(&name);

    let pids = [victim.pid()];
    systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot test scope"),
            Property::Bool("Delegate", true),
            Property::Bool("DefaultDependencies", false),
            Property::Pids("PIDs", &pids),
        ],
    )
    .expect("StartTransientUnit");

    assert!(
        wait_for(|| path.is_dir()).is_some(),
        "scope cgroup never appeared"
    );

    let _ = victim.0.kill();
    let _ = victim.0.wait();

    let collected = wait_for(|| !path.is_dir());
    assert!(
        collected.is_some(),
        "systemd did not collect the empty scope on its own"
    );
    let ms = collected.unwrap_or_default().as_secs_f64() * 1e3;
    println!("empty scope collected in {ms:.1} ms with no StopUnit call");
    assert!(
        ms < 150.0,
        "self-collection at {ms:.1} ms must beat the 150.6 ms a blocking \
         StopUnit costs, or skipping the call is not worth it"
    );
    cleanup(&name);
}

/// Creating a scope must cost far less than the 185 ms a stock runtime spends
/// on the whole systemd path, since most of that is the teardown wait.
#[test]
fn scope_creation_is_the_smaller_half() {
    let Some(mut connection) = connect() else {
        return;
    };
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let name = format!("kot-test-timing-{}.scope", std::process::id());
    let path = scope_path(&name);

    let pids = [victim.pid()];
    let start = Instant::now();
    systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot test scope"),
            Property::Bool("Delegate", true),
            Property::Bool("DefaultDependencies", false),
            Property::Pids("PIDs", &pids),
        ],
    )
    .expect("StartTransientUnit");
    let sent = start.elapsed();

    let ready = wait_for(|| path.is_dir());
    assert!(ready.is_some(), "scope cgroup never appeared");
    let total = start.elapsed();

    println!(
        "call returned in {:.2} ms, cgroup usable {:.1} ms after the call",
        sent.as_secs_f64() * 1e3,
        total.as_secs_f64() * 1e3
    );
    assert!(
        sent < Duration::from_millis(5),
        "sending the call must not block; took {:.2} ms",
        sent.as_secs_f64() * 1e3
    );
    assert!(
        total < Duration::from_millis(100),
        "cgroup must be usable well inside the 185 ms budget; took {:.1} ms",
        total.as_secs_f64() * 1e3
    );
    cleanup(&name);
}

/// Resource limits have to reach systemd, or a container would run
/// unconstrained while appearing configured.
#[test]
fn resource_properties_are_applied() {
    let Some(mut connection) = connect() else {
        return;
    };
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let name = format!("kot-test-limits-{}.scope", std::process::id());
    let path = scope_path(&name);
    const LIMIT: u64 = 64 * 1024 * 1024;

    let pids = [victim.pid()];
    systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot test scope"),
            Property::Bool("Delegate", true),
            Property::Bool("DefaultDependencies", false),
            Property::U64("MemoryMax", LIMIT),
            Property::U64("TasksMax", 128),
            Property::Pids("PIDs", &pids),
        ],
    )
    .expect("StartTransientUnit");

    assert!(
        wait_for(|| path.is_dir()).is_some(),
        "scope cgroup never appeared"
    );
    let applied = wait_for(|| {
        std::fs::read_to_string(path.join("memory.max"))
            .is_ok_and(|s| s.trim() == LIMIT.to_string())
    });
    assert!(
        applied.is_some(),
        "memory.max was not set to {LIMIT}; got {:?}",
        std::fs::read_to_string(path.join("memory.max"))
    );
    cleanup(&name);
}

/// Every limit the manager hands to systemd has to arrive there.
///
/// The manager skips writing the cgroup files a transient unit's properties
/// cover. A limit listed as covered with no property sent for it is dropped
/// twice over, and the container runs unconstrained while reporting success.
#[test]
fn swap_and_block_io_limits_reach_the_unit() {
    if !rustix::process::geteuid().is_root() {
        println!("skipping: making a transient scope needs root");
        return;
    }
    if connect().is_none() {
        return;
    }
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    if Layout::detect().is_ok_and(Layout::has_legacy) {
        println!("skipping: the swap property is the unified hierarchy's");
        return;
    }

    const MEMORY: i64 = 64 * 1024 * 1024;
    const TOTAL: i64 = 96 * 1024 * 1024;
    const WEIGHT: u16 = 500;
    let resources = Resources {
        memory: Some(Memory {
            limit: Some(MEMORY),
            swap: Some(TOTAL),
            ..Memory::default()
        }),
        block_io: Some(BlockIo {
            weight: Some(WEIGHT),
            ..BlockIo::default()
        }),
        ..Resources::default()
    };

    let id = format!("limits-{}", std::process::id());
    let mut manager = Manager::new(Kind::Systemd, None, &id).expect("manager");
    let name = manager.unit().expect("a unit name").to_owned();
    let pid = i32::try_from(victim.pid()).expect("a pid");
    manager
        .begin_create(pid, Some(&resources))
        .expect("start the scope");
    manager.wait_ready().expect("wait for the scope");
    manager.apply(Some(&resources)).expect("apply the limits");

    // The configuration states memory and swap combined; the hierarchy and
    // systemd both count swap alone.
    let swap = (TOTAL - MEMORY).to_string();
    let file = scope_path(&name).join("memory.swap.max");
    let applied = wait_for(|| {
        std::fs::read_to_string(&file).is_ok_and(|text| text.trim() == swap)
    });
    assert!(
        applied.is_some(),
        "memory.swap.max was not set to {swap}; got {:?}",
        std::fs::read_to_string(&file)
    );

    // The weight reaches systemd as a property rather than as a file, so only
    // systemd's own view of the unit says whether it arrived.
    let shown = property_of(&name, "IOWeight");
    assert_eq!(
        shown,
        Some(kot::cgroup::v2::io_weight(WEIGHT).to_string()),
        "systemd did not record the block I/O weight"
    );

    let _ = manager.destroy();
    cleanup(&name);
}

/// A limit the configuration lifts has to be lifted on the unit too.
///
/// The specification spells no limit as a negative number. Saying nothing
/// about it instead leaves whatever is already in force, so an `update` that
/// removed a limit would report success and change nothing.
#[test]
fn a_lifted_limit_reaches_the_unit() {
    if !rustix::process::geteuid().is_root() {
        println!("skipping: making a transient scope needs root");
        return;
    }
    if connect().is_none() {
        return;
    }
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };

    const LIMIT: i64 = 64 * 1024 * 1024;
    let limited = Resources {
        memory: Some(Memory {
            limit: Some(LIMIT),
            ..Memory::default()
        }),
        ..Resources::default()
    };
    let lifted = Resources {
        memory: Some(Memory {
            limit: Some(-1),
            ..Memory::default()
        }),
        ..Resources::default()
    };

    let id = format!("lifted-{}", std::process::id());
    let mut manager = Manager::new(Kind::Systemd, None, &id).expect("manager");
    let name = manager.unit().expect("a unit name").to_owned();
    let pid = i32::try_from(victim.pid()).expect("a pid");
    manager
        .begin_create(pid, Some(&limited))
        .expect("start the scope");
    manager.wait_ready().expect("wait for the scope");
    manager.apply(Some(&limited)).expect("apply the limit");

    let file = scope_path(&name).join("memory.max");
    let applied = wait_for(|| {
        std::fs::read_to_string(&file)
            .is_ok_and(|text| text.trim() == LIMIT.to_string())
    });
    assert!(applied.is_some(), "the limit was never applied");

    manager.apply(Some(&lifted)).expect("lift the limit");
    let lifted_now = wait_for(|| {
        std::fs::read_to_string(&file).is_ok_and(|text| text.trim() == "max")
    });
    assert!(
        lifted_now.is_some(),
        "memory.max should be lifted; got {:?}",
        std::fs::read_to_string(&file)
    );

    let _ = manager.destroy();
    cleanup(&name);
}

/// What systemd reports for one property of a unit.
fn property_of(unit: &str, name: &str) -> Option<String> {
    let out = Command::new("systemctl")
        .args(["show", unit, "-p", name, "--value"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// A scope name already in use must be replaceable, or returning from `delete`
/// before systemd has finished would not be safe.
#[test]
fn a_scope_name_can_be_reused_immediately() {
    let Some(mut connection) = connect() else {
        return;
    };
    let name = format!("kot-test-reuse-{}.scope", std::process::id());
    let path = scope_path(&name);

    for round in 0..2 {
        let Some(mut victim) = Victim::spawn() else {
            println!("skipping: no sleep binary");
            return;
        };
        let pids = [victim.pid()];
        systemd::start_transient_unit(
            &mut connection,
            &name,
            Mode::Replace,
            &[
                Property::Str("Description", "kot test scope"),
                Property::Bool("Delegate", true),
                Property::Bool("DefaultDependencies", false),
                Property::Pids("PIDs", &pids),
            ],
        )
        .unwrap_or_else(|e| panic!("round {round}: {e}"));
        assert!(
            wait_for(|| path.is_dir()).is_some(),
            "round {round}: scope never appeared"
        );
        let _ = victim.0.kill();
        let _ = victim.0.wait();
        // Deliberately do not wait for collection: the next round has to
        // succeed against a name systemd may still be tearing down.
    }
    cleanup(&name);
}

/// A scope has to be looked for where the systemd that made it puts it.
///
/// The runtime used to reach only the system's own manager and to build the
/// path below `system.slice`. A rootless container's scope is made by the
/// caller's own manager, which hangs its units below its own service and puts
/// them in a different slice, so a container that started would then have been
/// waited for in a directory that never appears.
#[test]
fn a_scope_is_found_where_the_manager_that_made_it_puts_it() {
    let Some(connection) = connect() else {
        return;
    };
    let owner = connection.owner();
    drop(connection);

    let Some(mut victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let id = format!("found{}", std::process::id());
    let mut manager =
        Manager::new(Kind::Systemd, None, &id).expect("building a manager");
    manager
        .begin_create(i32::try_from(victim.pid()).expect("pid"), None)
        .expect("asking for the scope");
    let computed = manager.path().to_string();

    let ready = manager.wait_ready();
    // The directory appearing and the process arriving in it are two steps,
    // and only the second says where the scope really is.
    let cgroup_of = |pid: u32| {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .unwrap_or_default()
            .trim()
            .rsplit("::")
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let moved = wait_for(|| cgroup_of(victim.pid()).contains(&id));
    let actual = cgroup_of(victim.pid());

    let _ = manager.destroy();
    let _ = victim.0.kill();
    let _ = victim.0.wait();

    assert_eq!(
        computed, actual,
        "the runtime looked for the scope somewhere else than systemd made it \
         (owner {owner:?})"
    );
    assert!(
        ready.is_ok(),
        "the cgroup should have been found: {ready:?}"
    );
    assert!(moved.is_some(), "the process never joined a scope");
    let expected_user = owner.is_some();
    assert_eq!(
        computed.starts_with("/user.slice/"),
        expected_user,
        "a user manager's scope belongs below its own service: {computed}"
    );
}

/// A property an annotation names has to reach the unit.
///
/// An engine tells the runtime how the container should be stopped by naming
/// the systemd property, and a scope made without it is stopped some other
/// way than the one that was asked for.
#[test]
fn properties_named_by_annotations_reach_the_unit() {
    let Some(mut connection) = connect() else {
        return;
    };
    let Some(victim) = Victim::spawn() else {
        println!("skipping: no sleep binary");
        return;
    };
    let name = format!("kot-test-annotated-{}.scope", std::process::id());

    // The second is stated in seconds, which systemd takes in microseconds
    // under a name of its own.
    let annotations = [
        ("org.systemd.property.KillSignal", "5"),
        ("org.systemd.property.TimeoutStopSec", "uint64 7"),
    ];
    let named =
        kot::cgroup::unit::from_annotations(&annotations).expect("annotations");

    let pids = [victim.pid()];
    let mut properties = vec![
        Property::Str("Description", "kot test scope"),
        Property::Bool("Delegate", true),
        Property::Bool("DefaultDependencies", false),
        Property::Pids("PIDs", &pids),
    ];
    properties.extend(
        named
            .iter()
            .map(kot::cgroup::unit::UnitProperty::as_property),
    );
    systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &properties,
    )
    .expect("StartTransientUnit");

    assert!(
        wait_for(|| scope_path(&name).is_dir()).is_some(),
        "scope cgroup never appeared"
    );
    let shown = |property: &str| -> String {
        let output = Command::new("systemctl")
            .args(["show", "-p", property, &name])
            .output()
            .expect("systemctl show");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    assert_eq!(shown("KillSignal"), "KillSignal=5");
    assert_eq!(shown("TimeoutStopUSec"), "TimeoutStopUSec=7s");
    cleanup(&name);
}
