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

use kot::{
    cgroup::{
        Kind, Layout, Manager,
        devices::{self, Form},
        layout, manager, v2,
        write::Writes,
    },
    oci::spec::Memory,
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

/// A configured cgroup path must not be able to climb out of the hierarchy.
///
/// The path the configuration states is joined to the hierarchy root one
/// component at a time. A `..` among those components names the parent of the
/// node the caller meant, which is another container's cgroup or the root of
/// the tree, and every limit, device rule and process placement would be
/// applied there instead.
#[test]
fn a_cgroup_path_that_climbs_out_is_refused() {
    for relative in [
        "..",
        "../escape",
        "/kot/../../escape",
        "kot/./../../elsewhere",
        "/../sibling",
    ] {
        assert!(
            layout::controller_path(layout::ROOT, relative).is_err(),
            "{relative} leaves the hierarchy and must be refused"
        );
        assert!(
            layout::ensure_below(relative.as_bytes()).is_err(),
            "{relative} leaves the hierarchy and must be refused"
        );
    }
}

/// An ordinary path still resolves, and a leading separator is read as the
/// hierarchy root rather than as the filesystem root.
#[test]
fn an_ordinary_cgroup_path_is_joined_below_the_root() {
    for relative in ["/kot/abc", "kot/abc", "//kot//abc"] {
        let path = layout::controller_path(layout::ROOT, relative)
            .expect("an ordinary path resolves");
        assert_eq!(
            path.as_bytes(),
            b"/sys/fs/cgroup/kot/abc",
            "{relative} should land below the hierarchy root"
        );
    }
}

/// Builds the resources section of a configuration for the writer tests.
fn resources(unified: &str) -> String {
    format!(
        r#"{{
        "ociVersion": "1.0.0",
        "process": {{"args": ["/true"], "cwd": "/"}},
        "root": {{"path": "rootfs"}},
        "linux": {{
            "namespaces": [{{"type": "mount"}}],
            "resources": {{"unified": {unified}}}
        }}
    }}"#
    )
}

/// Lowers the unified section of a configuration, reporting refusal.
fn lower_unified(unified: &str) -> Result<(), ()> {
    let text = resources(unified);
    let arena = bumpalo::Bump::new();
    let spec = kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
    let linux = spec.linux.as_ref().expect("linux");
    let resources = linux.resources.as_ref().expect("resources");
    let mut writes = Writes::new();
    kot::cgroup::v2::lower(resources, &mut writes, v2::Bandwidth::default())
        .map_err(|_| ())
}

/// A `unified` key is an attribute name, never a path.
///
/// The keys arrive from the configuration unchanged and are opened relative
/// to the container's cgroup directory. An absolute one makes the kernel
/// ignore that directory, and a relative one with a separator walks out of
/// it, so a crafted configuration could write to another container's limits
/// or to a control file at the root of the tree.
#[test]
fn a_unified_key_that_is_a_path_is_refused() {
    for key in [
        "../../sys/fs/cgroup/cgroup.procs",
        "/sys/fs/cgroup/memory.max",
        "sub/memory.max",
        "",
    ] {
        let unified = format!(r#"{{"{key}": "0"}}"#);
        assert!(
            lower_unified(&unified).is_err(),
            "the key {key:?} is a path and must be refused"
        );
    }
}

/// An ordinary attribute name still reaches the writer.
#[test]
fn an_ordinary_unified_key_is_accepted() {
    lower_unified(r#"{"memory.high": "1000000"}"#)
        .expect("an attribute name is what the section is for");
}

/// Builds a memory section for the headroom tests.
fn memory_limits(
    limit: Option<i64>,
    swap: Option<i64>,
    checked: bool,
) -> Memory {
    Memory {
        limit,
        swap,
        check_before_update: checked.then_some(true),
        ..Memory::default()
    }
}

/// An update that would put the limit under current usage is refused.
///
/// Writing the lower limit would not fail: the kernel accepts it and then
/// reclaims, or kills the container when it cannot. A caller setting
/// `checkBeforeUpdate` has said it would rather the update fail.
#[test]
fn an_update_below_current_usage_is_refused() {
    let memory = memory_limits(Some(100), None, true);
    assert!(
        manager::memory_headroom(&memory, 200, 0, false).is_err(),
        "a limit of 100 with 200 in use would kill the container"
    );
    assert!(
        manager::memory_headroom(&memory, 100, 0, false).is_ok(),
        "a limit exactly at current usage is not over it"
    );
    assert!(manager::memory_headroom(&memory, 50, 0, false).is_ok());
}

/// Without the flag the update goes through, which is the default behaviour.
#[test]
fn an_unchecked_update_is_written_whatever_the_usage() {
    let memory = memory_limits(Some(100), None, false);
    manager::memory_headroom(&memory, 1 << 30, 0, false)
        .expect("nothing asked for the check");
}

/// The swap figure the configuration states is a total, and the usage it is
/// compared against has to be the same total.
///
/// The unified hierarchy counts memory and swap separately, so the total is
/// the sum. The legacy controller already keeps the combined figure.
#[test]
fn a_swap_update_is_compared_against_the_combined_usage() {
    let memory = memory_limits(None, Some(300), true);
    assert!(
        manager::memory_headroom(&memory, 200, 200, false).is_err(),
        "400 in use together is above a 300 total"
    );
    assert!(manager::memory_headroom(&memory, 100, 100, false).is_ok());

    // The legacy counter is the combined figure on its own.
    assert!(manager::memory_headroom(&memory, 200, 200, true).is_ok());
    assert!(manager::memory_headroom(&memory, 200, 400, true).is_err());
}

/// Lowers a `linux.resources` fragment and returns the value written to one
/// file, if any.
fn written(
    fragment: &str,
    file: &str,
    current: v2::Bandwidth,
) -> Option<String> {
    let text = format!(
        r#"{{
        "ociVersion": "1.0.0",
        "process": {{"args": ["/true"], "cwd": "/"}},
        "root": {{"path": "rootfs"}},
        "linux": {{
            "namespaces": [{{"type": "mount"}}],
            "resources": {fragment}
        }}
    }}"#
    );
    let arena = bumpalo::Bump::new();
    let spec = kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
    let linux = spec.linux.as_ref().expect("linux");
    let resources = linux.resources.as_ref().expect("resources");
    let mut writes = Writes::new();
    v2::lower(resources, &mut writes, current).expect("lower");
    writes.entries().iter().find_map(|entry| {
        (entry.file.as_bytes() == file.as_bytes()).then(|| {
            String::from_utf8(entry.value.as_bytes().to_vec())
                .expect("a rendered value is text")
        })
    })
}

/// Updating one half of the CPU bandwidth leaves the other half alone.
///
/// Quota and period share one file, so a write states both. Substituting the
/// kernel's default period for the one in force would change the fraction of
/// the machine a container gets while the caller was only asking to change
/// its quota.
#[test]
fn a_quota_update_keeps_the_period_in_force() {
    let current = v2::Bandwidth {
        quota: Some(50_000),
        period: Some(200_000),
    };
    assert_eq!(
        written(r#"{"cpu": {"quota": 80000}}"#, "cpu.max", current).as_deref(),
        Some("80000 200000"),
        "the period in force must survive a quota update"
    );
    assert_eq!(
        written(r#"{"cpu": {"period": 500000}}"#, "cpu.max", current)
            .as_deref(),
        Some("50000 500000"),
        "the quota in force must survive a period update"
    );
}

/// With nothing in force, the kernel's own default period is written.
///
/// This is the create path, where there is no previous value to keep.
#[test]
fn a_new_container_gets_the_default_period() {
    assert_eq!(
        written(
            r#"{"cpu": {"quota": 80000}}"#,
            "cpu.max",
            v2::Bandwidth::default()
        )
        .as_deref(),
        Some("80000 100000")
    );
}

/// A share of zero asks for no weight at all, so nothing is written.
///
/// The value is outside the range the controller accepts, and tooling emits
/// it to mean that the field is unset rather than zero.
#[test]
fn a_zero_cpu_share_writes_no_weight() {
    assert_eq!(
        written(
            r#"{"cpu": {"shares": 0}}"#,
            "cpu.weight",
            v2::Bandwidth::default()
        ),
        None,
        "a share of zero is not a weight"
    );
    assert!(
        written(
            r#"{"cpu": {"shares": 1024}}"#,
            "cpu.weight",
            v2::Bandwidth::default()
        )
        .is_some(),
        "an ordinary share still becomes a weight"
    );
}

/// Collects every value written to one file.
fn all_written(fragment: &str, file: &str) -> Vec<String> {
    let text = format!(
        r#"{{
        "ociVersion": "1.0.0",
        "process": {{"args": ["/true"], "cwd": "/"}},
        "root": {{"path": "rootfs"}},
        "linux": {{
            "namespaces": [{{"type": "mount"}}],
            "resources": {fragment}
        }}
    }}"#
    );
    let arena = bumpalo::Bump::new();
    let spec = kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
    let linux = spec.linux.as_ref().expect("linux");
    let resources = linux.resources.as_ref().expect("resources");
    let mut writes = Writes::new();
    v2::lower(resources, &mut writes, v2::Bandwidth::default()).expect("lower");
    writes
        .entries()
        .iter()
        .filter(|entry| entry.file.as_bytes() == file.as_bytes())
        .map(|entry| {
            String::from_utf8(entry.value.as_bytes().to_vec())
                .expect("a rendered value is text")
        })
        .collect()
}

/// A huge page limit has to bound reserved pages as well as faulted ones.
///
/// Pages taken through a reservation are counted against a second limit, so
/// a container reserving its pages up front would otherwise take more than
/// the configuration allows.
#[test]
fn a_hugepage_limit_bounds_the_reserved_pool_too() {
    let fragment = r#"{"hugepageLimits": [
        {"pageSize": "2MB", "limit": 4194304}
    ]}"#;
    assert_eq!(all_written(fragment, "hugetlb.2MB.max"), vec!["4194304"]);
    assert_eq!(
        all_written(fragment, "hugetlb.2MB.rsvd.max"),
        vec!["4194304"],
        "the reserved pool takes the same limit"
    );
}

/// A per-device block weight is written rather than refused.
///
/// The unified hierarchy takes per-device weights on their own lines in the
/// same file as the default one, so a configuration asking for them can be
/// honoured instead of stopping the container.
#[test]
fn a_per_device_block_weight_is_written() {
    let fragment = r#"{"blockIO": {
        "weight": 500,
        "weightDevice": [{"major": 8, "minor": 0, "weight": 300}]
    }}"#;
    let written = all_written(fragment, "io.weight");
    assert!(
        written.contains(&"default 5000".to_owned()),
        "the default weight is still written, got: {written:?}"
    );
    assert!(
        written.iter().any(|line| line == "8:0 3000"),
        "the per-device weight is written, got: {written:?}"
    );
}

/// Turning cgroup management off does not fail a container that states
/// limits, but the caller is told none of them are applied.
///
/// The choice is the caller's: they disabled the manager on the command
/// line, over a bundle they may not control, and the runtime should not
/// refuse a container for that. What it must not do is stay quiet.
#[test]
fn limits_with_no_cgroup_manager_still_start() {
    let arena = bumpalo::Bump::new();
    let text = r#"{
        "ociVersion": "1.0.0",
        "process": {"args": ["/true"], "cwd": "/"},
        "root": {"path": "rootfs"},
        "linux": {
            "namespaces": [{"type": "mount"}],
            "resources": {"pids": {"limit": 64}}
        }
    }"#;
    let spec = kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
    let linux = spec.linux.as_ref().expect("linux");
    let resources = linux.resources.as_ref().expect("resources");
    assert!(
        resources.are_requested(),
        "the caller has to be able to see that limits were stated"
    );

    let Ok(mut manager) = Manager::new(Kind::Disabled, None, "no-cgroups")
    else {
        println!("skipping: no cgroup hierarchy to detect");
        return;
    };
    manager
        .apply(Some(resources))
        .expect("a container is not refused for the caller's own choice");
}

/// A configuration that asks for no limits still runs without a manager.
#[test]
fn no_limits_needs_no_cgroup_manager() {
    let empty = kot::oci::spec::Resources::default();
    assert!(!empty.are_requested());

    let Ok(mut manager) = Manager::new(Kind::Disabled, None, "no-cgroups")
    else {
        println!("skipping: no cgroup hierarchy to detect");
        return;
    };
    manager.apply(Some(&empty)).expect("nothing was asked for");
}

/// Waiting for a systemd scope must not spend the wait burning processor.
///
/// The first turns are free, because a scope usually appears within a few
/// scheduling slots. After that each pause doubles to a bounded ceiling, so
/// an eleven millisecond round trip costs a handful of wakeups instead of
/// however many yields fit into it. That time was being taken from the
/// container being started.
#[test]
fn waiting_for_a_scope_backs_off() {
    use std::time::Duration;

    assert_eq!(manager::backoff(0), Duration::ZERO);
    assert_eq!(manager::backoff(7), Duration::ZERO, "the fast case is free");
    assert_eq!(manager::backoff(8), Duration::from_micros(50));
    assert_eq!(manager::backoff(9), Duration::from_micros(100));
    assert_eq!(manager::backoff(10), Duration::from_micros(200));

    let ceiling = Duration::from_millis(2);
    for turn in [16u32, 64, 1_000, 99_999] {
        assert_eq!(
            manager::backoff(turn),
            ceiling,
            "a pause must stay bounded, whatever the turn"
        );
    }

    // The whole wait has to fit the deadline in far fewer turns than the
    // loop allows, or the bound below it would be doing the work.
    let mut total = Duration::ZERO;
    let mut turns = 0u32;
    while total < Duration::from_secs(1) && turns < 100_000 {
        total += manager::backoff(turns);
        turns += 1;
    }
    assert!(
        turns < 1_000,
        "a second of waiting should cost well under a thousand wakeups, \
         took {turns}"
    );
}

/// A new cpuset directory is given the CPUs and memory nodes of the one
/// above it.
///
/// The controller refuses to take a process while either list is empty, and
/// the kernel does not fill them in: every level of a new path starts blank.
/// Without this a container on a host that merely has the cpuset controller
/// mounted cannot be placed in its own cgroup at all.
#[test]
fn a_new_cpuset_inherits_what_it_may_run_on() {
    let root =
        std::env::temp_dir().join(format!("kot-cpuset-{}", std::process::id()));
    let leaf = root.join("kot/abc");
    std::fs::create_dir_all(&leaf).expect("the tree");

    // The controller root names something; every level below it is blank,
    // which is how the kernel creates them.
    std::fs::write(root.join("cpuset.cpus"), "0-3\n").expect("cpus");
    std::fs::write(root.join("cpuset.mems"), "0\n").expect("mems");
    for level in [root.join("kot"), leaf.clone()] {
        std::fs::write(level.join("cpuset.cpus"), "").expect("cpus");
        std::fs::write(level.join("cpuset.mems"), "").expect("mems");
    }

    layout::seed_cpuset(&root.to_string_lossy(), "/kot/abc")
        .expect("seeding a fresh cpuset");

    for level in [root.join("kot"), leaf.clone()] {
        let cpus =
            std::fs::read_to_string(level.join("cpuset.cpus")).expect("cpus");
        let mems =
            std::fs::read_to_string(level.join("cpuset.mems")).expect("mems");
        assert_eq!(cpus, "0-3", "{} should have inherited", level.display());
        assert_eq!(mems, "0", "{} should have inherited", level.display());
    }

    // A level that already names something keeps it: a configuration asking
    // for a narrower set must not be widened back to its parent's.
    std::fs::write(leaf.join("cpuset.cpus"), "1\n").expect("cpus");
    layout::seed_cpuset(&root.to_string_lossy(), "/kot/abc")
        .expect("seeding again");
    let kept = std::fs::read_to_string(leaf.join("cpuset.cpus")).expect("cpus");
    assert_eq!(kept.trim(), "1", "an existing value is not overwritten");

    std::fs::remove_dir_all(&root).expect("cleaning up");
}

/// A block weight is written under whichever name the host has for it.
///
/// The controller names the file after the scheduler attached to the
/// device, so a host using the newer one has no `blkio.weight` at all and
/// the weight the configuration asked for would be written nowhere.
#[test]
fn a_legacy_block_weight_names_both_files() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "process": {"args": ["/true"], "cwd": "/"},
        "root": {"path": "rootfs"},
        "linux": {
            "namespaces": [{"type": "mount"}],
            "resources": {"blockIO": {"weight": 500}}
        }
    }"#;
    let arena = bumpalo::Bump::new();
    let spec = kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
    let linux = spec.linux.as_ref().expect("linux");
    let resources = linux.resources.as_ref().expect("resources");
    let mut writes = Writes::new();
    kot::cgroup::v1::lower(resources, &mut writes).expect("lower");

    let weight = writes
        .entries()
        .iter()
        .find(|entry| entry.file.as_bytes() == b"blkio.weight")
        .expect("the weight is written");
    let alias = weight.alias.as_ref().expect("a second name to try");
    assert_eq!(alias.as_bytes(), b"blkio.bfq.weight");
}

/// A section that is present but states nothing is not a limit.
///
/// Tooling writes `"memory": {}` where a template had a place for limits
/// and the caller set none. A container refused for that would be refused
/// for punctuation, and `--cgroup-manager disabled` would be unusable with
/// the configurations engines actually emit.
#[test]
fn an_empty_resources_section_asks_for_nothing() {
    let parse = |fragment: &str| -> bool {
        let text = format!(
            r#"{{
            "ociVersion": "1.0.0",
            "process": {{"args": ["/true"], "cwd": "/"}},
            "root": {{"path": "rootfs"}},
            "linux": {{
                "namespaces": [{{"type": "mount"}}],
                "resources": {fragment}
            }}
        }}"#
        );
        let arena = bumpalo::Bump::new();
        let spec =
            kot::oci::parse::spec(text.as_bytes(), &arena).expect("parse");
        let linux = spec.linux.as_ref().expect("linux");
        let resources = linux.resources.as_ref().expect("resources");
        resources.are_requested()
    };

    assert!(!parse("{}"), "nothing at all");
    assert!(!parse(r#"{"memory": {}, "cpu": {}, "blockIO": {}}"#));
    assert!(parse(r#"{"memory": {"limit": 1024}}"#), "a real limit");
    assert!(parse(r#"{"cpu": {"shares": 2}}"#));
    assert!(parse(r#"{"pids": {"limit": 1}}"#));
    assert!(
        parse(r#"{"devices": [{"allow": false, "access": "rwm"}]}"#),
        "a device rule is a restriction that needs a controller"
    );
}
