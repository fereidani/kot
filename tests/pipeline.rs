//! Parsing and lowering a real `config.json`, end to end.
//!
//! The fixtures are what Podman actually generates, so these check the shape
//! of configuration the runtime will really see, not a reduced example.

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

use std::time::Instant;

use bumpalo::Bump;
use kot::oci::{
    lower::{self, Settings},
    parse,
    plan::{Section, View, process_flag},
};

const PODMAN: &str = include_str!("data/oci/podman-config.json");
const MINIMAL: &str = include_str!("data/oci/minimal-config.json");

fn settings() -> Settings {
    Settings {
        rootfs: "/var/lib/kot/rootfs".to_owned(),
        ..Settings::default()
    }
}

/// The realistic configuration has to parse into the shape we expect, field
/// for field, or lowering is working from the wrong input.
#[test]
fn podman_config_parses() {
    let arena = Bump::new();
    let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");

    assert_eq!(spec.version, "1.0.0");
    let process = spec.process.as_ref().expect("process");
    assert_eq!(process.args, vec!["/true"]);
    assert!(process.no_new_privileges);
    assert_eq!(process.rlimits.len(), 2);

    let capabilities = process.capabilities.as_ref().expect("capabilities");
    let bounding = capabilities.bounding.as_ref().expect("bounding");
    assert!(bounding.contains(&"CAP_CHOWN"));
    assert_eq!(bounding.len(), 14);

    let linux = spec.linux.as_ref().expect("linux");
    assert_eq!(linux.namespaces.len(), 6);
    assert_eq!(linux.masked_paths.len(), 10);
    assert_eq!(linux.readonly_paths.len(), 5);

    let seccomp = linux.seccomp.as_ref().expect("seccomp");
    assert_eq!(seccomp.default_action, "SCMP_ACT_ERRNO");
    assert_eq!(seccomp.architectures.len(), 3);
    assert_eq!(seccomp.syscalls.len(), 24);

    let resources = linux.resources.as_ref().expect("resources");
    assert_eq!(
        resources.memory.as_ref().and_then(|m| m.limit),
        Some(536_870_912)
    );
    assert_eq!(resources.pids_limit, Some(2048));
    assert_eq!(spec.mounts.len(), 7);
}

/// Everything the configuration asked for has to appear in the plan, because
/// a quietly dropped restriction is a security failure rather than a missing
/// feature.
#[test]
fn podman_config_lowers() {
    let arena = Bump::new();
    let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");

    let view = View::new(&lowered.arena).expect("view");
    let container = view.container().expect("container");
    let process = view.process().expect("process");

    assert_eq!(
        view.text(container.rootfs).expect("rootfs"),
        "/var/lib/kot/rootfs"
    );
    assert_ne!(container.clone_flags, 0, "namespaces are created at clone");
    assert_eq!(container.unshare_flags, 0, "nothing is joined");
    assert!(lowered.joins.is_empty());
    assert!(!lowered.forks_after_unshare);

    assert!(process.has(process_flag::NO_NEW_PRIVS));
    assert!(process.has(process_flag::HAS_CAPS));
    assert!(process.has(process_flag::HAS_SECCOMP));
    assert_ne!(process.cap_bounding, 0);
    assert_eq!(view.text(process.cwd).expect("cwd"), "/");

    assert_eq!(view.count(Section::Mounts), 7);
    assert_eq!(view.count(Section::Rlimits), 2);
    // Ten masked paths plus five read-only ones.
    assert_eq!(view.count(Section::Paths), 15);
    // Six default device nodes, none of which the fixture lists itself.
    assert_eq!(view.count(Section::Devices), 6);

    let seccomp = view.seccomp().expect("seccomp");
    assert!(!seccomp.is_empty(), "a filter must be present");
    assert_eq!(seccomp.len() % 8, 0, "instructions are eight bytes each");
    println!("filter: {} instructions", seccomp.len() / 8);

    let mut args = Vec::new();
    view.string_list(Section::Args, &mut args).expect("args");
    assert_eq!(args.len(), 1);
    assert_eq!(view.text(args[0]).expect("arg"), "/true");
}

/// The same configuration must always produce the same bytes, so a plan can be
/// compared against a reference.
#[test]
fn lowering_is_deterministic() {
    let arena = Bump::new();
    let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
    let mut first = lower::Scratch::new();
    let mut second = lower::Scratch::new();
    let a = lower::plan(&mut first, &spec, &settings()).expect("lower");
    let b = lower::plan(&mut second, &spec, &settings()).expect("lower");
    assert_eq!(a.arena, b.arena, "lowering must be deterministic");

    // A reused scratch buffer must give the same answer as a fresh one.
    let c = lower::plan(&mut first, &spec, &settings()).expect("lower");
    assert_eq!(a.arena, c.arena, "reuse must not change the plan");
}

/// A plan has to survive the round trip it will really make: bytes out of the
/// driver, bytes into init.
#[test]
fn a_plan_round_trips_through_bytes() {
    let arena = Bump::new();
    let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");

    // Copy the bytes, as writing them to a memory file and mapping them back
    // would, and check that every section still reads.
    let copied = lowered.arena.clone();
    let view = View::new(&copied).expect("view");

    let mut mounts = 0;
    view.mounts(|op| {
        assert!(!view.text(op.target).expect("target").is_empty());
        mounts += 1;
        Ok(())
    })
    .expect("walk mounts");
    assert_eq!(mounts, 7);

    let mut devices = 0;
    view.devices(|op| {
        assert!(view.text(op.path).expect("path").starts_with("/dev/"));
        devices += 1;
        Ok(())
    })
    .expect("walk devices");
    assert_eq!(devices, 6);

    let mut paths = 0;
    view.paths(|op| {
        assert!(op.path_action().is_some());
        paths += 1;
        Ok(())
    })
    .expect("walk paths");
    assert_eq!(paths, 15);
}

/// Every string in the plan must be reachable as a NUL-terminated string, so
/// init can hand a path to a syscall without copying it first.
#[test]
fn plan_strings_are_terminated() {
    let arena = Bump::new();
    let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");
    let view = View::new(&lowered.arena).expect("view");

    view.mounts(|op| {
        for reference in [op.source, op.target, op.fstype, op.data] {
            let text = view.text(reference).expect("text");
            let terminated = view.c_str(reference).expect("c_str");
            assert_eq!(terminated.to_bytes(), text.as_bytes());
        }
        Ok(())
    })
    .expect("walk mounts");
}

/// A key this runtime does not read must not decide whether the file parses.
///
/// Unknown fields are skipped for forward compatibility, and a number under
/// one of them follows the JSON grammar rather than the stricter rule the
/// fields this runtime reads are held to. Refusing a fraction, an exponent or
/// a value above `i64::MAX` there would fail a configuration written for a
/// later version of the specification, or for another runtime's extension.
#[test]
fn unknown_keys_may_hold_any_number() {
    for value in ["1.5", "-2.5e10", "1e400", "18446744073709551615", "0.0"] {
        let text = format!(
            "{{\"ociVersion\": \"1.0.0\", \"extension\": {value}, \
             \"process\": {{\"args\": [\"/true\"], \"cwd\": \"/\"}}}}"
        );
        let arena = Bump::new();
        let spec = parse::spec(text.as_bytes(), &arena)
            .unwrap_or_else(|e| panic!("{value} under an unknown key: {e}"));
        assert_eq!(spec.version, "1.0.0");
        let process = spec.process.as_ref().expect("process");
        assert_eq!(process.args, vec!["/true"]);
    }
}

/// A number that is not one must still fail, wherever it appears.
///
/// Skipping a value the runtime does not read is not licence to accept
/// anything: a document that is not JSON is not a document this runtime
/// should agree to start a container from.
#[test]
fn unknown_keys_do_not_excuse_a_malformed_number() {
    for value in ["1..2", "-", "1e", "01", "--1", "1.", ".5", "1e+"] {
        let text = format!(
            "{{\"ociVersion\": \"1.0.0\", \"extension\": {value}, \
             \"process\": {{\"args\": [\"/true\"], \"cwd\": \"/\"}}}}"
        );
        let arena = Bump::new();
        assert!(
            parse::spec(text.as_bytes(), &arena).is_err(),
            "{value} is not a JSON number and must be refused"
        );
    }
}

/// A number a field actually reads is still held to the stricter rule.
#[test]
fn a_field_that_is_read_still_refuses_a_fraction() {
    let text = "{\"ociVersion\": \"1.0.0\", \
                \"linux\": {\"resources\": {\"pids\": {\"limit\": 1.5}}}}";
    let arena = Bump::new();
    assert!(
        parse::spec(text.as_bytes(), &arena).is_err(),
        "a limit with a fraction must be refused rather than rounded"
    );
}

/// Parsing and lowering together are on the critical path of every container
/// start, so they get a budget like everything else.
#[test]
fn parse_and_lower_are_fast() {
    let mut scratch = lower::Scratch::new();
    let settings = settings();

    // Warm the buffers, since a runtime handling many containers reuses them.
    for _ in 0..8 {
        let arena = Bump::new();
        let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
        lower::plan(&mut scratch, &spec, &settings).expect("lower");
    }

    let mut best = f64::MAX;
    for _ in 0..64 {
        let arena = Bump::new();
        let start = Instant::now();
        let spec = parse::spec(PODMAN.as_bytes(), &arena).expect("parse");
        let lowered =
            lower::plan(&mut scratch, &spec, &settings).expect("lower");
        let elapsed = start.elapsed().as_secs_f64() * 1e6;
        std::hint::black_box(&lowered.arena);
        best = best.min(elapsed);
    }

    let budget = if cfg!(debug_assertions) {
        20_000.0
    } else {
        600.0
    };
    println!("parse and lower: {best:.1} us (budget {budget:.0} us)");
    assert!(
        best < budget,
        "parse and lower must stay under {budget:.0} us, took {best:.1} us"
    );
}

/// A configuration with no seccomp section still has to lower, and the plan
/// must say so rather than carrying an empty filter that would be installed.
#[test]
fn minimal_config_lowers_without_seccomp() {
    let arena = Bump::new();
    let spec = parse::spec(MINIMAL.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");
    let view = View::new(&lowered.arena).expect("view");
    let process = view.process().expect("process");

    assert!(!process.has(process_flag::HAS_SECCOMP));
    assert!(view.seccomp().expect("seccomp").is_empty());
}

/// Null is how tooling writes an optional field it did not set, and every
/// runtime has to read it as absent rather than as a value.
#[test]
fn null_fields_are_treated_as_absent() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "hostname": null,
        "process": {
            "args": ["/bin/sh"],
            "cwd": "/",
            "capabilities": null,
            "rlimits": null
        },
        "root": {"path": "rootfs"},
        "linux": {"namespaces": [{"type": "pid"}], "seccomp": null}
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    assert_eq!(spec.hostname, None);
    let process = spec.process.as_ref().expect("process");
    assert!(process.capabilities.is_none());
    assert!(process.rlimits.is_empty());
    assert!(spec.linux.as_ref().expect("linux").seccomp.is_none());
}

/// A configuration naming a platform this runtime does not implement has to be
/// refused, not silently half-applied.
#[test]
fn foreign_platform_sections_are_recorded() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "windows": {"layerFolders": ["C:\\layers"]},
        "root": {"path": "rootfs"}
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    assert_eq!(spec.foreign_platforms, vec!["windows"]);
}

/// Escapes have to survive, including the surrogate pairs that carry
/// characters outside the basic plane.
#[test]
fn string_escapes_are_expanded() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "hostname": "a\tb\u0041\u00e9\ud83d\ude00",
        "root": {"path": "rootfs"}
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    assert_eq!(spec.hostname, Some("a\tbAé😀"));
}

/// Adversarial input must be refused rather than misread.
#[test]
fn malformed_input_is_rejected() {
    let cases = [
        ("{", "unterminated object"),
        ("{\"a\"}", "missing colon"),
        ("{\"a\": }", "missing value"),
        ("{\"a\": \"unterminated", "unterminated string"),
        ("{\"a\": 1} trailing", "trailing content"),
        (
            "{\"ociVersion\": 1.5}",
            "fractional number for a string field",
        ),
        ("[]", "not an object"),
    ];
    for (text, why) in cases {
        let arena = Bump::new();
        assert!(
            parse::spec(text.as_bytes(), &arena).is_err(),
            "should have been rejected: {why}"
        );
    }
}

/// Nesting has to be bounded, or a hostile bundle could drive the parser into
/// the stack.
#[test]
fn deep_nesting_is_refused() {
    let mut text = String::from("{\"a\":");
    for _ in 0..4096 {
        text.push('[');
    }
    let arena = Bump::new();
    assert!(parse::spec(text.as_bytes(), &arena).is_err());
}

#[test]
fn the_recursive_mount_options_mirror_the_plain_ones() {
    use kot::oci::lower::tables::{Effect, mount_option};

    // Every recursive name is the plain one with an `r` in front, and the two
    // differ only in the flag that says how far the change reaches.
    for plain in [
        "ro",
        "rw",
        "suid",
        "nosuid",
        "dev",
        "nodev",
        "exec",
        "noexec",
        "diratime",
        "nodiratime",
        "symfollow",
        "nosymfollow",
    ] {
        let one = mount_option(plain);
        let all = mount_option(&format!("r{plain}"));
        match (one, all) {
            (
                Effect::Flag {
                    ms_set: a,
                    attr_set: b,
                    recursive: false,
                    ..
                },
                Effect::Flag {
                    ms_set: c,
                    attr_set: d,
                    recursive: true,
                    ..
                },
            ) => {
                assert_eq!((a, b), (c, d), "r{plain} should match {plain}");
            }
            other => panic!("r{plain} and {plain} disagree: {other:?}"),
        }
    }

    // Names that begin with `r` without being recursive anything.
    for name in ["ro", "rw", "relatime", "remount", "rbind", "rprivate"] {
        assert!(
            !matches!(mount_option(name), Effect::Data),
            "{name} should be recognised as itself"
        );
    }
    assert!(matches!(mount_option("rnonsense"), Effect::Data));
}

/// A literal multi-byte character next to an escape has to survive both.
///
/// The escaped and unescaped halves of a string travel different paths, and
/// only the escaped one produces characters. Copying the rest a byte at a time
/// would read each byte of a character as a character of its own.
#[test]
fn literal_characters_survive_alongside_escapes() {
    let text = r#"{
        "ociVersion": "1.0.0",
        "hostname": "café-café-\t-ü-ü",
        "root": {"path": "rootfs"}
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    assert_eq!(spec.hostname, Some("café-café-\t-ü-ü"));
}

/// A string that is not valid UTF-8 is refused rather than carried along.
#[test]
fn an_invalid_string_is_refused() {
    // 0xff cannot appear in UTF-8. The escape puts the string on the path
    // that builds a new buffer, which is where the check has to happen.
    let mut raw = br#"{"ociVersion":"1.0.0","hostname":"a\tb"#.to_vec();
    raw.push(0xff);
    raw.extend_from_slice(br#"","root":{"path":"rootfs"}}"#);
    let arena = Bump::new();
    assert!(
        parse::spec(&raw, &arena).is_err(),
        "a string that is not utf-8 should be refused"
    );
}

/// A mount that states its own id mapping has to reach the plan as a request
/// the driver can act on, and as a record naming which request is its own.
///
/// Before this was wired up the mapping was parsed, recorded, and then never
/// looked at again, so the container got the mount with the host's ownership
/// and nothing said so.
#[test]
fn an_id_mapped_mount_names_the_namespace_it_needs() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "mounts": [
        { "destination": "/plain", "type": "bind", "source": "/src",
          "options": ["rbind"] },
        { "destination": "/shifted", "type": "bind", "source": "/src",
          "options": ["rbind"],
          "uidMappings": [{ "containerID": 1000, "hostID": 0, "size": 1 }],
          "gidMappings": [{ "containerID": 1000, "hostID": 0, "size": 1 }] }
      ]
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");

    assert_eq!(lowered.idmaps.len(), 1, "one mount asked for a mapping");
    let request = lowered.idmaps.first().expect("the request");
    assert_eq!(request.uid_ranges.len(), 1);
    assert_eq!(request.gid_ranges.len(), 1);
    assert_eq!(request.uid_ranges[0].container_id, 1000);
    assert_eq!(request.uid_ranges[0].host_id, 0);
    assert_eq!(request.gid_ranges[0].container_id, 1000);

    let view = View::new(&lowered.arena).expect("view");
    let mut seen = Vec::new();
    view.mounts(|op| {
        seen.push((
            view.text(op.target).expect("target").to_owned(),
            op.idmap_fd,
        ));
        Ok(())
    })
    .expect("walk mounts");
    assert_eq!(
        seen,
        vec![("/plain".to_owned(), -1), ("/shifted".to_owned(), 0)],
        "only the mapped mount names a request, by its position"
    );
}

/// `tmpcopyup` carries a directory's contents into the filesystem covering it,
/// so asking for it anywhere else describes something that cannot happen.
#[test]
fn tmpcopyup_outside_a_tmpfs_is_refused() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "mounts": [
        { "destination": "/here", "type": "bind", "source": "/src",
          "options": ["rbind", "tmpcopyup"] }
      ]
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    assert!(
        lower::plan(&mut scratch, &spec, &settings()).is_err(),
        "tmpcopyup on a bind should be refused rather than dropped"
    );
}

/// The same for `copy-symlink`, which describes what to do with a bind's
/// source and means nothing without one.
#[test]
fn copy_symlink_outside_a_bind_is_refused() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "mounts": [
        { "destination": "/here", "type": "tmpfs", "source": "tmpfs",
          "options": ["copy-symlink"] }
      ]
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    assert!(
        lower::plan(&mut scratch, &spec, &settings()).is_err(),
        "copy-symlink on a filesystem mount should be refused"
    );
}

/// An execution domain flag has to reach the plan.
///
/// The domain was lowered and the flags beside it were parsed and then
/// dropped, so a container that asked for a fixed address space layout got an
/// ordinary randomised one and nothing said so.
#[test]
fn a_personality_flag_reaches_the_plan() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "process": { "args": ["/bin/sh"], "cwd": "/" },
      "linux": {
        "personality": { "domain": "LINUX", "flags": ["ADDR_NO_RANDOMIZE"] }
      }
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");
    let view = View::new(&lowered.arena).expect("view");
    let process = view.process().expect("process");

    assert!(process.has(process_flag::HAS_PERSONALITY));
    assert_eq!(
        process.personality & 0x0004_0000,
        0x0004_0000,
        "ADDR_NO_RANDOMIZE should be part of the domain word"
    );
}

/// A flag the runtime cannot honour is refused while the message is still
/// worth reading.
#[test]
fn an_unknown_personality_flag_is_refused() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "process": { "args": ["/bin/sh"], "cwd": "/" },
      "linux": {
        "personality": { "domain": "LINUX", "flags": ["ADDR_COMPAT_LAYOUT"] }
      }
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    assert!(
        lower::plan(&mut scratch, &spec, &settings()).is_err(),
        "an unimplemented personality flag should be refused"
    );
}

/// `mountLabel` has to reach the mounts that can carry it.
///
/// It used to be parsed, interned into the plan, and then never applied, so a
/// container's mounts kept whatever the host's policy gave them and nothing
/// reported that the label had gone nowhere.
#[test]
fn a_mount_label_reaches_the_mounts_that_take_one() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "linux": {
        "mountLabel": "system_u:object_r:container_file_t:s0:c1,c2",
        "namespaces": [{ "type": "mount" }]
      },
      "mounts": [
        { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" },
        { "destination": "/proc", "type": "proc", "source": "proc" },
        { "destination": "/bound", "type": "bind", "source": "/src",
          "options": ["rbind"] },
        { "destination": "/own", "type": "tmpfs", "source": "tmpfs",
          "options": ["context=\"system_u:object_r:tmp_t:s0\""] }
      ]
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");
    let view = View::new(&lowered.arena).expect("view");

    let mut seen = Vec::new();
    view.mounts(|op| {
        seen.push((
            view.text(op.target).expect("target").to_owned(),
            view.text(op.context).expect("context").to_owned(),
        ));
        Ok(())
    })
    .expect("walk mounts");

    let label = "system_u:object_r:container_file_t:s0:c1,c2";
    assert_eq!(
        seen,
        vec![
            ("/tmp".to_owned(), label.to_owned()),
            // The kernel labels these from its own policy and refuses a
            // context outright.
            ("/proc".to_owned(), String::new()),
            // A bind takes the label of the filesystem it came from.
            ("/bound".to_owned(), String::new()),
            // The bundle named one itself, which wins.
            ("/own".to_owned(), String::new()),
        ],
        "the label should reach exactly the mounts that can carry it"
    );
}

/// A label that would end its own quoted option early is refused, because the
/// older mount interface passes it inside quotes.
#[test]
fn a_mount_label_with_a_quote_is_refused() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "linux": { "mountLabel": "system_u:object_r:\"broken\":s0" },
      "mounts": [
        { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" }
      ]
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    assert!(
        lower::plan(&mut scratch, &spec, &settings()).is_err(),
        "a label carrying a quote should be refused"
    );
}

/// Every flag the runtime reports as known has to be one it accepts.
///
/// `SECCOMP_FILTER_FLAG_TSYNC_ESRCH` had a constant and no token, so a profile
/// naming it was refused outright and the container never started. Both sides
/// now come from one table, which is what keeps them from drifting again.
#[test]
fn every_known_seccomp_flag_is_accepted() {
    for (name, bit) in kot::seccomp::FLAGS {
        let mut flags = kot::seccomp::Flags::empty();
        assert!(flags.add(name), "{name} is reported known but refused");
        assert_eq!(flags.bits(), bit, "{name} resolved to the wrong bit");
    }
}

/// A flag the runtime does not implement is still refused, because quietly
/// dropping a hardening flag is worse than failing to start.
#[test]
fn an_unknown_seccomp_flag_is_refused() {
    let mut flags = kot::seccomp::Flags::empty();
    assert!(!flags.add("SECCOMP_FILTER_FLAG_MADE_UP"));
    assert!(
        !flags.add("SECCOMP_FILTER_FLAG_NEW_LISTENER"),
        "the runtime adds the listener itself, so a profile may not ask"
    );
    assert_eq!(flags.bits(), 0);
}

/// A profile naming the flag has to lower, which is the whole of the bug.
#[test]
fn a_profile_may_ask_for_tsync_esrch() {
    let text = r#"{
      "ociVersion": "1.0.2",
      "root": { "path": "rootfs" },
      "process": { "args": ["/bin/sh"], "cwd": "/" },
      "linux": {
        "seccomp": {
          "defaultAction": "SCMP_ACT_ALLOW",
          "flags": [
            "SECCOMP_FILTER_FLAG_TSYNC",
            "SECCOMP_FILTER_FLAG_TSYNC_ESRCH"
          ]
        }
      }
    }"#;
    let arena = Bump::new();
    let spec = parse::spec(text.as_bytes(), &arena).expect("parse");
    let mut scratch = lower::Scratch::new();
    let lowered = lower::plan(&mut scratch, &spec, &settings()).expect("lower");
    let view = View::new(&lowered.arena).expect("view");
    let process = view.process().expect("process");

    let wanted =
        kot::sys::seccomp::FLAG_TSYNC | kot::sys::seccomp::FLAG_TSYNC_ESRCH;
    assert_eq!(
        process.seccomp_flags & wanted,
        wanted,
        "both flags should reach the plan"
    );
}
