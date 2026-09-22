//! Reading a container's figures out of the cgroup, and reporting them.
//!
//! The parsers take the text of a cgroup file, so what a given kernel's
//! output turns into is checked here rather than by starting a container and
//! hoping the host keeps the figure being tested.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use kot::stats::{
    Cpu, Device, Memory, Pids, Stats, field, legacy_cpu, legacy_devices,
    number, render, unified_cpu, unified_devices,
};

/// The unified hierarchy counts microseconds and the report is nanoseconds.
///
/// A caller comparing two samples, or the same container across two hosts,
/// gets figures in one unit or gets nonsense.
#[test]
fn unified_processor_time_is_reported_in_nanoseconds() {
    let stat =
        "usage_usec 1234\nuser_usec 1000\nsystem_usec 234\nnr_periods 0\n";
    assert_eq!(
        unified_cpu(stat),
        Cpu {
            total: 1_234_000,
            kernel: 234_000,
            user: 1_000_000,
        }
    );
}

/// The legacy hierarchy keeps the total in nanoseconds already and the split
/// in clock ticks.
#[test]
fn legacy_processor_time_converts_its_ticks() {
    let cpu = legacy_cpu("1234000\n", "user 100\nsystem 23\n");
    assert_eq!(cpu.total, 1_234_000);
    assert_eq!(cpu.user, 1_000_000_000, "a hundred ticks is a second");
    assert_eq!(cpu.kernel, 230_000_000);
}

/// A figure the hierarchy does not keep reads as zero rather than failing.
#[test]
fn a_missing_figure_is_zero() {
    assert_eq!(field("user_usec 5\n", "nothing_like_this"), 0);
    assert_eq!(field("", "usage_usec"), 0);
    assert_eq!(number(""), 0);
    assert_eq!(number("not a number"), 0);
}

/// The kernel's word for no limit is not a limit of that many bytes.
#[test]
fn no_limit_is_not_a_number() {
    assert_eq!(number("max\n"), 0);
    assert_eq!(number("9223372036854775807\n"), 9_223_372_036_854_775_807);
}

/// The unified per-device counters are named on the line they appear in.
#[test]
fn unified_device_counters_are_read_by_name() {
    let text = "8:0 rbytes=1024 wbytes=2048 rios=4 wios=8 dbytes=0\n\
                259:0 wbytes=99 wios=1\n";
    let devices = unified_devices(text);
    assert_eq!(
        devices.first().copied(),
        Some(Device {
            major: 8,
            minor: 0,
            read_bytes: 1024,
            write_bytes: 2048,
            reads: 4,
            writes: 8,
        })
    );
    // A counter the kernel left out stays zero, and the rest still read.
    let second = devices.get(1).copied().expect("a second device");
    assert_eq!((second.major, second.minor), (259, 0));
    assert_eq!((second.write_bytes, second.writes), (99, 1));
    assert_eq!((second.read_bytes, second.reads), (0, 0));
}

/// The legacy figures come from two files and describe the same devices.
///
/// Folding them into one entry per device is what makes the two hierarchies
/// report the same shape.
#[test]
fn legacy_device_counters_come_from_two_files() {
    let bytes = "8:0 Read 1024\n8:0 Write 2048\n8:0 Sync 0\nTotal 3072\n";
    let operations = "8:0 Read 4\n8:0 Write 8\nTotal 12\n";
    let devices = legacy_devices(bytes, operations);

    assert_eq!(devices.len(), 1, "one device, not one line per counter");
    assert_eq!(
        devices.first().copied(),
        Some(Device {
            major: 8,
            minor: 0,
            read_bytes: 1024,
            write_bytes: 2048,
            reads: 4,
            writes: 8,
        })
    );
}

/// A sample is rendered as one document a supervisor can read per line.
#[test]
fn a_sample_renders_as_one_document() {
    let stats = Stats {
        cpu: Cpu {
            total: 10,
            kernel: 4,
            user: 6,
        },
        memory: Memory {
            usage: 100,
            limit: 1000,
            peak: 200,
            failures: 1,
            swap_usage: 5,
            swap_limit: 50,
        },
        pids: Pids {
            current: 3,
            limit: 100,
        },
        devices: vec![Device {
            major: 8,
            minor: 0,
            read_bytes: 1024,
            write_bytes: 2048,
            reads: 4,
            writes: 8,
        }],
        oom_kills: 0,
    };

    let text = render("stats", "abc", Some(&stats));
    assert_eq!(text.lines().count(), 1, "one line per event");

    // The envelope names the kind and the container, and the figures are
    // under the key a reader looks for.
    let arena = bumpalo::Bump::new();
    let mut parser = kot::oci::json::Parser::new(text.as_bytes(), &arena);
    let mut kind = None;
    let mut id = None;
    let mut saw_data = false;
    parser.enter_object().expect("an object");
    while let Some(key) = parser.next_key().expect("a key") {
        match key {
            "type" => kind = Some(parser.string().expect("text").to_owned()),
            "id" => id = Some(parser.string().expect("text").to_owned()),
            "data" => {
                saw_data = true;
                parser.skip_value().expect("the sample");
            }
            _ => parser.skip_value().expect("anything else"),
        }
    }
    assert_eq!(kind.as_deref(), Some("stats"));
    assert_eq!(id.as_deref(), Some("abc"));
    assert!(saw_data, "a sample carries its figures");

    for wanted in [
        "\"total\": 10",
        "\"usage\": 100",
        "\"limit\": 1000",
        "\"current\": 3",
        "\"major\": 8",
        "\"op\": \"Read\"",
    ] {
        assert!(text.contains(wanted), "{wanted} should be in: {text}");
    }
}

/// An out-of-memory event carries no sample, only what happened.
#[test]
fn an_out_of_memory_event_names_the_container() {
    let text = render("oom", "abc", None);
    assert!(text.contains("\"type\": \"oom\""));
    assert!(text.contains("\"id\": \"abc\""));
    assert!(!text.contains("data"), "there is no sample to carry");
}
