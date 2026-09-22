//! The fixed-size path buffer at the syscall boundary.
//!
//! Paths arrive from a container's configuration, so they are bytes rather
//! than text and the buffer has to say so without ever allocating.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use kot::sys::path::PathBuf;

/// A path that is not UTF-8 still renders, and renders the same way the
/// standard library's lossy conversion would.
///
/// The buffer writes the replacement itself rather than borrowing
/// `String::from_utf8_lossy`, which would allocate for exactly these paths.
/// Rendering has to stay identical for that to be an implementation detail.
#[test]
fn a_path_that_is_not_utf8_renders_losslessly() {
    let cases: [&[u8]; 7] = [
        b"/plain/path",
        b"/one\xffbad",
        b"/two\xff\xffbad",
        b"\xff",
        b"/cut/short/\xe2\x82",
        b"/mixed/\xc3\xa9/\xff/end",
        b"",
    ];
    for bytes in cases {
        let path = PathBuf::<64>::from(bytes).expect("a path buffer");
        assert_eq!(
            path.to_string(),
            String::from_utf8_lossy(bytes),
            "rendering {bytes:?} must match the lossy conversion"
        );
    }
}

/// A CPU list from the configuration has to become exactly the set it names.
///
/// The list is the only place a container says which processors it may use,
/// and a parser that dropped or widened a range would confine the payload to
/// something other than what was asked for.
#[test]
fn a_cpu_list_parses_into_the_set_it_names() {
    use kot::sys::process::CpuSet;

    let set = CpuSet::parse("0-3,8,10-11").expect("an ordinary list");
    for cpu in [0, 1, 2, 3, 8, 10, 11] {
        assert!(set.contains(cpu), "CPU {cpu} was named");
    }
    for cpu in [4, 7, 9, 12, 64, 1023] {
        assert!(!set.contains(cpu), "CPU {cpu} was not named");
    }

    // Whitespace and a single number are both ordinary forms.
    let single = CpuSet::parse(" 5 ").expect("one CPU is a list");
    assert!(single.contains(5));
    assert!(!single.contains(4));

    // A set that spans a word boundary must not lose the upper half.
    let wide = CpuSet::parse("63-64").expect("a range across a word");
    assert!(wide.contains(63) && wide.contains(64));
}

/// A list that names nothing usable is refused rather than applied in part.
#[test]
fn a_malformed_cpu_list_is_refused() {
    use kot::sys::process::{CpuSet, MAX_CPUS};

    for list in ["", "   ", ",", "3-1", "x", "1-", "-2", "1.5", "-"] {
        assert!(
            CpuSet::parse(list).is_err(),
            "the list {list:?} names no usable set"
        );
    }
    let beyond = format!("{MAX_CPUS}");
    assert!(
        CpuSet::parse(&beyond).is_err(),
        "a CPU the mask cannot hold must be refused, not dropped"
    );
}
