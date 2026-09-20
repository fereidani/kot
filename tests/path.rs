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
