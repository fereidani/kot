//! The D-Bus reader's handling of hostile input.
//!
//! The peer here is systemd, which is trusted, but the reader is the only
//! thing standing between a malformed reply and this process, so it has to
//! refuse rather than follow whatever the message describes.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use kot::cgroup::dbus::marshal;

/// A nested variant cannot be allowed to recurse as deep as the message is
/// long.
///
/// The inner signature of a variant comes from the message body, not from the
/// signature the reader started with, so a peer that keeps nesting variants
/// chooses the recursion depth. Without a limit the depth is bounded only by
/// the message size, which is a megabyte.
#[test]
fn deeply_nested_variants_are_refused() {
    // Each level is the signature "v" as a length byte, the character and a
    // terminator, then the next level. The innermost level is a single byte.
    const LEVELS: usize = 100;
    let body = nest(LEVELS);
    let mut reader = marshal::Reader::new(&body);
    let refused = reader.skip("v");
    assert_eq!(
        refused.map_err(kot::sys::error::Error::context),
        Err("dbus: nested too deeply"),
        "a variant nested {LEVELS} deep should be refused for its depth"
    );
}

/// Nesting within what the specification allows is still followed.
#[test]
fn nesting_the_specification_allows_still_reads() {
    // Thirty levels, comfortably inside the limit and deeper than anything
    // systemd sends.
    let body = nest(30);
    let mut reader = marshal::Reader::new(&body);
    assert!(reader.skip("v").is_ok(), "30 levels should still read");
}

/// A reply the runtime actually receives still reads.
#[test]
fn ordinary_nesting_still_reads() {
    // One variant holding a byte, which is the shape of every property value
    // systemd sends back.
    let body = nest(1);
    let mut reader = marshal::Reader::new(&body);
    assert!(reader.skip("v").is_ok(), "a plain variant should read");
}

/// Builds a value of `levels` nested variants wrapping a single byte.
///
/// The caller reads it with the signature "v", so the outermost variant is
/// described by that rather than by anything in the buffer.
fn nest(levels: usize) -> Vec<u8> {
    // The innermost variant declares a byte and carries it.
    let mut body = vec![1u8, b'y', 0u8, 42u8];
    for _ in 1..levels {
        let mut next = vec![1u8, b'v', 0u8];
        next.extend_from_slice(&body);
        body = next;
    }
    body
}

/// A string the body does not terminate has to be refused.
///
/// The length says where the value ends and the terminator says the same
/// thing again. A reader that steps over the terminator without looking at it
/// accepts a body whose length ran past its end, and hands out whatever
/// followed as though the peer had sent it.
#[test]
fn a_string_without_its_terminator_is_refused() {
    let mut truncated = vec![5u8, 0, 0, 0];
    truncated.extend_from_slice(b"hello");
    let mut reader = marshal::Reader::new(&truncated);
    assert_eq!(
        reader.string().map_err(kot::sys::error::Error::context),
        Err("dbus: unterminated string"),
        "a string running to the end of the body has no terminator"
    );

    let mut wrong = truncated.clone();
    wrong.push(b'!');
    let mut reader = marshal::Reader::new(&wrong);
    assert_eq!(
        reader.string().map_err(kot::sys::error::Error::context),
        Err("dbus: unterminated string"),
        "a terminator that is not zero means the length is wrong"
    );

    let mut whole = truncated;
    whole.push(0);
    let mut reader = marshal::Reader::new(&whole);
    assert_eq!(reader.string().ok(), Some("hello"), "a whole string reads");
}

/// The same for a signature, which counts its length in one byte.
#[test]
fn a_signature_without_its_terminator_is_refused() {
    let mut reader = marshal::Reader::new(&[1u8, b'y']);
    assert_eq!(
        reader.signature().map_err(kot::sys::error::Error::context),
        Err("dbus: unterminated signature")
    );
    let mut reader = marshal::Reader::new(&[1u8, b'y', 0]);
    assert_eq!(reader.signature().ok(), Some("y"));
}

/// An alignment the protocol never uses must not take the process with it.
///
/// The reader takes the alignment from the signature it is handed, and every
/// one D-Bus defines is one, two, four or eight. Zero is none of those, and
/// dividing by it would end the process and not merely the message. The writer
/// is held to the same rule by an assertion, since the alignments it uses are
/// the runtime's own choice rather than a peer's.
#[test]
fn a_zero_alignment_is_not_a_division() {
    let body = [1u8, 0, 0, 0, 2, 0, 0, 0];
    let mut reader = marshal::Reader::new(&body);
    assert!(reader.align(0).is_ok(), "aligning to nothing is nothing");
    assert_eq!(reader.u32().ok(), Some(1), "the reader keeps its place");
    assert!(reader.align(1).is_ok(), "aligning to one is nothing too");
    assert_eq!(reader.u32().ok(), Some(2), "and it still keeps it");
}

/// A document nested inside another stays a document.
///
/// The seccomp notify payload carries the container's state as an object.
/// Writing it as a string would produce a different document: the reader
/// would find text where the specification says there is a structure, and
/// the agent that cannot parse it leaves every handed-over syscall waiting.
#[test]
fn a_nested_document_is_not_escaped_into_a_string() {
    let mut inner = kot::json::Writer::new();
    inner.object(None);
    inner.string(Some("id"), "abc");
    inner.number(Some("pid"), 42);
    inner.end_object();
    let inner = inner.finish();

    let mut outer = kot::json::Writer::new();
    outer.object(None);
    outer.string(Some("metadata"), "");
    outer.document(Some("state"), &inner);
    outer.end_object();
    let text = outer.finish();

    assert!(
        !text.contains("\\\""),
        "a nested document must not be escaped, got: {text}"
    );

    // It has to parse back as a structure, which is the property the agent
    // depends on. The parser walks it rather than a substring search saying
    // the text merely looks right.
    let arena = bumpalo::Bump::new();
    let mut parser = kot::oci::json::Parser::new(text.as_bytes(), &arena);
    let mut found: Option<String> = None;
    parser.enter_object().expect("the payload is an object");
    while let Some(key) = parser.next_key().expect("a key") {
        if key != "state" {
            parser.skip_value().expect("skipping a value");
            continue;
        }
        parser
            .enter_object()
            .expect("the state is an object, not text");
        while let Some(field) = parser.next_key().expect("a key") {
            if field == "id" {
                found = Some(parser.string().expect("a string").to_owned());
            } else {
                parser.skip_value().expect("skipping a value");
            }
        }
    }
    assert_eq!(found.as_deref(), Some("abc"));
}
