//! What the commands print about a container.

// Tests assert rather than propagate: a failed assertion is the result being
// reported, so the crate's ban on panicking constructs does not apply here.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use kot::report::processes_in;

/// A listing from the host is the host's, and only the column of process ids
/// says which lines are the container's.
///
/// The parent id, the user id and the arguments are all numbers on the same
/// line. Matching any of them prints a process that is not in the container,
/// and with it the command line of whoever is running it.
#[test]
fn only_the_pid_column_decides_which_lines_belong() {
    let listing = "\
UID          PID    PPID  C STIME TTY          TIME CMD
root         900       1  0 10:00 ?        00:00:00 /usr/bin/in-container
root        4242     900  0 10:00 ?        00:00:00 /usr/bin/also-in
root        7000     900  0 10:00 ?        00:00:00 /usr/bin/child-of-900
1234        8000       1  0 10:00 ?        00:00:00 /usr/bin/uid-matches
root        9000    4242  0 10:00 ?        00:00:00 /usr/bin/ppid-matches
";
    let (header, lines) =
        processes_in(listing, &[900, 4242, 1234]).expect("a pid column");

    assert!(header.starts_with("UID"));
    let printed: Vec<&str> = lines
        .iter()
        .map(|line| line.rsplit('/').next().unwrap_or(line))
        .collect();
    assert_eq!(
        printed,
        vec!["in-container", "also-in"],
        "only the lines whose pid column matches belong"
    );
}

/// A listing with no column of process ids is not guessed at.
///
/// A caller can ask `ps` for any format, including one with no pid in it.
/// Picking lines out of that would be guesswork, so the caller is told to
/// report the ids it already knows instead.
#[test]
fn a_listing_without_a_pid_column_is_refused() {
    let listing = "USER COMMAND\nroot /usr/bin/something\n";
    assert!(processes_in(listing, &[900]).is_none());
    assert!(processes_in("", &[900]).is_none());
}

/// The column is found wherever the header puts it, and `PPID` is not it.
#[test]
fn the_pid_column_is_found_by_name() {
    let listing = "\
PPID PID CMD
900 4242 /usr/bin/wanted
4242 900 /usr/bin/also-wanted
7000 7001 /usr/bin/other
";
    let (_, lines) = processes_in(listing, &[4242]).expect("a pid column");
    assert_eq!(lines, vec!["900 4242 /usr/bin/wanted"]);
}
