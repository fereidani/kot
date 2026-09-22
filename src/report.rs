//! Rendering the reports the commands print.
//!
//! The text a caller sees is part of the interface, so the parts of it that
//! involve a decision live here rather than inline where they are printed.

/// Picks the lines of a process listing that belong to the container.
///
/// The process id is read from the column the header names, never from any
/// number that happens to appear on the line. A host process whose parent
/// id, user id or argument matches one of the container's ids is not in the
/// container, and printing it would attribute an unrelated command line, and
/// whatever is on it, to a container that never ran it.
///
/// Returns `None` when the listing has no column of process ids to read,
/// which happens when the caller asked for a format without one. Guessing
/// there is what this exists to avoid, so the caller reports the ids it knows
/// instead.
#[must_use]
pub fn processes_in<'a>(
    listing: &'a str,
    pids: &[i32],
) -> Option<(&'a str, Vec<&'a str>)> {
    let mut lines = listing.lines();
    let header = lines.next()?;
    let column = header
        .split_whitespace()
        .position(|field| field.eq_ignore_ascii_case("pid"))?;

    let mut selected = Vec::new();
    for line in lines {
        let pid = line
            .split_whitespace()
            .nth(column)
            .and_then(|field| field.parse::<i32>().ok());
        if pid.is_some_and(|pid| pids.contains(&pid)) {
            selected.push(line);
        }
    }
    Some((header, selected))
}
