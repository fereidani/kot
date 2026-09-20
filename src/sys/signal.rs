//! Signal numbers and the names callers spell them with.
//!
//! The runtime installs no asynchronous signal handlers, so nothing in it has
//! an async-signal-safety obligation. What it needs from signals is the name
//! table: `kill` takes whatever spelling the caller gave and resolves it to a
//! number.

/// Kill, which cannot be caught or blocked.
pub const SIGKILL: u32 = 9;

/// Resolves a signal name to its number.
///
/// Accepts `SIGTERM`, `TERM` and `15`, because callers pass all three.
#[must_use]
pub fn by_name(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return (1..=64).contains(&n).then_some(n);
    }
    // The rest of the name is matched without regard to case, so the prefix
    // is too: a caller writing `sigterm` means the same signal as `SIGTERM`.
    let bare = match name.get(..3) {
        Some(prefix) if prefix.eq_ignore_ascii_case("SIG") => {
            name.get(3..).unwrap_or(name)
        }
        _ => name,
    };
    let index = NAMES.iter().position(|n| n.eq_ignore_ascii_case(bare))?;
    u32::try_from(index + 1).ok()
}

/// Signal names the runtime accepts, indexed by signal number minus one.
const NAMES: [&str; 31] = [
    "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1",
    "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP",
    "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH",
    "IO", "PWR", "SYS",
];
