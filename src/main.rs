//! The runtime's entry point.
//!
//! Turns whatever a command returns into an exit code. Two conventions matter
//! to callers and are honoured exactly: `exec` exits with the status of the
//! process it ran, and a failure of `exec` itself exits with 255, which is
//! distinct from any status a payload can produce. Every other failure exits
//! with 1, so a supervisor can tell a runtime that could not do its job from
//! a payload that chose to exit with a high status.

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let code = match kot::run(&argv) {
        Ok(code) => code,
        Err(error) => {
            kot::log::error(&format!("{error:#}"));
            kot::failure_code(&argv)
        }
    };
    std::process::exit(code);
}
