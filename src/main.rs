//! The runtime's entry point.
//!
//! Turns whatever a command returns into an exit code. Two conventions matter
//! to callers and are honoured exactly: `exec` exits with the status of the
//! process it ran, and every other failure exits with 255, which is distinct
//! from any status a payload can produce.

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let code = match kot::run(&argv) {
        Ok(code) => code,
        Err(error) => {
            kot::log::error(&format!("{error:#}"));
            kot::FAILURE
        }
    };
    std::process::exit(code);
}
