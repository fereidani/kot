//! Diagnostics.
//!
//! A supervisor reads these, so they go to standard error by default and to a
//! file when the caller asks. The format is either one line per message or one
//! JSON object per message, because callers already parse both.

use std::{
    fs::File,
    io::Write as _,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

use crate::cli::{Global, Level, LogFormat};

/// Where messages go, once configured. Absent means standard error.
static SINK: OnceLock<Mutex<Option<File>>> = OnceLock::new();
/// How much to report, as a number so it can be read without a lock.
static LEVEL: AtomicU8 = AtomicU8::new(0);
/// Whether to render JSON.
static JSON: AtomicU8 = AtomicU8::new(0);

/// Points the log at wherever the caller asked for.
///
/// # Errors
///
/// When the target names something this runtime cannot write to. A caller
/// that asked for the diagnostics to go somewhere and silently got them
/// elsewhere has no way to find that out.
pub fn configure(global: &Global) -> anyhow::Result<()> {
    LEVEL.store(
        match global.level {
            Level::Error => 0,
            Level::Warning => 1,
            Level::Debug => 2,
        },
        Ordering::Relaxed,
    );
    JSON.store(
        u8::from(global.log_format == LogFormat::Json),
        Ordering::Relaxed,
    );

    let file = match global.log.as_deref() {
        None => None,
        Some(target) => Some(open_target(target)?),
    };
    let _ = SINK.set(Mutex::new(file));
    Ok(())
}

/// Opens what `--log` names, which is a path or a path behind a scheme.
///
/// Only one scheme is spoken: a file. Taking the whole string as a name
/// instead would quietly make a file called `journald:` in the current
/// directory.
fn open_target(target: &str) -> anyhow::Result<File> {
    let path = match target.split_once(':') {
        Some(("file", rest)) => rest,
        // A colon inside a file name is not a scheme; only one before the
        // first separator can be.
        Some((scheme, _)) if !scheme.is_empty() && !scheme.contains('/') => {
            anyhow::bail!(
                "--log names the {scheme} scheme, which this runtime does \
                 not write to; use a path or file:PATH"
            );
        }
        _ => target,
    };
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("opening the log file {path}: {e}"))
}

/// Renders a message as the one line a reader takes it for.
///
/// A message carries text from a configuration: a path, an identifier, a
/// name. A line break in any of those would end the line early and leave
/// what followed looking like a message of its own, which is how a log
/// reader is made to see something the runtime never said. The JSON form
/// escapes them itself, so this is only for the plain one.
fn one_line(message: &str) -> std::borrow::Cow<'_, str> {
    if !message.contains(|c: char| c.is_control()) {
        return std::borrow::Cow::Borrowed(message);
    }
    let escaped = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    std::borrow::Cow::Owned(escaped)
}

/// Reports a failure.
pub fn error(message: &str) {
    emit("error", message);
}

/// Reports something that might become a failure.
pub fn warn(message: &str) {
    if LEVEL.load(Ordering::Relaxed) >= 1 {
        emit("warning", message);
    }
}

/// Reports what the runtime is doing.
pub fn debug(message: &str) {
    if LEVEL.load(Ordering::Relaxed) >= 2 {
        emit("debug", message);
    }
}

fn emit(level: &str, message: &str) {
    let line = if JSON.load(Ordering::Relaxed) == 1 {
        let mut json = crate::json::Writer::new();
        json.object(None);
        json.string(Some("level"), level);
        json.string(Some("msg"), message);
        json.string(Some("time"), &crate::now());
        json.end_object();
        json.finish()
    } else {
        format!("{level}: {}\n", one_line(message))
    };

    if let Some(sink) = SINK.get() {
        if let Ok(mut sink) = sink.lock() {
            if let Some(file) = sink.as_mut() {
                let _ = file.write_all(line.as_bytes());
                return;
            }
        }
    }
    let _ = std::io::stderr().write_all(line.as_bytes());
}
