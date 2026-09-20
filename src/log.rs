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
pub fn configure(global: &Global) {
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

    let file = global.log.as_deref().and_then(|target| {
        // Other runtimes accept a `file:` prefix; a bare path means the same
        // thing.
        let path = target.strip_prefix("file:").unwrap_or(target);
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    });
    let _ = SINK.set(Mutex::new(file));
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
        format!("{level}: {message}\n")
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
