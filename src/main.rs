//! The runtime's entry point.
//!
//! Turns whatever a command returns into an exit code. Two conventions matter
//! to callers and are honoured exactly: `exec` exits with the status of the
//! process it ran, and a failure of `exec` itself exits with 255, which is
//! distinct from any status a payload can produce. Every other failure exits
//! with 1, so a supervisor can tell a runtime that could not do its job from
//! a payload that chose to exit with a high status.
//!
//! The C entry point is taken over rather than left to the standard library.
//! What that startup does is worth about 21 syscalls: it reads
//! `/proc/self/maps` for the main thread's bounds, installs an alternate
//! stack and four handlers to name a stack overflow, and polls the standard
//! descriptors. A runtime that runs twice per container and lives for
//! milliseconds pays that twice and uses almost none of it. What it does
//! use is done by hand below: the standard descriptors are filled, `SIGPIPE`
//! is ignored, and what a command wrote is flushed before the process
//! leaves. A stack overflow is a plain `SIGSEGV` here rather than a named
//! one, which under `panic = "abort"` reads much the same.

#![no_main]

use std::{
    ffi::CStr,
    io::Write,
    os::fd::{BorrowedFd, IntoRawFd},
};

/// The entry point `libc` calls, in place of the one the standard library
/// would have wrapped.
///
/// Answers with the exit status rather than calling `exit`, so `libc` runs
/// what it registered at startup.
///
/// # Safety
///
/// `vector` must be an array of `count` pointers to C strings followed by a
/// null pointer, which is what the kernel and `libc` hand the entry point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(count: i32, vector: *const *const u8) -> i32 {
    open_standard_streams();
    ignore_broken_pipes();
    // SAFETY: the caller guarantees the array and its strings, and nothing
    // here keeps a borrow of them past the collect.
    let arguments = unsafe { collect(count, vector) };
    let code = match kot::run(&arguments) {
        Ok(code) => code,
        Err(error) => {
            kot::log::error(&format!("{error:#}"));
            kot::failure_code(&arguments)
        }
    };
    // The standard library flushes at the end of the main it wraps; this is
    // that flush. Commands that print a record leave the last line buffered
    // without it.
    if let Err(error) = std::io::stdout().flush() {
        kot::log::error(&format!("writing to standard output: {error}"));
        return kot::failure_code(&arguments);
    }
    code
}

/// Copies the arguments out of the array `libc` passed.
///
/// Anything that is not UTF-8 is carried through lossily rather than
/// dropped: an argument the runtime cannot read is still one a command has
/// to report as unknown.
///
/// # Safety
///
/// As for [`main`].
unsafe fn collect(count: i32, vector: *const *const u8) -> Vec<String> {
    let count = usize::try_from(count).unwrap_or(0);
    let mut arguments = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: `index` is below the count, so the pointer is one of the
        // array's own and points at a null-terminated string.
        let argument = unsafe {
            let pointer = *vector.add(index);
            if pointer.is_null() {
                break;
            }
            CStr::from_ptr(pointer.cast())
        };
        arguments.push(argument.to_string_lossy().into_owned());
    }
    arguments
}

/// Puts the null device on any standard descriptor the caller left closed.
///
/// The standard library does this before the main it wraps, and a runtime
/// has more use for it than most programs: a container is handed the three
/// numbers it was started with, and with one of them closed the first file
/// anything opens takes that number. The payload's output then goes into
/// whatever that file is.
fn open_standard_streams() {
    use rustix::{
        event::{PollFd, PollFlags, poll},
        fs::{Mode, OFlags, open},
    };

    // SAFETY: these numbers are the process's own standard descriptors,
    // whether or not they are open, and the borrows end with the poll.
    let borrowed = unsafe {
        [
            BorrowedFd::borrow_raw(0),
            BorrowedFd::borrow_raw(1),
            BorrowedFd::borrow_raw(2),
        ]
    };
    let mut fds = [
        PollFd::new(&borrowed[0], PollFlags::empty()),
        PollFd::new(&borrowed[1], PollFlags::empty()),
        PollFd::new(&borrowed[2], PollFlags::empty()),
    ];
    // No events are asked for, so the only answer wanted is whether each
    // number is a descriptor at all, and the call must not wait for one.
    let now = rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if poll(&mut fds, Some(&now)).is_err() {
        return;
    }
    // Ascending, so that a lower number is filled before the open that
    // needs the next one: an open takes the lowest descriptor free.
    for (number, fd) in fds.iter().enumerate() {
        if !fd.revents().contains(PollFlags::NVAL) {
            continue;
        }
        let Ok(null) = open(c"/dev/null", OFlags::RDWR, Mode::empty()) else {
            // There is nothing to report this on: the descriptor a report
            // would go to is the one missing.
            return;
        };
        let raw = null.into_raw_fd();
        let Ok(number) = i32::try_from(number) else {
            return;
        };
        if raw == number {
            continue;
        }
        // SAFETY: `raw` was just opened here and `number` is a standard
        // descriptor this process has established is closed.
        // SAFETY: as above for the copy; the original is this function's
        // own descriptor and nothing else refers to it.
        let moved = unsafe {
            let moved = kot::sys::process::dup3(raw, number, 0);
            rustix::io::close(raw);
            moved
        };
        if moved.is_err() {
            return;
        }
    }
}

/// Keeps a closed pipe from ending the process.
///
/// The standard library does this before the main it wraps, and for the same
/// reason: a runtime whose reader has gone away should see the write fail,
/// not die between two steps of taking a container apart.
fn ignore_broken_pipes() {
    /// `SIGPIPE`.
    const SIGPIPE: u32 = 13;

    if let Err(error) = kot::sys::signalfd::ignore(SIGPIPE) {
        kot::log::warn(&format!("ignoring broken pipes: {error}"));
    }
}
