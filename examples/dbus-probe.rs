//! Diagnostic: send one `StartTransientUnit` and print whatever comes back.
//!
//! Kept out of the test suite because its value is the raw reply, not a pass
//! or fail. Run with `cargo run --example dbus-probe`.

// A diagnostic, not production code: failing loudly at the first problem is
// the point, so the crate's ban on panicking constructs does not apply.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use std::{process::Command, time::Duration};

use kot::cgroup::dbus::{
    Connection,
    systemd::{self, Mode, Property},
};

fn main() {
    let mut connection = match Connection::open(None) {
        Ok(c) => c,
        Err(e) => {
            println!("connect failed: {e}");
            return;
        }
    };
    println!("connected, brokered={}", connection.is_brokered());

    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let name = format!("kot-probe-{}.scope", std::process::id());
    let pids = [child.id()];

    let serial = systemd::start_transient_unit(
        &mut connection,
        &name,
        Mode::Replace,
        &[
            Property::Str("Description", "kot probe"),
            Property::Bool("Delegate", true),
            Property::Bool("DefaultDependencies", false),
            Property::Pids("PIDs", &pids),
        ],
    )
    .expect("send");
    println!("sent serial {serial}");

    for round in 0..40 {
        std::thread::sleep(Duration::from_millis(50));
        match connection.poll() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                println!("poll failed: {e}");
                break;
            }
        }
        loop {
            let taken = connection.take_message(|header, body| {
                println!(
                    "round {round}: kind={} serial={} reply_to={:?} \
                     member={:?} error={:?} sig={:?} body={} bytes",
                    header.kind,
                    header.serial,
                    header.reply_serial,
                    header.member,
                    header.error_name,
                    header.signature,
                    body.len()
                );
                if header.error_name.is_some() {
                    println!("  error text: {}", String::from_utf8_lossy(body));
                }
                Ok(())
            });
            match taken {
                Ok(Some(())) => {}
                Ok(None) => break,
                Err(e) => {
                    println!("parse failed: {e}");
                    break;
                }
            }
        }
    }

    let path = format!("/sys/fs/cgroup/system.slice/{name}");
    println!("cgroup exists: {}", std::path::Path::new(&path).is_dir());
    let _ = child.kill();
    let _ = child.wait();
    let _ = Command::new("systemctl").args(["stop", &name]).output();
}
