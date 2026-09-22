//! Handing the seccomp notify descriptor to the agent that asked for it.
//!
//! A profile with a notify action is only useful if something is listening:
//! the kernel suspends every matching syscall until an agent answers it. The
//! configuration names a unix socket, and the runtime is required to connect
//! to it and pass the descriptor the kernel gave it, along with enough state
//! for the agent to know which container it is answering for.
//!
//! Init cannot do this itself. By the time the filter is installed the
//! filesystem has been pivoted, so the socket's path is gone, and the process
//! ids it would report are the ones inside the container rather than the ones
//! the agent shares with the runtime.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use anyhow::{Context as _, Result, bail};

use crate::state::Record;

/// Sends the descriptor and the container's state to the agent.
pub fn deliver(
    path: &str,
    metadata: &str,
    record: &Record,
    listener: BorrowedFd<'_>,
) -> Result<()> {
    let socket = connect(path)?;
    let payload = payload(metadata, record);
    send(socket.as_fd(), payload.as_bytes(), listener)
        .with_context(|| format!("sending the seccomp listener to {path}"))
}

fn connect(path: &str) -> Result<OwnedFd> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect,
        socket_with,
    };

    let address = SocketAddrUnix::new(path).with_context(|| {
        format!("the seccomp listener path {path} is not usable")
    })?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("creating the seccomp agent socket")?;
    connect(socket.as_fd(), &address)
        .with_context(|| format!("connecting to the seccomp agent {path}"))?;
    Ok(socket)
}

/// The document the agent expects alongside the descriptor.
///
/// `fds` names the descriptors in the order they are attached, which is how
/// the agent knows which one is the listener.
fn payload(metadata: &str, record: &Record) -> String {
    let mut json = crate::json::Writer::new();
    json.object(None);
    json.string(Some("ociVersion"), &record.oci_version);
    json.string_array("fds", ["seccompFd"]);
    json.number(Some("pid"), i64::from(record.pid));
    json.string(Some("metadata"), metadata);
    // The state is an object in this document, not a string holding one. An
    // agent reads the whole payload into the structure the specification
    // defines, and a string where an object belongs fails that outright,
    // leaving every syscall the profile hands over suspended.
    json.document(
        Some("state"),
        &crate::state::render_public(record, crate::state::observe(record)),
    );
    json.end_object();
    json.finish()
}

fn send(
    socket: BorrowedFd<'_>,
    payload: &[u8],
    listener: BorrowedFd<'_>,
) -> Result<()> {
    use rustix::net::{
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg,
    };

    let mut space = [core::mem::MaybeUninit::<u8>::uninit(); 64];
    let mut buffer = SendAncillaryBuffer::new(&mut space);
    let fds = [listener];
    if !buffer.push(SendAncillaryMessage::ScmRights(&fds)) {
        bail!("no room to attach the seccomp listener");
    }
    let slices = [std::io::IoSlice::new(payload)];
    let sent = sendmsg(socket, &slices, &mut buffer, SendFlags::empty())
        .context("writing to the seccomp agent")?;
    if sent != payload.len() {
        bail!("the seccomp agent accepted only part of the message");
    }
    Ok(())
}
