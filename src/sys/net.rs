//! The one piece of network configuration a runtime owes a container.
//!
//! A network namespace is created with a loopback device that is down, so a
//! container in one cannot reach itself until somebody brings it up. Nothing
//! else about networking belongs to a runtime: an address, a route or a
//! second interface is the engine's business, and the specification says so.

use std::os::fd::{AsFd as _, BorrowedFd};

use crate::sys::{
    error::{Context, Error, Result},
    raw::{arg_fd, arg_ref, nr, ret_unit, syscall3},
};

/// Read the flags of the interface an `ifreq` names.
const SIOCGIFFLAGS: usize = 0x8913;
/// Write them back.
const SIOCSIFFLAGS: usize = 0x8914;

/// The interface is up.
const IFF_UP: u16 = 0x1;
/// The interface has a carrier, which loopback always does.
const IFF_RUNNING: u16 = 0x40;

/// How many bytes an interface name may take, including its terminator.
const IF_NAME_SIZE: usize = 16;

/// The kernel's `struct ifreq`, as far as the flags request reads it.
///
/// The kernel takes a fixed-size structure whose second half is a union of
/// everything an interface request can carry. Only the flags are used here,
/// and the rest is the padding that keeps the size and alignment the kernel
/// expects.
#[repr(C, align(8))]
#[derive(Default)]
struct IfReq {
    name: [u8; IF_NAME_SIZE],
    flags: u16,
    padding: [u8; 22],
}

/// Brings the loopback device up in the caller's network namespace.
///
/// Only for a namespace this runtime created. A namespace the configuration
/// joined belongs to whoever made it, and its interfaces are in whatever
/// state that owner chose.
pub fn bring_up_loopback() -> Result<()> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socket_with};

    // Any socket will do: the request acts on the namespace the socket
    // belongs to, not on the protocol it speaks.
    let socket = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .context("network: open a socket for the loopback device")?;

    let mut request = IfReq::default();
    let name = b"lo";
    let Some(field) = request.name.get_mut(..name.len()) else {
        return Err(Error::msg("network: interface name does not fit"));
    };
    field.copy_from_slice(name);

    flags_request(socket.as_fd(), SIOCGIFFLAGS, &mut request)
        .context("network: read the loopback flags")?;
    request.flags |= IFF_UP | IFF_RUNNING;
    flags_request(socket.as_fd(), SIOCSIFFLAGS, &mut request)
        .context("network: bring the loopback device up")
}

/// Issues one interface-flags request.
fn flags_request(
    socket: BorrowedFd<'_>,
    request: usize,
    interface: &mut IfReq,
) -> Result<()> {
    // SAFETY: both requests read and write exactly one `ifreq`, which is
    // what is passed and which outlives the call.
    let r = unsafe {
        syscall3(nr::IOCTL, arg_fd(socket), request, arg_ref(interface))
    };
    ret_unit(r, "ioctl")
}
