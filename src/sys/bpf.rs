//! `bpf(2)`, used for the cgroup v2 device controller.
//!
//! Only three commands are wrapped: loading a program, attaching it to a
//! cgroup, and detaching it again.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use crate::sys::{
    error::{Error, Result},
    raw::{arg_ref, nr, ret_fd, ret_unit, syscall3},
};

/// `BPF_PROG_LOAD`
const PROG_LOAD: usize = 5;
/// `BPF_PROG_ATTACH`
const PROG_ATTACH: usize = 8;

/// `BPF_PROG_TYPE_CGROUP_DEVICE`
pub const PROG_TYPE_CGROUP_DEVICE: u32 = 15;
/// `BPF_CGROUP_DEVICE`
pub const ATTACH_TYPE_CGROUP_DEVICE: u32 = 6;
/// Allow several programs to be attached to one cgroup.
pub const F_ALLOW_MULTI: u32 = 2;

/// One eBPF instruction, matching `struct bpf_insn`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Insn {
    /// Opcode.
    pub code: u8,
    /// Destination register in the low nibble, source in the high nibble.
    pub regs: u8,
    /// Signed offset, used by jumps and memory access.
    pub off: i16,
    /// Immediate operand.
    pub imm: i32,
}

impl Insn {
    /// Builds an instruction from separate register numbers.
    #[must_use]
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (dst & 0x0f) | ((src & 0x0f) << 4),
            off,
            imm,
        }
    }
}

#[repr(C, align(8))]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
}

#[repr(C, align(8))]
#[derive(Default)]
struct AttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
    pad: u32,
}

/// Loads an eBPF program and returns its descriptor.
///
/// `log` receives the verifier's output when the load fails, which is the only
/// way to find out why. On success it is left untouched.
pub fn prog_load(
    prog_type: u32,
    insns: &[Insn],
    name: &str,
    log: &mut [u8],
) -> Result<OwnedFd> {
    const LICENSE: &[u8] = b"MIT\0";

    let insn_cnt =
        u32::try_from(insns.len()).map_err(|_| Error::msg("bpf: program"))?;
    // The kernel only accepts letters, digits, underscore and dot here, and
    // refuses the whole load for anything else, so an unusable character is
    // dropped rather than allowed to turn a working program into EINVAL.
    let mut prog_name = [0u8; 16];
    let mut written = 0usize;
    for byte in name.bytes() {
        if written + 1 >= prog_name.len() {
            break;
        }
        if !byte.is_ascii_alphanumeric() && byte != b'_' && byte != b'.' {
            continue;
        }
        if let Some(slot) = prog_name.get_mut(written) {
            *slot = byte;
            written += 1;
        }
    }

    let attr = ProgLoadAttr {
        prog_type,
        insn_cnt,
        insns: insns.as_ptr() as u64,
        license: LICENSE.as_ptr() as u64,
        log_level: u32::from(!log.is_empty()),
        log_size: u32::try_from(log.len()).unwrap_or(0),
        log_buf: if log.is_empty() {
            0
        } else {
            log.as_mut_ptr() as u64
        },
        prog_name,
        ..ProgLoadAttr::default()
    };

    // SAFETY: `attr` describes buffers that all outlive the call. The kernel
    // copies at most `size_of::<ProgLoadAttr>()` bytes and zero-fills the
    // remainder of its own larger union.
    let r = unsafe {
        syscall3(
            nr::BPF,
            PROG_LOAD,
            arg_ref(&attr),
            core::mem::size_of::<ProgLoadAttr>(),
        )
    };
    ret_fd(r, "bpf(PROG_LOAD)")
}

impl AttachAttr {
    /// Issues one of the commands that take a filled-in attach request.
    fn send(&self, op: usize, context: &'static str) -> Result<()> {
        let size = core::mem::size_of::<Self>();
        // SAFETY: `self` is a correctly shaped request of exactly `size`
        // bytes that outlives the call, and the descriptors it names are
        // valid for the duration.
        let r = unsafe { syscall3(nr::BPF, op, arg_ref(self), size) };
        ret_unit(r, context)
    }
}

/// Attaches a loaded program to a cgroup directory descriptor.
pub fn prog_attach(
    cgroup: BorrowedFd<'_>,
    prog: BorrowedFd<'_>,
    attach_type: u32,
    flags: u32,
) -> Result<()> {
    let attr = AttachAttr {
        target_fd: cgroup.as_raw_fd().unsigned_abs(),
        attach_bpf_fd: prog.as_raw_fd().unsigned_abs(),
        attach_type,
        attach_flags: flags,
        ..AttachAttr::default()
    };
    attr.send(PROG_ATTACH, "bpf(PROG_ATTACH)")
}
