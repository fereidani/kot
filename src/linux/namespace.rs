//! Entering and creating namespaces.
//!
//! Two orderings matter and neither is negotiable. A joined user namespace has
//! to be entered before anything else, because it decides what the process is
//! allowed to do afterwards; a joined mount namespace has to be entered last,
//! because entering it changes what every path means. The plan already sorts
//! the list that way, so this module applies it rather than deciding it.

use std::os::fd::{BorrowedFd, OwnedFd};

use crate::{
    linux::handoff::Slot,
    oci::plan::{Section, View, record::IdRange},
    sys::{
        clone::{CLONE_NEWPID, CLONE_NEWUSER},
        error::{Context, Error, Result},
        path::{Path, PathBuf},
        process::setns,
    },
};

/// Enters every namespace the plan says to join.
///
/// The descriptors were opened by the driver, which still had the privilege to
/// reach them, and handed over by number.
pub fn join(plan: &View<'_>) -> Result<bool> {
    let count = plan.count(Section::Namespaces) as usize;
    let mut index = 0usize;
    let mut joined_pid = false;
    plan.namespaces(|op| {
        if op.fd_index < 0 {
            return Ok(());
        }
        let number = Slot::namespace(index);
        index += 1;
        joined_pid |= op.clone_flag == CLONE_NEWPID;
        // SAFETY: the driver placed this descriptor at exactly this number
        // before the re-execution, and nothing has closed it since.
        let fd = unsafe { BorrowedFd::borrow_raw(number) };
        setns(fd, op.clone_flag)
    })?;
    debug_assert!(index <= count, "joined no more namespaces than planned");
    Ok(joined_pid)
}

/// Creates the namespaces that could not be made at clone time.
///
/// Returns true when a pid namespace was among them, which means the caller
/// has to fork once more: `unshare` puts the caller's *children* in the new
/// pid namespace, not the caller.
pub fn unshare(flags: u64) -> Result<bool> {
    use rustix::thread::{UnshareFlags, unshare_unsafe};

    if flags == 0 {
        return Ok(false);
    }
    let bits = u32::try_from(flags & 0xffff_ffff)
        .map_err(|_| Error::msg("namespace: flags out of range"))?;
    // SAFETY: this runs in the container init process, which is
    // single-threaded and has just been executed from a sealed image, so
    // nothing else in it can observe the namespace change half applied.
    unsafe { unshare_unsafe(UnshareFlags::from_bits_retain(bits)) }
        .context("namespace: unshare")?;
    Ok(flags & CLONE_NEWPID != 0)
}

/// Whether a container ends up in a user namespace the runtime created.
#[must_use]
pub const fn creates_user_namespace(
    clone_flags: u64,
    unshare_flags: u64,
) -> bool {
    (clone_flags | unshare_flags) & CLONE_NEWUSER != 0
}

/// Writes the id mapping files for a process in a new user namespace.
///
/// The process cannot write these itself: the kernel requires the writer to
/// hold privilege in the *parent* namespace, which is exactly what the process
/// gave up by entering the new one. That is why this runs in the driver.
pub fn write_id_maps(plan: &View<'_>, pid: i32) -> Result<()> {
    if plan.count(Section::UidMap) == 0 && plan.count(Section::GidMap) == 0 {
        return Ok(());
    }
    // The kernel refuses a gid map from a process that could still call
    // `setgroups`, unless it holds `CAP_SETGID` outside the namespace. Denying
    // it first is how an unprivileged mapping becomes possible at all.
    let _ = write_proc(pid, "setgroups", b"deny");

    write_map(plan, pid, Section::UidMap, "uid_map")?;
    write_map(plan, pid, Section::GidMap, "gid_map")
}

fn write_map(
    plan: &View<'_>,
    pid: i32,
    section: Section,
    file: &str,
) -> Result<()> {
    if plan.count(section) == 0 {
        return Ok(());
    }
    // The whole mapping has to go in one write: the kernel takes the file as a
    // single record and rejects a partial one.
    let mut body = Path::new();
    plan.id_map(section, |range: IdRange| append_range(&mut body, range))?;
    write_proc(pid, file, body.as_bytes())
}

/// Renders one mapping line into the buffer the whole map is written from.
fn append_range(body: &mut Path, range: IdRange) -> Result<()> {
    body.push_u64(u64::from(range.container_id))?;
    body.push_str(" ")?;
    body.push_u64(u64::from(range.host_id))?;
    body.push_str(" ")?;
    body.push_u64(u64::from(range.size))?;
    body.push_str("\n")
}

/// Builds a user namespace carrying `uid` and `gid`, for an id-mapped mount.
///
/// A mount takes its mapping from a user namespace rather than from a table,
/// so one has to exist before the mount can be made. Nothing is going to live
/// in this namespace: it is created only to be named by a descriptor, applied
/// to the mount, and dropped.
///
/// The mapping files cannot be written by a process already inside the
/// namespace, so a child is put there and the driver writes them from outside,
/// exactly as it does for the container's own namespace. The child waits on a
/// pipe it never receives anything through; closing the driver's end is what
/// tells it to go.
///
/// Runs in the driver, before the container's own process exists.
pub fn id_mapped(uid: &[IdRange], gid: &[IdRange]) -> Result<OwnedFd> {
    use rustix::{
        io::{read, retry_on_intr},
        pipe::pipe,
    };

    use crate::sys::clone::{CloneSpec, Fork};

    if uid.is_empty() && gid.is_empty() {
        return Err(Error::msg("namespace: id mapping has no ranges"));
    }

    let (wait, release) = pipe().context("namespace: id map pipe")?;
    let spec = CloneSpec::new().namespaces(CLONE_NEWUSER);
    // SAFETY: the driver is single-threaded at this point, so the child
    // inherits nothing another thread could have left inconsistent.
    match unsafe { spec.spawn() }? {
        Fork::Child => {
            drop(release);
            let mut byte = [0u8; 1];
            // The read ends when the driver drops its end, which it does once
            // it has the descriptor. Nothing is ever sent.
            let _ = retry_on_intr(|| read(&wait, &mut byte));
            std::process::exit(0);
        }
        Fork::Parent(pid) => {
            drop(wait);
            let outcome = map_child(pid, uid, gid);
            // Releasing before reaping, so the child is already on its way out
            // by the time the wait begins.
            drop(release);
            reap(pid);
            outcome
        }
    }
}

/// Writes a child's mapping files and takes a descriptor for its namespace.
fn map_child(pid: i32, uid: &[IdRange], gid: &[IdRange]) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, open};

    // As for the container's own namespace, the gid map needs `setgroups`
    // denied first unless the driver holds `CAP_SETGID` outside it.
    let _ = write_proc(pid, "setgroups", b"deny");
    for (ranges, file) in [(uid, "uid_map"), (gid, "gid_map")] {
        if ranges.is_empty() {
            continue;
        }
        let mut body = Path::new();
        for range in ranges {
            // A mount's mapping runs the other way round from a container's.
            // The kernel reads a file's on-disk id as an id inside this
            // namespace and shows what it maps to, so the id the
            // specification calls the host's is the one on the inside here.
            append_range(
                &mut body,
                IdRange {
                    container_id: range.host_id,
                    host_id: range.container_id,
                    size: range.size,
                },
            )?;
        }
        write_proc(pid, file, body.as_bytes())?;
    }

    let mut path = Path::new();
    path.push_str("/proc/")?;
    path.push_i64(i64::from(pid))?;
    path.push_str("/ns/user")?;
    open(
        path.as_c_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("namespace: open id mapping namespace")
}

/// Collects the child that carried a mapping namespace.
fn reap(pid: i32) {
    use rustix::process::{Pid, WaitOptions, kill_process, waitpid};

    let Some(pid) = Pid::from_raw(pid) else {
        return;
    };
    // Bounded: only an interrupted wait repeats, and the child is already
    // exiting or has been killed.
    for _ in 0..1024 {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Err(e) if e.raw_os_error() == crate::sys::error::EINTR => {}
            _ => return,
        }
        let _ = kill_process(pid, rustix::process::Signal::KILL);
    }
}

fn write_proc(pid: i32, file: &str, value: &[u8]) -> Result<()> {
    use rustix::fs::{Mode, OFlags, open};

    let mut path = Path::new();
    path.push_str("/proc/")?;
    path.push_i64(i64::from(pid))?;
    path.push_str("/")?;
    path.push_str(file)?;

    let fd = open(
        path.as_c_str(),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("namespace: open mapping file")?;
    let written =
        rustix::io::write(&fd, value).context("namespace: write mapping")?;
    if written == value.len() {
        Ok(())
    } else {
        Err(Error::msg("namespace: short mapping write"))
    }
}

/// Opens the namespace files a plan says to join.
///
/// Runs in the driver, which still has the privilege and the paths.
pub fn open_joins(paths: &[String]) -> Result<Vec<OwnedFd>> {
    use rustix::fs::{Mode, OFlags, open};

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let buffer = Path::from(path.as_bytes())?;
        let fd = open(
            buffer.as_c_str(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("namespace: open to join")?;
        out.push(fd);
    }
    Ok(out)
}

/// Gives the container its own session keyring.
///
/// Without this a key the container adds is visible to whatever session the
/// runtime was started from, which is a leak between containers on the same
/// host.
pub fn new_session_keyring(id: &str) -> Result<()> {
    let mut name = PathBuf::<64>::new();
    name.push_str("kot-")?;
    let truncated = id.get(..id.len().min(32)).unwrap_or(id);
    name.push_str(truncated)?;
    match crate::sys::process::join_session_keyring(name.as_c_str()) {
        Ok(_) => Ok(()),
        // A kernel without keyrings, or a namespace that forbids them, is not
        // a reason to refuse to start the container.
        Err(e) if e.is_unsupported() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Re-opens a descriptor with different access, through `/proc/self/fd`.
///
/// Used for the start fifo, which the driver opens for its path alone and
/// which init has to open for writing at a point where it can no longer reach
/// the state directory by name.
pub fn reopen(
    fd: BorrowedFd<'_>,
    flags: rustix::fs::OFlags,
) -> Result<OwnedFd> {
    use std::os::fd::AsRawFd;

    use rustix::fs::{Mode, open};

    let mut path = PathBuf::<64>::new();
    path.push_str("/proc/self/fd/")?;
    path.push_i64(i64::from(fd.as_raw_fd()))?;
    open(
        path.as_c_str(),
        flags | rustix::fs::OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("namespace: reopen descriptor")
}

/// Borrows a descriptor the driver placed at a known number.
///
/// # Safety
///
/// The caller must be the container init process, after the handoff has put a
/// descriptor at `slot`.
#[must_use]
pub unsafe fn slot(slot: Slot) -> BorrowedFd<'static> {
    // SAFETY: the caller guarantees the descriptor is present, and the
    // returned borrow names a number this process owns for its whole life.
    unsafe { BorrowedFd::borrow_raw(slot.fd()) }
}
