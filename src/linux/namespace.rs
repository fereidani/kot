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
    oci::plan::{Container, Section, View, record::IdRange},
    sys::{
        clone::{CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER},
        error::{Context, EPERM, Error, Result},
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
/// Returns true when the caller has to fork once more, which is the case for
/// a pid namespace and for a time namespace alike: `unshare` puts the
/// caller's *children* in either of those, never the caller. A container
/// left in the parent of the namespace it asked for would see the host's
/// process numbers, or the host's clocks.
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
    Ok(flags & (CLONE_NEWPID | CLONE_NEWTIME) != 0)
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
pub fn write_id_maps(
    plan: &View<'_>,
    pid: i32,
    may_deny_setgroups: bool,
) -> Result<()> {
    if plan.count(Section::UidMap) == 0 && plan.count(Section::GidMap) == 0 {
        return Ok(());
    }
    match write_map(plan, pid, Section::UidMap, "uid_map") {
        Ok(()) => {}
        // An unprivileged caller may write only its own id directly.
        // Anything wider is what the subordinate ranges an administrator
        // granted are for, and the helper is installed to write those.
        Err(e) if e.errno() == EPERM => {
            run_id_helper(plan, pid, Section::UidMap, "newuidmap")?;
        }
        Err(e) => return Err(e),
    }

    // The gid map is tried as the runtime stands. A writer holding
    // `CAP_SETGID` outside the namespace is allowed it, and the container
    // then keeps the ability to set supplementary groups, which is what a
    // configuration naming `additionalGids` needs.
    match write_map(plan, pid, Section::GidMap, "gid_map") {
        Ok(()) => return Ok(()),
        Err(e) if e.errno() == EPERM => {
            // The helper writes it with privilege of its own, so the
            // container keeps `setgroups` where this succeeds.
            if run_id_helper(plan, pid, Section::GidMap, "newgidmap").is_ok() {
                return Ok(());
            }
            if !may_deny_setgroups {
                return Err(e);
            }
        }
        Err(e) => return Err(e),
    }

    // Without that privilege the kernel takes the map only from a process
    // that can no longer call `setgroups`, so denying it is the price of
    // having a mapping at all. The container cannot have supplementary
    // groups after this, and the code that would set them says so rather
    // than dropping them quietly.
    write_proc(pid, "setgroups", b"deny")?;
    write_map(plan, pid, Section::GidMap, "gid_map")
}

/// Writes the clock offsets of the time namespace this process just made.
///
/// A new time namespace starts with both of its clocks reading exactly what
/// the host's do, and the offsets are what the configuration asked for
/// instead. The kernel fixes them the moment anything is in the namespace,
/// and `unshare` leaves the caller outside the one it creates, so this is
/// the only moment they can be written: after the unshare and before the
/// fork that puts the container inside.
pub fn write_time_offsets(container: &Container) -> Result<()> {
    if !container.set_boottime && !container.set_monotonic {
        return Ok(());
    }
    // One write for the whole file, as with the id maps: the kernel takes
    // each line as a record and a half-written set would leave the container
    // on a clock nobody asked for.
    let mut body = Path::new();
    let clocks = [
        (
            "boottime",
            container.set_boottime,
            container.boottime_secs,
            container.boottime_nanos,
        ),
        (
            "monotonic",
            container.set_monotonic,
            container.monotonic_secs,
            container.monotonic_nanos,
        ),
    ];
    for (clock, wanted, secs, nanos) in clocks {
        if !wanted {
            continue;
        }
        body.push_str(clock)?;
        body.push_str(" ")?;
        body.push_i64(secs)?;
        body.push_str(" ")?;
        body.push_u64(u64::from(nanos))?;
        body.push_str("\n")?;
    }
    // This process's own file, not a child's: it has unshared the namespace
    // and is therefore still outside it, which is the only state the kernel
    // lets the clocks be set from.
    write_own_proc("timens_offsets", body.as_bytes())
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

/// Writes a mapping through the setuid helper an unprivileged caller needs.
///
/// A caller without privilege may map only its own id by writing the file
/// itself. Anything wider needs the subordinate ranges an administrator
/// granted it, and the two helpers are installed setuid for exactly that:
/// they check the ranges asked for against what was granted and write the
/// map with the privilege the caller does not have. Without them a rootless
/// container has one id and no more, which is not enough for an image whose
/// files belong to several.
///
/// Runs in the driver, on a process that is waiting, so spawning a program
/// here costs nothing the container is waiting on twice.
fn run_id_helper(
    plan: &View<'_>,
    pid: i32,
    section: Section,
    program: &str,
) -> Result<()> {
    let mut command = std::process::Command::new(program);
    command.arg(pid.to_string());
    plan.id_map(section, |range: IdRange| {
        command.arg(range.container_id.to_string());
        command.arg(range.host_id.to_string());
        command.arg(range.size.to_string());
        Ok(())
    })?;

    let status = command.status().map_err(|_| {
        Error::msg("namespace: the id mapping helper is absent")
    })?;
    if status.success() {
        return Ok(());
    }
    Err(Error::msg(
        "namespace: the id mapping helper refused the ranges",
    ))
}

/// Writes one of this process's own files under `/proc`.
fn write_own_proc(file: &str, value: &[u8]) -> Result<()> {
    use rustix::fs::{Mode, OFlags, open};

    let mut path = Path::new();
    path.push_str("/proc/self/")?;
    path.push_str(file)?;
    let fd = open(
        path.as_c_str(),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("namespace: open the clock offsets")?;
    let written = rustix::io::write(&fd, value)
        .context("namespace: write the clock offsets")?;
    if written == value.len() {
        Ok(())
    } else {
        Err(Error::msg("namespace: short write of the clock offsets"))
    }
}
