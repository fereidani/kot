//! The container init process.
//!
//! Init runs from a sealed image with nothing but a plan and a handful of
//! descriptors. It applies the plan, reports what it did, waits to be told to
//! go, and replaces itself with the payload. Everything it does is a syscall:
//! there is no parsing, no configuration to interpret, and no decision left to
//! make, because all of those happened in the driver while the plan was built.
//!
//! The sequence below is the container lifecycle from the inside, and each
//! handshake with the driver marks a point where the driver has work of its
//! own to do before init may continue.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::{
    linux::{
        handoff::{self, InitArgs, Slot},
        mount::{self, Resolver},
        namespace, process, rootfs,
        sync::{self, Kind, Message},
        terminal,
    },
    oci::plan::{Container, Process, View, process_flag},
    sys::{
        clone::{CLONE_NEWNET, CLONE_NEWUSER, CloneSpec, Fork},
        error::{Context, Error, Result},
        prctl,
        seccomp::SockFilter,
        signal,
    },
};

/// Whether the plan says to enter somebody else's user namespace.
fn joins_user_namespace(plan: &View<'_>) -> Result<bool> {
    let mut joins = false;
    plan.namespaces(|op| {
        joins |= op.fd_index >= 0 && op.clone_flag == CLONE_NEWUSER;
        Ok(())
    })?;
    Ok(joins)
}

/// Runs the container init process.
///
/// Only returns on failure. On success the process has been replaced by the
/// payload, so there is nothing left to return to.
#[must_use]
pub fn run(args: &InitArgs) -> Failure {
    // SAFETY: this is the container init process, and the driver placed the
    // sync socket at this number before the re-execution.
    let socket = unsafe { namespace::slot(Slot::Sync) };
    match attempt(args, socket) {
        Ok(failure) => failure,
        Err(error) => {
            // Whatever the driver has already sent comes off the socket
            // first. Init takes the driver's word for the cgroup only when it
            // reaches the mount that needs it, so a failure before then would
            // otherwise close this end with that word still queued, which
            // resets the connection and leaves the driver reporting the reset
            // rather than the reason.
            sync::drain(socket);
            // The driver is the only thing that can report this usefully: init
            // may be inside a user namespace with no filesystem it can reach
            // and no terminal it can write to. Saying so again here would put
            // the same failure on the same terminal twice.
            let told = sync::send(socket, &Message::failure(error)).is_ok();
            Failure {
                error,
                reported: told,
            }
        }
    }
}

/// How the container init process ended.
pub struct Failure {
    /// What went wrong.
    pub error: Error,
    /// True when the driver was told and will report it, so init can keep
    /// quiet rather than duplicate what the caller already sees.
    pub reported: bool,
}

fn attempt(args: &InitArgs, socket: BorrowedFd<'_>) -> Result<Failure> {
    // SAFETY: the driver placed the plan at this number before the
    // re-execution, and it is a sealed memory file that cannot change.
    let plan_fd = unsafe { namespace::slot(Slot::Plan) };
    let mapping = Mapping::open(plan_fd)?;
    let plan = View::new(mapping.bytes())?;
    let init = Init {
        plan: &plan,
        container: plan.container()?,
        payload: plan.process()?,
        socket,
        args,
    };

    // A hard limit cannot be raised from inside a user namespace, so a
    // process about to enter one takes its limits with it. The driver did
    // that for a namespace the clone made; every other container applies
    // them later, with the rest of the process settings.
    if init.container.unshare_flags & CLONE_NEWUSER != 0
        || joins_user_namespace(&plan)?
    {
        process::apply_rlimits(&plan)?;
    }

    // Joining a pid namespace needs the same extra fork as creating one:
    // `setns` puts the caller's children in the namespace rather than the
    // caller, so without it an `exec` would run beside the container with the
    // container's filesystem, seeing process numbers that mean nothing there.
    let joined_pid = namespace::join(&plan)?;
    let unshared = namespace::unshare(init.container.unshare_flags)?;

    // The clocks of a new time namespace can be set only while nothing is
    // in it. `unshare` leaves this process outside the namespace it just
    // made and puts its children there instead, so this is the one moment
    // between the namespace existing and the container being in it.
    namespace::write_time_offsets(&init.container)?;

    let needs_fork = unshared || joined_pid;
    if needs_fork {
        return init.fork_into_pid_namespace();
    }

    init.enter_container()
}

/// What init applies a plan from.
///
/// These travel together through every step below: the plan and the two
/// records read out of it, the socket the driver is answered on, and what the
/// caller asked for on the command line.
struct Init<'a> {
    plan: &'a View<'a>,
    container: Container,
    payload: Process,
    socket: BorrowedFd<'a>,
    args: &'a InitArgs,
}

impl Init<'_> {
    /// Forks once more so the child is in the pid namespace rather than beside
    /// it.
    ///
    /// Neither `unshare` nor `setns` moves the caller into a pid namespace;
    /// both only place its future children there. A configuration that creates
    /// a pid namespace after the clone, and every `exec` that joins one,
    /// therefore needs this extra step. The parent stays as a proxy so the
    /// driver still has a child to wait on.
    fn fork_into_pid_namespace(&self) -> Result<Failure> {
        let spec = CloneSpec::new();
        // SAFETY: this process is single-threaded, having just been executed
        // from a sealed image, so the child inherits nothing another thread
        // could have left inconsistent.
        let side = unsafe { spec.spawn()? };
        match side {
            Fork::Child => self.enter_container(),
            // The child does all the reporting, including its own readiness.
            // The proxy stays quiet: the driver expects one exchange whether
            // or not a fork happened, and a second message from here would be
            // read as the answer to the next question it asks.
            // The child has already told the driver whatever went wrong.
            Fork::Parent(pid) => {
                // And it gives up the caller's streams, which it has no
                // use for. A read of what the runtime printed ends when
                // the last copy of that pipe closes, so a proxy holding
                // one would keep the caller waiting for the container.
                let _ = crate::sys::process::close_range(0, 2, 0);
                wait_for(pid).map(|error| Failure {
                    error,
                    reported: true,
                })
            }
        }
    }

    /// Applies the plan and hands over to the payload.
    fn enter_container(&self) -> Result<Failure> {
        // Tell the driver which process it is dealing with, and let it write
        // the id mapping files if a user namespace was created. Init cannot
        // write those itself: the kernel wants privilege in the parent
        // namespace.
        let pid = rustix::process::getpid().as_raw_nonzero().get();
        sync::send(self.socket, &Message::with_pid(Kind::Ready, pid))?;
        // A user namespace the clone made was mapped before this process
        // re-executed. Only one unshared afterwards still waits for its
        // mapping.
        if self.container.unshare_flags & CLONE_NEWUSER != 0 {
            sync::expect(self.socket, Kind::IdMapsWritten)?;
        }

        // A foreground container should not outlive the runtime that is
        // waiting on it, so the kernel is asked to kill it if that process
        // disappears. A container created to be started later is the opposite
        // case: the runtime exits as soon as it has built it, and the
        // container has to survive that.
        if !self.args.detached {
            #[allow(clippy::cast_possible_wrap)]
            let signal = signal::SIGKILL as i32;
            prctl::set_pdeathsig(signal)?;
        }

        // The container leaves the runtime's process group, for two
        // reasons: a group inherited across a pid namespace has no number
        // there, and a container still in that group is sent every
        // terminal signal twice, once by the terminal and once forwarded.
        // A process that takes a terminal gets a session, and with it a
        // group, a little later.
        if !self.payload.has(process_flag::TERMINAL) {
            process::start_process_group()?;
        }

        // An `exec` joins a container that already exists, so there is nothing
        // to mount, nothing to pivot into, and nothing to name.
        if !self.container.join_only {
            self.build_filesystem()?;
            rootfs::apply_names(self.plan, &self.container)?;
            if self.container.new_keyring {
                namespace::new_session_keyring("container")?;
            }
            // A network namespace is made with its loopback device down, so
            // a container in a fresh one cannot reach itself until somebody
            // brings it up. Nothing else will: an engine configures
            // addresses and routes through a hook or a plugin, and a
            // container that has only a loopback device would get neither.
            // A namespace the configuration joined is left alone, since its
            // interfaces are in whatever state its owner chose.
            let created =
                self.container.clone_flags | self.container.unshare_flags;
            if created & CLONE_NEWNET != 0 {
                crate::sys::net::bring_up_loopback()?;
            }
        }

        // Everything the container's filesystem needed is done. The driver
        // runs the hooks that belong at this point before letting init
        // continue.
        sync::send(self.socket, &Message::new(Kind::Prepared))?;
        // An `exec` waits to be let go: its driver still has to put this
        // process in the container's cgroup and give it its affinity, and
        // neither could be done before the process existed. A container
        // being created has had all of that done already.
        if self.container.join_only {
            sync::expect(self.socket, Kind::Proceed)?;
        }

        self.finish()
    }

    /// Takes the cgroup namespace, once the driver says the move is done.
    ///
    /// A cgroup namespace is rooted where its maker sits, so it cannot be made
    /// before the driver has put this process in the container's cgroup. The
    /// driver says so exactly once, and only when the configuration asked for
    /// the namespace at all.
    fn enter_cgroup_namespace(
        &self,
        already: &core::cell::Cell<bool>,
    ) -> Result<()> {
        if !self.container.cgroup_namespace {
            return Ok(());
        }
        // A source request may have taken the driver's word for it already.
        if !already.replace(false) {
            sync::expect(self.socket, Kind::CgroupJoined)?;
        }
        namespace::unshare(crate::sys::clone::CLONE_NEWCGROUP)?;
        Ok(())
    }

    /// Builds the container's filesystem view, in the order that works.
    fn build_filesystem(&self) -> Result<()> {
        let (plan, container) = (self.plan, &self.container);
        let cgroup_joined = core::cell::Cell::new(false);
        // Made or joined, either leaves this process without privilege
        // over the filesystems its mount sources are on.
        let in_user_namespace =
            (container.clone_flags | container.unshare_flags) & CLONE_NEWUSER
                != 0
                || joins_user_namespace(plan)?;

        // Two ways to the same tree. Given a namespace holding the rootfs
        // alone, every mount is made while the host is still in reach and
        // the namespace entered with them in hand; otherwise the copy of
        // the host's tree this process was born with is prepared for the
        // pivot below.
        let mut ahead = Vec::new();
        let mut resolver = if self.args.has_tree {
            mount::make_ahead(
                plan,
                container,
                self.socket,
                &cgroup_joined,
                &mut ahead,
            )?;
            // SAFETY: the driver placed the namespace at this number before
            // the re-execution, and `has_tree` says it did.
            let tree = unsafe { namespace::slot(Slot::Tree) };
            rootfs::enter_tree(tree)?;
            Resolver::new(c"/")?
        } else {
            rootfs::prepare(container, plan)?;
            Resolver::new(plan.c_str(container.rootfs)?)?
        };

        // Everything from here on is made inside the container and
        // belongs to it. The bundle above was reached as the runtime's own
        // user, which is whose bundle it is.
        process::adopt_container_root()?;

        let joined = self.args.namespaces;
        let mut in_cgroup_namespace = false;
        let mut index = 0i32;
        plan.mounts(|op| {
            let at = mount::Source {
                index,
                socket: self.socket,
                cgroup_joined: &cgroup_joined,
                in_user_namespace,
                ahead: usize::try_from(index)
                    .ok()
                    .and_then(|at| ahead.get(at))
                    .map_or(mount::Ahead::Reachable, mount::Made::ahead),
            };
            index += 1;
            // Only a cgroup mount depends on the namespace, and it is the
            // last thing a stock bundle asks for. Waiting here rather than
            // before any of this is what lets the driver settle the container
            // cgroup, which takes the best part of ten milliseconds between
            // systemd and the move, while the rest of the filesystem is
            // built.
            if !in_cgroup_namespace
                && matches!(plan.text(op.fstype)?, "cgroup" | "cgroup2")
            {
                self.enter_cgroup_namespace(&cgroup_joined)?;
                in_cgroup_namespace = true;
            }
            // A mount with an id mapping names the namespace carrying it by
            // position. The driver placed those above the namespaces to join,
            // in the order the mount records name them.
            let idmap = match usize::try_from(op.idmap_fd) {
                Err(_) => None,
                Ok(index) if index < self.args.idmaps => {
                    // SAFETY: the driver placed this descriptor at exactly
                    // this number before the re-execution, and nothing has
                    // closed it since.
                    Some(unsafe {
                        BorrowedFd::borrow_raw(Slot::idmap(joined, index))
                    })
                }
                Ok(_) => {
                    return Err(Error::msg("mount: id mapping is missing"));
                }
            };
            mount::establish(plan, &mut resolver, &op, idmap, at)
        })?;
        if !in_cgroup_namespace {
            self.enter_cgroup_namespace(&cgroup_joined)?;
        }
        rootfs::create_devices(plan, &mut resolver, self.socket)?;

        // The hooks that run inside the container but still resolve their own
        // paths on the host belong here, between the mounts existing and the
        // root changing. Init cannot run them itself, so it waits while the
        // driver does.
        sync::send(self.socket, &Message::new(Kind::Mounted))?;
        if self.container.hooks_before_pivot {
            sync::expect(self.socket, Kind::HooksRun)?;
        }

        // A namespace made from the rootfs has the container's root as its
        // root already, and every cached directory below it still names
        // what it did. After a pivot the cached descriptors name paths in
        // the old root, so the resolver starts again from the new one.
        let mut inside = if self.args.has_tree {
            resolver
        } else {
            if container.no_pivot {
                rootfs::chroot(resolver.root())?;
            } else {
                rootfs::pivot(resolver.root())?;
            }
            drop(resolver);
            Resolver::new(c"/")?
        };
        // Now that the container's root is the root, it can be given the
        // propagation the configuration asked for. Doing it before the
        // change would have sent everything above back out through the
        // mount the bundle sits on.
        rootfs::apply_propagation(container)?;

        // Before the paths below are made read only, and after the root has
        // changed so that `/proc` means the container's. A configuration
        // naming a parameter almost always names `/proc/sys` among the paths
        // to seal as well, so the other order leaves every setting it asked
        // for refused by a filesystem the runtime made read only a moment
        // earlier.
        rootfs::apply_sysctls(plan)?;

        rootfs::apply_paths(plan, &mut inside)?;

        // Made here, while the root can still be written to: a read-only
        // root says what the payload may write, not what the runtime may
        // build for it.
        process::create_working_directory(plan, &self.payload)?;

        if container.rootfs_readonly {
            rootfs::seal_root()?;
        }
        Ok(())
    }

    /// Hands the seccomp notify descriptor back for delivery.
    ///
    /// The agent's socket is a path on the host, which is unreachable from
    /// here because the filesystem has already been pivoted, and the state
    /// the agent is owed names the process by the id the runtime sees rather
    /// than the one this process sees. Both facts live on the driver's side,
    /// so the descriptor goes back the way everything else does.
    ///
    /// Waiting for the answer matters: a notifying syscall made before the
    /// agent holds the descriptor has nothing to answer it.
    fn deliver_listener(&self, listener: &OwnedFd) -> Result<()> {
        sync::send_fd(
            self.socket,
            &Message::new(Kind::SeccompListener),
            listener.as_fd(),
        )?;
        sync::expect(self.socket, Kind::Proceed)?;
        Ok(())
    }

    /// Installs the seccomp filter and hands any listener to the driver.
    fn install_filter(&self, filter: &mut Vec<SockFilter>) -> Result<()> {
        let listener =
            process::apply_seccomp(self.plan, &self.payload, filter)?;
        if let Some(listener) = listener {
            self.deliver_listener(&listener)?;
        }
        Ok(())
    }

    /// Applies the process settings and executes the payload.
    fn finish(&self) -> Result<Failure> {
        let (plan, payload) = (self.plan, &self.payload);
        let mut command = process::Command::new(plan)?;
        // The environment is completed before anything is resolved through
        // it: the payload is looked up along the `PATH` it ends up with.
        command.ensure_home(payload.uid)?;
        let pid = rustix::process::getpid().as_raw_nonzero().get();
        command.set_listen_pid(pid)?;

        // The terminal is created before privilege is dropped, because opening
        // the multiplexer and taking control of the session both need it.
        if payload.has(process_flag::TERMINAL) {
            self.attach_terminal()?;
        }

        // Applied again for a container that took them early, which costs
        // nothing: setting a limit to what it already is needs no privilege.
        process::apply_rlimits(plan)?;
        process::apply_scheduling(plan, payload)?;
        process::enter_working_directory(plan, payload)?;

        // The payload has to be resolved before privilege is dropped, because
        // a program the container's user cannot read is still one the
        // configuration asked to run.
        let program = match process::resolve_program(&command) {
            Ok(program) => program,
            Err(error) => return self.report_payload(&command, error),
        };

        // Installing a filter takes either `no_new_privs` or `CAP_SYS_ADMIN`.
        // A configuration asking for the first gets its filter as late as it
        // can, so that few of the runtime's own calls are made under it. One
        // that does not has only the capability to offer, and that goes when
        // privilege does, so the filter has to be in place before then.
        let mut filter = Vec::<SockFilter>::new();
        let guarded = payload.has(process_flag::NO_NEW_PRIVS);
        if !guarded {
            self.install_filter(&mut filter)?;
        }

        // Before the change of user, which is the only moment the runtime
        // still has the privilege to hand the streams over.
        process::adopt_standard_streams(payload);

        process::narrow_capabilities(payload)?;
        process::drop_privileges(plan, payload)?;
        process::apply_capabilities(payload)?;
        process::apply_labels(plan, payload)?;
        process::apply_no_new_privs(payload)?;

        if guarded {
            self.install_filter(&mut filter)?;
        }

        // Everything the configuration asked for is applied. Saying so here
        // rather than at the last handshake leaves the driver able to report a
        // failure in any of it: past this point the only steps left cannot
        // fail for a reason the configuration chose.
        sync::send(self.socket, &Message::new(Kind::Configured))?;
        // An `exec` joins a container that is already running, so none of the
        // container's own hook points apply to it and nobody is listening.
        if !self.container.join_only && self.container.hooks_before_exec {
            sync::expect(self.socket, Kind::HooksRun)?;
        }

        if self.args.has_start_fifo {
            wait_for_start()?;
        }

        // The program is parked first, because the sweep below would otherwise
        // close the very descriptor that is about to be executed.
        let slot = handoff::park_program(program, self.args.preserved)?;
        // Everything else the runtime was holding goes now, so the payload
        // starts with exactly the descriptors it was promised.
        handoff::close_runtime_block(self.args.preserved)?;
        // SAFETY: the program was just parked at this number and nothing has
        // closed it since; the borrow does not outlive the call, which on
        // success does not return at all.
        let program = unsafe { BorrowedFd::borrow_raw(slot) };
        // Nothing is listening by now, so a failure to execute the payload
        // has only the terminal left to reach.
        Ok(Failure {
            error: command.exec(program),
            reported: false,
        })
    }

    /// Reports a payload that could not be resolved, naming it.
    ///
    /// The name is what a caller needs and what the error type cannot
    /// carry, so it goes on the message to the driver. Reported here rather
    /// than returned, since a returned error is sent where the name is out
    /// of reach.
    fn report_payload(
        &self,
        command: &process::Command,
        error: Error,
    ) -> Result<Failure> {
        let name = command.program()?;
        let message = Message::failure_named(error, name.to_bytes());
        let reported = sync::send(self.socket, &message).is_ok();
        Ok(Failure { error, reported })
    }

    /// Gives the payload a terminal.
    ///
    /// The pseudo-terminal comes from the container's own multiplexer, so the
    /// numbering it sees is its own, and the controlling end goes to whoever
    /// asked for it: a caller's console socket, or the driver's own end of a
    /// pair when the container is running in the foreground.
    fn attach_terminal(&self) -> Result<()> {
        if !self.args.has_console_socket {
            return Err(Error::msg(
                "terminal: a terminal was requested with nowhere to send it",
            ));
        }
        let (controller, follower) = terminal::open()?;
        terminal::own(follower.as_fd(), self.payload.uid, self.payload.gid)?;
        terminal::resize(
            controller.as_fd(),
            self.payload.console_height,
            self.payload.console_width,
        )?;

        // SAFETY: the driver placed the console socket at this number before
        // the re-execution, and `has_console_socket` says it did.
        let socket = unsafe { namespace::slot(Slot::ConsoleSocket) };
        terminal::send(socket, controller.as_fd())?;
        drop(controller);

        terminal::adopt(follower.as_fd())
    }
}

/// Waits for the real init and exits with whatever it did.
fn wait_for(pid: i32) -> Result<Error> {
    use rustix::process::{Pid, WaitOptions, waitpid};
    let Some(pid) = Pid::from_raw(pid) else {
        return Err(Error::msg("init: bad process id"));
    };
    // Bounded by the child's lifetime; the loop only repeats when the wait was
    // interrupted by a signal, which cannot happen without bound.
    for _ in 0..1024 {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => {
                let code = status.exit_status().unwrap_or(0);
                #[allow(clippy::cast_possible_wrap)]
                std::process::exit(code);
            }
            Ok(None) => {}
            Err(e) if e.raw_os_error() == crate::sys::error::EINTR => {}
            Err(e) => return Err(Error::from(e).describe("init: wait")),
        }
    }
    Err(Error::msg("init: gave up waiting"))
}

/// Blocks until the caller runs `start`.
///
/// The fifo is opened for writing, which blocks until something opens it for
/// reading, and `start` is the command that does. The descriptor has to be
/// reopened through `/proc/self/fd` because by now init cannot reach the state
/// directory by name.
fn wait_for_start() -> Result<()> {
    use rustix::fs::OFlags;

    // SAFETY: the driver placed the fifo at this number before the
    // re-execution, and `has_start_fifo` says it did.
    let placeholder = unsafe { namespace::slot(Slot::StartFifo) };
    let writable = namespace::reopen(placeholder, OFlags::WRONLY)?;
    let written = rustix::io::write(&writable, b"\0")
        .context("init: signal readiness on the start fifo")?;
    if written == 0 {
        return Err(Error::msg("init: start fifo closed"));
    }
    Ok(())
}

/// A read-only mapping of the plan.
struct Mapping {
    address: *mut core::ffi::c_void,
    length: usize,
}

impl Mapping {
    fn open(fd: BorrowedFd<'_>) -> Result<Self> {
        use rustix::mm::{MapFlags, ProtFlags, mmap};

        let stat = rustix::fs::fstat(fd).context("init: stat plan")?;
        let length = usize::try_from(stat.st_size)
            .map_err(|_| Error::msg("init: plan too large"))?;
        if length == 0 {
            return Err(Error::msg("init: plan is empty"));
        }
        // SAFETY: the kernel chooses the address, the length comes from the
        // file's own size, and the mapping is read only and private, so
        // nothing else can be disturbed by it.
        let address = unsafe {
            mmap(
                core::ptr::null_mut(),
                length,
                ProtFlags::READ,
                MapFlags::PRIVATE,
                fd,
                0,
            )
            .context("init: map plan")?
        };
        Ok(Self { address, length })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping covers exactly `length` readable bytes and
        // outlives the borrow, and nothing writes through it.
        unsafe {
            core::slice::from_raw_parts(self.address.cast::<u8>(), self.length)
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the address and length are the ones `mmap` returned, and
        // nothing borrows the mapping at this point.
        unsafe {
            let _ = rustix::mm::munmap(self.address, self.length);
        }
    }
}
