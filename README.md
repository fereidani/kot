<div align="center">

<img src="logo.svg" alt="Kot logo" width="200">

# Kot

[![Crates.io][crates-badge]][crates-url]
[![Documentation][doc-badge]][doc-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/kot.svg?style=for-the-badge
[crates-url]: https://crates.io/crates/kot
[doc-badge]: https://img.shields.io/docsrs/kot?style=for-the-badge
[doc-url]: https://docs.rs/kot
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge
[mit-url]: LICENSE

</div>

`kot` is an OCI container runtime for Linux: the program a container engine
calls to create, start, and tear down containers. It implements the runtime
specification from 1.0.0 to 1.3.0 and takes the command line `runc` and `crun`
already take, so an engine can be pointed at it without changing anything else.

It links no container libraries. There is no `libseccomp`, no `libsystemd`, and
no `libcap`: the seccomp compiler, the D-Bus client, and the capability handling
are all in the crate, so the whole runtime is one static binary of about a
megabyte with three direct dependencies.

## Install

From crates.io:

```bash
cargo install kot
```

From source:

```bash
git clone https://github.com/fereidani/kot
cd kot
make
sudo make install
```

`make` builds the release binary and `sudo make install` copies it to
`/usr/local/bin`, which is why that step needs root. Set `PREFIX` to install
somewhere else and `DESTDIR` to stage it into a package root; `sudo make
uninstall` removes it again.

```bash
make PREFIX=/usr DESTDIR=/tmp/pkg install
```

For a binary with nothing to link against at all:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

## Usage

Hand it to an engine as the runtime to use:

```bash
podman --runtime /path/to/kot run --rm docker.io/library/alpine echo hello
```

`/path/to/kot` is wherever the binary landed: `/usr/local/bin/kot` after `sudo
make install`, `~/.cargo/bin/kot` after `cargo install kot`, or
`target/release/kot` in a build tree. `command -v kot` prints the one on your
`PATH`.

Or drive it directly, the way an engine would:

```bash
kot spec                       # write a starting config.json
kot create mycontainer         # build the container, leave it waiting
kot start mycontainer          # run its payload
kot state mycontainer          # report what it is doing
kot delete mycontainer         # remove it
```

## Commands

- `create` builds a container without running it.
- `start` runs the payload of a container that was created.
- `run` builds a container and runs it.
- `state` reports a container's state as the specification defines it.
- `kill` sends a signal to a container, or to every process in it.
- `delete` removes a container, optionally killing it first.
- `exec` runs another process inside a container that already exists.
- `list` lists the containers a state root knows about.
- `ps` shows the processes in a container.
- `pause` and `resume` stop and restart every process in a container.
- `update` changes a running container's resource limits.
- `spec` writes a starting configuration.
- `features` reports what this build supports, checked against the running
  kernel rather than assumed from what was compiled in.

## Design

Container startup is dominated by a handful of things that are slow for
reasons that can be removed rather than optimised. The measurements below were
taken on one host and will differ on yours; the shape of them is the point.

**The seccomp filter is compiled in process.** Emitting the filter for a stock
container profile costs `libseccomp` about 18 ms of CPU, which is why other
runtimes cache compiled filters on disk and then have to manage the cache and
its failure modes. Emitting the same filter directly costs microseconds, so
there is nothing worth caching. The emitter coalesces runs of consecutive
syscall numbers that share an action into range checks and gives every distinct
action one shared return, and the same profile always produces byte-identical
output, so a filter can be diffed against a reference and audited.

**The systemd round trip happens in the background.** Creating a transient
scope is a request that takes 0.02 ms to send and about 11 ms to land. Sending
it and getting on with the filesystem, rather than waiting for it first, turns
that into time the runtime was going to spend anyway. Readiness is learned by
watching for the cgroup directory instead of waiting for systemd's job
completion signal, and teardown does not block on a `StopUnit` job: an empty
scope is collected in about 1 ms, where waiting for the job costs 150 ms.

**A process is born in its cgroup.** On the unified hierarchy the cgroup is
made before the clone and the clone places the process directly into it.
Moving a process into a cgroup afterwards is not the cheap write it looks
like: the migration takes a lock whose writer side waits out a read-copy-update
grace period, several milliseconds on an otherwise idle host.

**The configuration is compiled, not interpreted.** `config.json` is parsed
into a `Spec` that borrows the file it was read from, validated once, and
lowered into a plan: one flat arena addressed by offsets rather than pointers,
sealed into a memory file the container init process maps read only. Because
the arena is the wire format, there is no serialisation step, and because every
question was answered while the plan was built, init parses nothing and decides
nothing. What is left for it is syscalls, and the only failures left are the
kernel's. The memory it does take is its own working space, a buffer for the
filter it installs and a cache of the directories it has resolved, never the
configuration.

**The runtime cannot be overwritten through the container.** Init runs from a
private read-only overlay of the directory the binary lives in, mounted nowhere
and reachable only through one descriptor. A file opened through it has an
inode of the overlay's own, so a container entrypoint that resolves to the
runtime finds nothing there to write to. A read-only bind mount cannot promise
that, because it shares its inode with the mount it came from.

**Mounts go through the kernel's newer interface.** `fsopen`, `fsmount`,
`open_tree`, `move_mount`, and `mount_setattr`, with destinations resolved by
`openat2` under `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`, relative to a
descriptor for the container's root, so the kernel does the confinement and
there is no window between checking a path and using it. A host whose kernel
lacks the mount API falls back to `mount(2)`, chosen once by a probe rather
than per mount; `openat2` itself is required either way, since resolving a
destination any other way would reintroduce that window.

## Testing

```bash
cargo test
```

The suite runs real containers where it can and skips with an explanation
where it cannot, so it still runs unprivileged and in environments without
systemd. Alongside the unit tests there are conformance tests that each name
the specification requirement they hold the runtime to, differential tests that
assert a container built by `kot` looks the same from the inside as one built
by `runc` or `crun`, and seccomp tests that install real filters in a child
process and check the kernel enforces what was asked for.

## License

`kot` is licensed under the MIT license. See the `LICENSE` file for more
information.
