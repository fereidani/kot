#!/usr/bin/env python3
"""Compare the run time, peak memory and filter cost of OCI runtimes.

Usage: tools/bench-runtimes.py [-n RUNS] [-o OUT.md] [RUNTIME ...]

Each RUNTIME is a name to look up on PATH or a path to a binary; the default
is runc, crun and kot. Runtimes take turns, so a machine that drifts over the
run drifts for all of them. Needs root: every measured run makes a container.

A runtime that fails a run is left out of the results altogether and said so
on standard error. A time for a runtime that could not always start a
container is not one worth comparing, and a row for it would say that it was.

The filter column is the one cost inside the container that belongs to the
runtime: the seccomp program it compiled, charged to every syscall the
payload makes. It is a syscall-heavy payload timed with the profile and
without it, each less its own empty run, so neither startup nor the cost of
installing the filter is counted.
"""

import argparse
import json
import os
import platform
import shutil
import statistics
import sys
import tempfile
import time

DEFAULTS = ["runc", "crun", "kot"]
BINDS = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"]
CGROUP = "/sys/fs/cgroup"
HEADERS = [
    "runtime",
    "median ms",
    "min ms",
    "max ms",
    "peak MB",
    "filter ns",
]
PROFILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests",
    "data",
    "seccomp",
    "allowed-syscalls.txt",
)


def allowed():
    try:
        with open(PROFILE) as names:
            return [
                line.strip()
                for line in names
                if line.strip() and not line.startswith("#")
            ]
    except OSError:
        return []


def config(payload, profile=None):
    mounts = [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        },
    ]
    for path in BINDS:
        if os.path.isdir(path):
            mounts.append(
                {
                    "destination": path,
                    "type": "bind",
                    "source": path,
                    "options": ["rbind", "ro"],
                }
            )
    linux = {
        "namespaces": [
            {"type": "pid"},
            {"type": "ipc"},
            {"type": "uts"},
            {"type": "mount"},
        ]
    }
    if profile:
        linux["seccomp"] = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [{"names": profile, "action": "SCMP_ACT_ALLOW"}],
        }
    return {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": payload,
            "env": ["PATH=/usr/bin:/bin"],
            "cwd": "/",
            "noNewPrivileges": True,
        },
        "root": {"path": "rootfs", "readonly": False},
        "hostname": "bench",
        "mounts": mounts,
        "linux": linux,
    }


def make_bundle(directory, payload, profile=None):
    rootfs = os.path.join(directory, "rootfs")
    spec = config(payload, profile)
    for mount in spec["mounts"]:
        os.makedirs(
            os.path.join(rootfs, mount["destination"].lstrip("/")),
            exist_ok=True,
        )
    with open(os.path.join(directory, "config.json"), "w") as out:
        json.dump(spec, out)


def timed_run(runtime, cid):
    null = os.open(os.devnull, os.O_RDWR)
    actions = [
        (os.POSIX_SPAWN_DUP2, null, 0),
        (os.POSIX_SPAWN_DUP2, null, 1),
        (os.POSIX_SPAWN_DUP2, null, 2),
    ]
    argv = [runtime["binary"], "--root", runtime["state"], "run", cid]
    start = time.perf_counter()
    pid = os.posix_spawn(
        runtime["binary"], argv, os.environ, file_actions=actions
    )
    _, status = os.waitpid(pid, 0)
    elapsed = time.perf_counter() - start
    os.close(null)
    return elapsed * 1000.0, status


def measured_run(runtime, cid):
    cgroup = os.path.join(CGROUP, f"bench-{os.getpid()}-{cid}")
    try:
        os.mkdir(cgroup)
    except OSError:
        return 0.0
    argv = [runtime["binary"], "--root", runtime["state"], "run", cid]
    pid = os.fork()
    if pid == 0:
        try:
            with open(os.path.join(cgroup, "cgroup.procs"), "w") as procs:
                procs.write(str(os.getpid()))
            null = os.open(os.devnull, os.O_RDWR)
            os.dup2(null, 0)
            os.dup2(null, 1)
            os.dup2(null, 2)
            os.execv(runtime["binary"], argv)
        except OSError:
            pass
        os._exit(127)
    os.waitpid(pid, 0)
    try:
        with open(os.path.join(cgroup, "memory.peak")) as peak:
            megabytes = int(peak.read().strip()) / (1024.0 * 1024.0)
    except OSError:
        megabytes = 0.0
    try:
        os.rmdir(cgroup)
    except OSError:
        pass
    return megabytes


def phases(payload, syscalls):
    profile = allowed()
    plain = [("start", payload, None)]
    if not profile or not os.path.exists("/usr/bin/dd"):
        return plain
    work = [
        "/usr/bin/dd",
        "if=/dev/zero",
        "of=/dev/null",
        "bs=1",
        f"count={syscalls // 2}",
    ]
    return plain + [
        ("start-filtered", payload, profile),
        ("work", work, None),
        ("work-filtered", work, profile),
    ]


def benchmark(runtimes, runs, warmup, payload, syscalls, work):
    stages = phases(payload, syscalls)
    for runtime in runtimes:
        runtime["state"] = os.path.join(work, runtime["name"], "state")
        os.makedirs(runtime["state"], exist_ok=True)
        runtime["bundles"] = {}
        runtime["samples"] = {}
        for name, args, profile in stages:
            directory = os.path.join(work, runtime["name"], name)
            make_bundle(directory, args, profile)
            runtime["bundles"][name] = directory
            runtime["samples"][name] = []
        runtime["bundle"] = runtime["bundles"]["start"]
        runtime["times"] = runtime["samples"]["start"]
        runtime["memory"] = []
        runtime["failed"] = 0

    for index in range(warmup + runs):
        for name, _, _ in stages:
            for runtime in runtimes:
                os.chdir(runtime["bundles"][name])
                elapsed, status = timed_run(runtime, f"{name}-{index}")
                if status != 0:
                    runtime["failed"] += 1
                elif index >= warmup:
                    runtime["samples"][name].append(elapsed)

    qualified = disqualify(runtimes, (warmup + runs) * len(stages))
    for index in range(max(3, runs // 5)):
        for runtime in qualified:
            os.chdir(runtime["bundle"])
            runtime["memory"].append(measured_run(runtime, f"mem-{index}"))
    return qualified


def disqualify(runtimes, attempts):
    """Drops every runtime that failed a run, saying so."""
    kept = []
    for runtime in runtimes:
        if runtime["failed"]:
            print(
                f"{runtime['name']}: {runtime['failed']} of {attempts} runs "
                "failed, so it is left out",
                file=sys.stderr,
            )
        else:
            kept.append(runtime)
    return kept


def cpu_model():
    """The processor's own name for itself.

    It says more about the numbers than the host's name does, and it is what
    the kernel reports, so nothing has to be typed in.
    """
    try:
        with open("/proc/cpuinfo") as info:
            for line in info:
                key, separator, value = line.partition(":")
                if separator and key.strip() in ("model name", "cpu model"):
                    return " ".join(value.split())
    except OSError:
        pass
    return platform.machine() or "unknown cpu"


def filter_cost(runtime, syscalls):
    samples = runtime["samples"]
    if any(not samples.get(name) for name in samples):
        return None
    if len(samples) < 4:
        return None
    filtered = min(samples["work-filtered"]) - min(samples["start-filtered"])
    plain = min(samples["work"]) - min(samples["start"])
    return (filtered - plain) * 1e6 / syscalls


def row(runtime, syscalls):
    times = runtime["times"]
    memory = runtime["memory"]
    cost = filter_cost(runtime, syscalls)
    return [
        runtime["name"],
        f"{statistics.median(times):.1f}" if times else "-",
        f"{min(times):.1f}" if times else "-",
        f"{max(times):.1f}" if times else "-",
        f"{max(memory):.1f}" if memory else "-",
        f"{cost:.0f}" if cost is not None else "-",
    ]


def table(rows):
    lines = [HEADERS] + rows
    widths = [max(len(line[i]) for line in lines) for i in range(len(HEADERS))]
    out = []
    for index, cells in enumerate(lines):
        out.append(
            "  ".join(
                cell.ljust(widths[i]) for i, cell in enumerate(cells)
            ).rstrip()
        )
        if index == 0:
            out.append("  ".join("-" * width for width in widths))
    return "\n".join(out)


def markdown(runtimes, rows, runs, payload, syscalls):
    system = os.uname()
    lines = [
        "# OCI runtime benchmark",
        "",
        f"- cpu: {cpu_model()}, {system.sysname} {system.release}",
        f"- payload: `{' '.join(payload)}`",
        f"- runs per runtime: {runs}",
        f"- filter column: nanoseconds per syscall over {syscalls} syscalls",
        "",
        "| " + " | ".join(HEADERS) + " |",
        "|" + "|".join("---" for _ in HEADERS) + "|",
    ]
    lines += ["| " + " | ".join(cells) + " |" for cells in rows]
    lines.append("")
    lines += [f"- {r['name']}: `{r['binary']}`" for r in runtimes]
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtimes", nargs="*", default=DEFAULTS)
    parser.add_argument("-n", "--runs", type=int, default=30)
    parser.add_argument("-w", "--warmup", type=int, default=3)
    parser.add_argument("-o", "--out", default="benchmark.md")
    parser.add_argument("-p", "--payload", default="/bin/true")
    parser.add_argument("-s", "--syscalls", type=int, default=400000)
    options = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("needs root: every measured run makes a container")

    runtimes = []
    for wanted in options.runtimes:
        binary = wanted if os.sep in wanted else shutil.which(wanted)
        if not binary or not os.access(binary, os.X_OK):
            print(f"skipping {wanted}: not found", file=sys.stderr)
            continue
        binary = os.path.abspath(binary)
        name = os.path.basename(binary)
        while any(runtime["name"] == name for runtime in runtimes):
            name += "'"
        runtimes.append({"name": name, "binary": binary})

    if not runtimes:
        sys.exit("no runtimes to measure")

    payload = options.payload.split()
    here = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="bench-") as work:
        try:
            runtimes = benchmark(
                runtimes,
                options.runs,
                options.warmup,
                payload,
                options.syscalls,
                work,
            )
        finally:
            os.chdir(here)

    if not runtimes:
        sys.exit("every runtime failed a run")
    runtimes.sort(key=lambda r: statistics.median(r["times"] or [float("inf")]))
    rows = [row(runtime, options.syscalls) for runtime in runtimes]
    print(table(rows))
    with open(options.out, "w") as out:
        out.write(
            markdown(runtimes, rows, options.runs, payload, options.syscalls)
        )
    print(f"\nwritten to {options.out}")


if __name__ == "__main__":
    main()
