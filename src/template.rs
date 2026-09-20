//! The starting configuration `kot spec` writes.
//!
//! A bundle that runs `sh` with nothing but the defaults, as the
//! specification's own example does and every tutorial starts from. Held as
//! text rather than built from the types, so that a reader of this file sees
//! exactly the document they are about to get, in the order they will read it.

/// Returns a starting `config.json`.
#[must_use]
pub fn config(rootless: bool) -> String {
    let namespaces = if rootless {
        "\n      { \"type\": \"pid\" },\n      { \"type\": \"ipc\" },\n      \
         { \"type\": \"uts\" },\n      { \"type\": \"mount\" },\n      \
         { \"type\": \"user\" },\n      { \"type\": \"network\" }\n    "
    } else {
        "\n      { \"type\": \"pid\" },\n      { \"type\": \"network\" },\n      \
         { \"type\": \"ipc\" },\n      { \"type\": \"uts\" },\n      \
         { \"type\": \"mount\" },\n      { \"type\": \"cgroup\" }\n    "
    };
    let mappings = if rootless {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        format!(
            ",\n    \"uidMappings\": [\n      {{ \"containerID\": 0, \
             \"hostID\": {uid}, \"size\": 1 }}\n    ],\n    \
             \"gidMappings\": [\n      {{ \"containerID\": 0, \
             \"hostID\": {gid}, \"size\": 1 }}\n    ]"
        )
    } else {
        String::new()
    };

    DOCUMENT
        .replace("NAMESPACES_HERE", namespaces)
        .replace("MAPPINGS_HERE", &mappings)
}

/// The starting configuration, with two places left to fill.
///
/// The two tokens are the only parts that depend on anything.
const DOCUMENT: &str = r#"{
  "ociVersion": "1.3.0",
  "process": {
    "terminal": true,
    "user": { "uid": 0, "gid": 0 },
    "args": ["sh"],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "TERM=xterm"
    ],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "effective": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"],
      "ambient": []
    },
    "rlimits": [
      { "type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024 }
    ],
    "noNewPrivileges": true
  },
  "root": { "path": "rootfs", "readonly": true },
  "hostname": "kot",
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
    },
    {
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]
    },
    {
      "destination": "/dev/shm",
      "type": "tmpfs",
      "source": "shm",
      "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]
    },
    {
      "destination": "/dev/mqueue",
      "type": "mqueue",
      "source": "mqueue",
      "options": ["nosuid", "noexec", "nodev"]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": ["nosuid", "noexec", "nodev", "ro"]
    }
  ],
  "linux": {
    "resources": {
      "devices": [{ "allow": false, "access": "rwm" }]
    },
    "namespaces": [NAMESPACES_HERE]MAPPINGS_HERE,
    "maskedPaths": [
      "/proc/acpi",
      "/proc/asound",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware"
    ],
    "readonlyPaths": [
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  }
}
"#;
