//! The features report.
//!
//! What this build supports, checked against the running kernel rather than
//! assumed from what was compiled in. A caller uses this to decide whether to
//! send a configuration at all, so an optimistic answer here turns into a
//! confusing failure later.

use crate::{json::Writer, seccomp::arch};

/// Renders the report.
#[must_use]
pub fn report() -> String {
    let mut json = Writer::new();
    json.object(None);
    json.string(Some("ociVersionMin"), crate::validate::OCI_VERSION_MIN);
    json.string(Some("ociVersionMax"), crate::validate::OCI_VERSION_MAX);
    json.string_array(
        "hooks",
        [
            "prestart",
            "createRuntime",
            "createContainer",
            "startContainer",
            "poststart",
            "poststop",
        ],
    );
    json.string_array("mountOptions", MOUNT_OPTIONS);

    linux_section(&mut json);

    json.object(Some("annotations"));
    json.string(Some("run.oci.kot.version"), env!("CARGO_PKG_VERSION"));
    // Checkpoint and restore are deliberately not implemented, so a caller
    // that probes before using them is told so.
    json.string(Some("org.opencontainers.runc.checkpoint.enabled"), "false");
    json.end_object();

    json.string_array(
        "potentiallyUnsafeConfigAnnotations",
        [
            "run.oci.keep_original_groups",
            "run.oci.seccomp_fail_unknown_syscall",
        ],
    );
    json.end_object();
    json.finish()
}

/// Mount options the runtime understands.
const MOUNT_OPTIONS: [&str; 46] = [
    "acl",
    "async",
    "atime",
    "bind",
    "defaults",
    "dev",
    "diratime",
    "dirsync",
    "exec",
    "idmap",
    "iversion",
    "lazytime",
    "loud",
    "mand",
    "noacl",
    "noatime",
    "nodev",
    "nodiratime",
    "noexec",
    "nofail",
    "noiversion",
    "nolazytime",
    "nomand",
    "norelatime",
    "nostrictatime",
    "nosuid",
    "nosymfollow",
    "private",
    "rbind",
    "relatime",
    "remount",
    "ro",
    "rprivate",
    "rshared",
    "rslave",
    "runbindable",
    "rw",
    "shared",
    "silent",
    "slave",
    "strictatime",
    "suid",
    "symfollow",
    "sync",
    "tmpcopyup",
    "unbindable",
];

/// The seccomp actions this kernel recognises.
fn available_actions() -> impl Iterator<Item = &'static str> {
    let candidates = [
        ("SCMP_ACT_KILL", 0x0000_0000u32),
        ("SCMP_ACT_KILL_PROCESS", 0x8000_0000),
        ("SCMP_ACT_KILL_THREAD", 0x0000_0000),
        ("SCMP_ACT_TRAP", 0x0003_0000),
        ("SCMP_ACT_ERRNO", 0x0005_0000),
        ("SCMP_ACT_TRACE", 0x7ff0_0000),
        ("SCMP_ACT_LOG", 0x7ffc_0000),
        ("SCMP_ACT_ALLOW", 0x7fff_0000),
        ("SCMP_ACT_NOTIFY", 0x7fc0_0000),
    ];
    candidates
        .into_iter()
        .filter(|(_, value)| crate::sys::seccomp::action_available(*value))
        .map(|(name, _)| name)
}

/// The seccomp filter flags this kernel accepts.
///
/// `WAIT_KILLABLE_RECV` governs how a notification is delivered, so the kernel
/// refuses it without a listener and probing it alone would report a flag it
/// supports as missing. It is asked for beside the listener flag instead.
fn available_flags() -> impl Iterator<Item = &'static str> {
    use crate::sys::seccomp::{FLAG_NEW_LISTENER, FLAG_WAIT_KILLABLE_RECV};

    crate::seccomp::FLAGS.into_iter().filter_map(|(name, bit)| {
        let asked = if bit == FLAG_WAIT_KILLABLE_RECV {
            bit | FLAG_NEW_LISTENER
        } else {
            bit
        };
        crate::sys::seccomp::flags_available(asked).then_some(name)
    })
}

fn systemd_available() -> bool {
    path_exists("/run/systemd/private") || path_exists("/run/systemd/system")
}

/// The NUMA policy modes a configuration may name.
///
/// Listed here and resolved in the lowering tables; the two are checked
/// against each other by a test, because a mode reported and not accepted
/// is worse than one that was never advertised.
const MEMORY_POLICY_MODES: [&str; 7] = [
    "MPOL_DEFAULT",
    "MPOL_BIND",
    "MPOL_INTERLEAVE",
    "MPOL_WEIGHTED_INTERLEAVE",
    "MPOL_PREFERRED",
    "MPOL_PREFERRED_MANY",
    "MPOL_LOCAL",
];

/// The NUMA policy flags a configuration may name.
const MEMORY_POLICY_FLAGS: [&str; 3] = [
    "MPOL_F_NUMA_BALANCING",
    "MPOL_F_RELATIVE_NODES",
    "MPOL_F_STATIC_NODES",
];

/// The `linux` half of the report.
///
/// Split out because it is most of the document: everything the kernel
/// side of the runtime can be asked to do is enumerated here.
fn linux_section(json: &mut Writer) {
    json.object(Some("linux"));
    json.string_array(
        "namespaces",
        [
            "cgroup", "ipc", "mount", "network", "pid", "user", "uts", "time",
        ],
    );
    json.string_array("capabilities", crate::sys::caps::NAMES);

    let layout = crate::cgroup::Layout::detect().ok();
    json.object(Some("cgroup"));
    json.boolean(
        Some("v1"),
        layout.is_some_and(crate::cgroup::Layout::has_legacy),
    );
    json.boolean(
        Some("v2"),
        layout.is_some_and(crate::cgroup::Layout::has_unified),
    );
    json.boolean(Some("systemd"), systemd_available());
    json.boolean(Some("systemdUser"), false);
    json.end_object();

    json.object(Some("seccomp"));
    json.boolean(Some("enabled"), true);
    json.string_array("actions", available_actions());
    json.string_array(
        "operators",
        [
            "SCMP_CMP_NE",
            "SCMP_CMP_LT",
            "SCMP_CMP_LE",
            "SCMP_CMP_EQ",
            "SCMP_CMP_GE",
            "SCMP_CMP_GT",
            "SCMP_CMP_MASKED_EQ",
        ],
    );
    json.string_array("archs", arch::ALL.iter().map(|a| a.name()));
    json.string_array(
        "knownFlags",
        crate::seccomp::FLAGS.iter().map(|(name, _)| *name),
    );
    json.string_array("supportedFlags", available_flags());
    json.end_object();

    json.object(Some("apparmor"));
    json.boolean(
        Some("enabled"),
        path_exists("/sys/kernel/security/apparmor"),
    );
    json.end_object();

    json.object(Some("selinux"));
    json.boolean(Some("enabled"), path_exists("/sys/fs/selinux"));
    json.end_object();

    json.object(Some("mountExtensions"));
    json.object(Some("idmap"));
    json.boolean(Some("enabled"), true);
    json.end_object();
    json.end_object();

    // Implemented, so it is reported. A caller that probes for it and finds
    // nothing has to assume it is absent and either refuse a configuration
    // that would have worked or apply it and hope.
    json.object(Some("memoryPolicy"));
    json.boolean(Some("enabled"), true);
    json.string_array("modes", MEMORY_POLICY_MODES);
    json.string_array("flags", MEMORY_POLICY_FLAGS);
    json.end_object();

    // Checked against the host rather than against what was compiled in:
    // the allocation needs hardware support and an administrator who
    // mounted the filesystem, and a caller told otherwise would send a
    // configuration that cannot be applied.
    json.object(Some("intelRdt"));
    json.boolean(Some("enabled"), crate::rdt::available());
    json.end_object();

    json.object(Some("netDevices"));
    json.boolean(Some("enabled"), false);
    json.end_object();
    json.end_object();
}

fn path_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}
