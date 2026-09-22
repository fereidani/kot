//! Building a bundle to run tests against, and driving the runtime binary.
//!
//! The container's root filesystem is mostly empty: the host's `/usr` and its
//! library directories are bound in read only, so any program on the host can
//! be the payload without a base image being fetched from anywhere. That also
//! means the bind mounts, the symbolic-link handling and the read-only
//! attributes are exercised by every test rather than by one.

use std::{
    fs::File,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

/// The runtime under test.
pub const RUNTIME: &str = env!("CARGO_BIN_EXE_kot");

/// A bundle in a temporary directory, removed when it is dropped.
pub struct Bundle {
    root: PathBuf,
    /// Unique suffix, so parallel tests cannot collide on a container id.
    tag: String,
}

impl Bundle {
    /// Creates a bundle whose payload is `args`.
    pub fn new(name: &str, args: &[&str]) -> Self {
        Self::with_config(name, args, |_| {})
    }

    /// Creates a bundle, letting the caller adjust the configuration.
    ///
    /// The configuration is handed over as text because a runtime receives
    /// text, and because a test that edits the text is testing the same path a
    /// real caller takes.
    pub fn with_config(
        name: &str,
        args: &[&str],
        adjust: impl FnOnce(&mut String),
    ) -> Self {
        let tag = format!("{name}-{}", std::process::id());
        let root = std::env::temp_dir().join(format!("kot-test-{tag}"));
        // A leftover from an earlier run is cleared the same guarded way:
        // whatever left it behind may have left a mount behind with it.
        remove_unless_mounted(&root);
        std::fs::create_dir_all(root.join("rootfs")).expect("bundle directory");

        let mut config = template(args, &root.join("rootfs"));
        adjust(&mut config);
        std::fs::write(root.join("config.json"), config).expect("config.json");
        Self { root, tag }
    }

    /// The bundle directory.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// A container id unique to this bundle.
    pub fn id(&self) -> String {
        format!("test-{}", self.tag)
    }

    /// Runs the runtime with the bundle's directory and id already supplied.
    ///
    /// The two output streams go to files rather than to pipes. `create`
    /// leaves the container's process running with the streams it was given,
    /// so a pipe stays open after the runtime itself has exited, and anything
    /// reading that pipe to end of file would wait for the container instead
    /// of for the command. Files have no such reader, and reading them back
    /// after the wait gives the same bytes a pipe would have.
    pub fn runtime(&self, args: &[&str]) -> Output {
        let out = self.root.join("stdout");
        let err = self.root.join("stderr");
        let status = Command::new(RUNTIME)
            .args(["--root", &self.state_root()])
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(File::create(&out).expect("stdout file")))
            .stderr(Stdio::from(File::create(&err).expect("stderr file")))
            .status()
            .expect("running the runtime");
        Output {
            status,
            stdout: std::fs::read(&out).unwrap_or_default(),
            stderr: std::fs::read(&err).unwrap_or_default(),
        }
    }

    /// A state root private to this bundle, so tests do not see each other's
    /// containers.
    pub fn state_root(&self) -> String {
        self.root.join("state").display().to_string()
    }

    /// Removes whatever the tests left behind.
    pub fn cleanup(&self) {
        let _ = self.runtime(&["delete", "--force", &self.id()]);
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        self.cleanup();
        remove_unless_mounted(&self.root);
    }
}

/// Removes a bundle, unless something is still mounted inside it.
///
/// The rootfs is where the host's `/usr`, `/etc` and the rest are bound, so
/// a recursive delete of the bundle walks into those mount points. While the
/// container holds them in its own mount namespace they are empty
/// directories here and there is nothing to walk into. If one ever leaks
/// into this namespace, the delete would be walking the host's own
/// filesystem, and the read-only attribute on those binds is the only thing
/// that would stop it.
///
/// That is too thin a margin for a delete running as root, so the mount
/// table is checked first. A bundle left behind in the temporary directory
/// costs nothing; the other outcome costs the machine.
fn remove_unless_mounted(root: &Path) {
    let Ok(table) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return;
    };
    let prefix = root.display().to_string();
    for line in table.lines() {
        let Some(point) = line.split_ascii_whitespace().nth(4) else {
            continue;
        };
        if point == prefix || point.starts_with(&format!("{prefix}/")) {
            eprintln!(
                "leaving {prefix} in place: {point} is still mounted, and \
                 deleting through it would reach the host"
            );
            return;
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// True when the output reports success.
pub fn succeeded(output: &Output) -> bool {
    output.status.success()
}

/// The output's standard output, as text.
pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The output's standard error, as text.
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts that a command succeeded, reporting both streams when it did not.
pub fn expect_ok(what: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{what} failed with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

/// The host directories a container needs to run a host binary.
///
/// Bound read only, which is both what a real bundle does for shared content
/// and a test of the read-only mount attribute. A host path that is itself a
/// symbolic link, as `/lib -> usr/lib` is on a merged system, becomes a link
/// in the image rather than a mount, because that is how a real base image is
/// built and because it keeps the bundle to options every runtime supports.
fn host_mounts(rootfs: &Path) -> String {
    let mut out = String::new();
    for path in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"] {
        let source = Path::new(path);
        if !source.exists() {
            continue;
        }
        if source.is_symlink() {
            if let Ok(target) = std::fs::read_link(source) {
                let name = path.trim_start_matches('/');
                let _ = std::os::unix::fs::symlink(target, rootfs.join(name));
            }
            continue;
        }
        use std::fmt::Write as _;
        let _ = write!(
            out,
            r#"    {{
      "destination": "{path}",
      "type": "bind",
      "source": "{path}",
      "options": ["rbind", "ro", "nosuid", "nodev"]
    }},
"#
        );
    }
    out
}

/// Renders a string as a JSON string body.
///
/// Payloads are shell fragments, so quotes and backslashes in them are
/// ordinary rather than exceptional.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// A configuration for the given payload.
fn template(args: &[&str], rootfs: &Path) -> String {
    let rendered: Vec<String> =
        args.iter().map(|a| format!("\"{}\"", escape(a))).collect();
    format!(
        r#"{{
  "ociVersion": "1.0.2",
  "process": {{
    "terminal": false,
    "user": {{ "uid": 0, "gid": 0 }},
    "args": [{}],
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/",
    "capabilities": {{
      "bounding": ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID", "CAP_SETGID"],
      "effective": ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID", "CAP_SETGID"],
      "permitted": ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID", "CAP_SETGID"],
      "ambient": []
    }},
    "rlimits": [{{ "type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096 }}],
    "noNewPrivileges": true
  }},
  "root": {{ "path": "rootfs", "readonly": false }},
  "hostname": "kot-test",
  "annotations": {{ "org.kot.test.marker": "present" }},
  "mounts": [
    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
    }},
    {{
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]
    }},
    {{
      "destination": "/dev/shm",
      "type": "tmpfs",
      "source": "shm",
      "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]
    }},
    {{
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": ["nosuid", "noexec", "nodev", "ro"]
    }},
    {{
      "destination": "/sys/fs/cgroup",
      "type": "cgroup",
      "source": "cgroup",
      "options": ["nosuid", "noexec", "nodev", "relatime", "ro"]
    }},
{}  ],
  "linux": {{
    "resources": {{ "devices": [{{ "allow": false, "access": "rwm" }}] }},
    "namespaces": [
      {{ "type": "pid" }},
      {{ "type": "network" }},
      {{ "type": "ipc" }},
      {{ "type": "uts" }},
      {{ "type": "mount" }},
      {{ "type": "cgroup" }}
    ],
    "maskedPaths": ["/proc/kcore", "/proc/timer_list", "/sys/firmware"],
    "readonlyPaths": ["/proc/bus", "/proc/irq", "/proc/sysrq-trigger"]
  }}
}}
"#,
        rendered.join(", "),
        host_mounts(rootfs)
    )
}
