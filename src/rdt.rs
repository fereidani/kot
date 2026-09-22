//! Cache and memory-bandwidth partitioning, through `resctrl`.
//!
//! The kernel exposes this as a filesystem: a directory is a class of
//! service, its `schemata` file states how much of the shared cache and of
//! the memory bandwidth that class may use, and a process joins the class by
//! having its id written into the class's `tasks` file.
//!
//! What to write is worked out here and can be checked without the
//! filesystem; where to write it is the rest of the module.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

use crate::oci::spec::IntelRdt;

/// Where the kernel mounts the control filesystem.
pub const ROOT: &str = "/sys/fs/resctrl";

/// Whether this host offers cache and bandwidth partitioning at all.
///
/// The directory exists only when the filesystem is mounted, which needs
/// both hardware support and an administrator who mounted it.
#[must_use]
pub fn available() -> bool {
    Path::new(ROOT).join("schemata").exists()
}

/// The lines to write into a class's `schemata` file.
///
/// A configuration states this either as whole lines or as the two
/// well-known ones separately. Whole lines win where both are given: they
/// are the more recent form and the more general one, and a caller that
/// wrote them meant them.
///
/// An empty result means the configuration asked for a class but no
/// allocation within it, which is legitimate: the class inherits the
/// schema it is created with, and the point was to group the container.
pub fn schemata(rdt: &IntelRdt<'_>, out: &mut String) {
    out.clear();
    if !rdt.schemata.is_empty() {
        for line in &rdt.schemata {
            out.push_str(line.trim());
            out.push('\n');
        }
        return;
    }
    for line in [rdt.l3_cache_schema, rdt.mem_bw_schema]
        .into_iter()
        .flatten()
    {
        out.push_str(line.trim());
        out.push('\n');
    }
}

/// The name of the class a container belongs to.
///
/// A configuration naming one is asking to join a class somebody else set
/// up, which is how several containers share an allocation. One that names
/// none gets a class of its own, named after the container so that two
/// containers cannot collide and so an operator can see which is which.
#[must_use]
pub fn class_of<'a>(rdt: &IntelRdt<'a>, container_id: &'a str) -> &'a str {
    match rdt.clos_id {
        Some(name) if !name.trim().is_empty() => name,
        _ => container_id,
    }
}

/// A class name has to be one directory under the filesystem root.
///
/// The name reaches the kernel as a path component. A separator in it would
/// name a directory somewhere else, and `..` would name the root itself,
/// where a schema applies to everything on the host rather than to one
/// container.
fn check_class(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("intelRdt: {name} is not a usable class name");
    }
    Ok(())
}

/// What applying an allocation created, so the caller can undo exactly
/// that and nothing more.
#[derive(Clone, Debug, Default)]
pub struct Created {
    /// The class the container is in, whoever made it.
    pub class: PathBuf,
    /// True when this runtime made that class, and so may remove it.
    pub owned: bool,
    /// The monitoring group, when this runtime made one.
    ///
    /// Separate from the class because a container may be monitored inside
    /// a class somebody else owns, and the group is still this runtime's to
    /// remove.
    pub monitor: Option<PathBuf>,
}

/// Puts a process into the class the configuration asked for.
///
/// A class the configuration named and this runtime found already there is
/// somebody else's: other containers may be in it, so it is used and left
/// alone. Only what this call made is reported back for removal.
pub fn apply(
    rdt: &IntelRdt<'_>,
    container_id: &str,
    pid: i32,
) -> Result<Created> {
    if !available() {
        bail!(
            "intelRdt: the configuration asks for cache or bandwidth \
             partitioning and {ROOT} is not mounted"
        );
    }
    let class = class_of(rdt, container_id);
    check_class(class)?;

    let directory = Path::new(ROOT).join(class);
    let ours = !directory.exists();
    if ours {
        std::fs::create_dir(&directory).with_context(|| {
            format!("creating the class {}", directory.display())
        })?;
    }

    let mut lines = String::new();
    schemata(rdt, &mut lines);
    if !lines.is_empty() {
        std::fs::write(directory.join("schemata"), &lines).with_context(
            || format!("writing the schema for the class {class}"),
        )?;
    }

    // The class first: the filesystem admits a task to a monitoring group
    // only once the class above it already holds that task, and refuses the
    // other order outright.
    write_task(&directory, pid)?;

    // Monitoring is a group of its own below the class, so that
    // the container's own usage readable apart from the class total.
    let mut made_monitor = None;
    if rdt.enable_monitoring {
        let monitor = directory.join("mon_groups").join(container_id);
        if !monitor.exists() {
            std::fs::create_dir(&monitor).with_context(|| {
                format!("creating the monitoring group for {container_id}")
            })?;
            made_monitor = Some(monitor.clone());
        }
        write_task(&monitor, pid)?;
    }
    Ok(Created {
        class: directory,
        owned: ours,
        monitor: made_monitor,
    })
}

/// Moves one process into a class or monitoring group.
fn write_task(directory: &Path, pid: i32) -> Result<()> {
    let file = directory.join("tasks");
    std::fs::write(&file, format!("{pid}\n"))
        .with_context(|| format!("adding the container to {}", file.display()))
}

/// Removes a class this runtime created.
///
/// A class the configuration named and somebody else made stays: other
/// containers may be in it, and removing it would take their allocation
/// with it.
pub fn remove(directory: &Path) {
    let _ = std::fs::remove_dir(directory);
}

/// Changes the allocation of a class that already exists.
///
/// Used by `update`, where the container is running and its class is the
/// one it was put in at creation. Nothing is created here: a class that has
/// gone means the container's allocation has gone with it, which is worth
/// reporting rather than quietly making again.
pub fn reschedule(class: &Path, lines: &str) -> Result<()> {
    if lines.trim().is_empty() {
        return Ok(());
    }
    if !class.is_dir() {
        bail!(
            "intelRdt: the class {} is not there to change",
            class.display()
        );
    }
    std::fs::write(class.join("schemata"), lines).with_context(|| {
        format!("writing the schema for the class {}", class.display())
    })
}
