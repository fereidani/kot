//! Turning a configured mount into a record the executor can apply.
//!
//! Most of the work is sorting mount options into three piles: kernel flags,
//! mount attributes, and filesystem-specific data. Doing it here means the
//! executor never sees a string it has to interpret.

use crate::{
    oci::{
        lower::tables::{self, Effect, ms},
        plan::{
            Builder,
            record::{MountKind, MountOp, mount_flag},
        },
        spec::Mount,
    },
    sys::error::{Error, Result},
};

/// Accumulated effect of a mount's options.
#[derive(Default)]
struct Options {
    ms_flags: u64,
    attr_set: u64,
    attr_clear: u64,
    propagation: u64,
    extra: u32,
    bind: Option<bool>,
    recursive_attrs: bool,
    /// The access-time mode, when one was asked for.
    ///
    /// Kept apart from the other attributes because the kernel treats it as
    /// one setting.
    atime: Option<u64>,
}

/// Lowers one mount.
///
/// `data` is scratch the caller owns, so building a plan does not allocate a
/// fresh option string per mount. `label` is the container-wide `mountLabel`,
/// which every mount that can carry one is given.
pub fn mount(
    builder: &mut Builder,
    source: &Mount<'_>,
    data: &mut String,
    cgroup_v2: bool,
    label: &str,
) -> Result<MountOp> {
    if source.destination.is_empty() {
        return Err(Error::msg("mount: destination is required"));
    }
    // A destination that is not absolute is resolved from the container's
    // root, which is where every other runtime puts it. The specification
    // asks for an absolute path, but an image builder writing a `VOLUME`
    // line the way Docker reads it produces destinations like `[/etc/foo`,
    // and a container the rest of the ecosystem runs is not one to refuse.

    let mut options = Options::default();
    data.clear();
    for option in &source.options {
        apply(option, &mut options, data);
    }

    // A bind is asked for either by the mount type or by an option, and the
    // recursive form wins wherever both appear.
    let mut kind = source.kind.unwrap_or("");
    if kind == "cgroup" && cgroup_v2 {
        // A unified host has no legacy hierarchy to mount. With a cgroup
        // namespace the substitute is rooted at the container's own cgroup,
        // which the bundle was asking for in the first place.
        kind = "cgroup2";
    }
    let is_bind = options.bind.is_some() || kind == "bind" || kind == "rbind";
    let recursive_bind = options.bind == Some(true) || kind == "rbind";

    let context = selinux_context(label, kind, is_bind, data)?;
    let mut op = MountOp {
        source: builder.intern(source.source.unwrap_or(""))?,
        target: builder.intern(source.destination)?,
        fstype: builder.intern(if is_bind { "" } else { kind })?,
        data: builder.intern(data)?,
        context: builder.intern(context)?,
        flags: options.ms_flags,
        attr_set: options.attr_set,
        attr_clr: options.attr_clear,
        propagation: options.propagation,
        kind: 0,
        idmap_fd: -1,
        extra: options.extra,
    };

    if is_bind {
        op.set_kind(if recursive_bind {
            MountKind::RecursiveBind
        } else {
            MountKind::Bind
        });
        op.flags |= ms::BIND;
        if recursive_bind {
            op.flags |= ms::REC;
        }
    } else {
        op.set_kind(MountKind::Filesystem);
        if kind.is_empty() {
            return Err(Error::msg("mount: type is required"));
        }
    }

    if let Some(mode) = options.atime {
        // Setting an access-time mode means clearing every bit of the mode and
        // setting exactly one, which is the shape the kernel checks for.
        op.attr_set |= mode;
        op.attr_clr |= crate::sys::mountattr::ATTR_ATIME_MASK;
    }
    if options.recursive_attrs {
        op.extra |= mount_flag::RECURSIVE;
    }
    // Carrying a directory's contents forward only means anything when the
    // thing covering it is a fresh empty filesystem.
    if options.extra & mount_flag::TMPCOPYUP != 0 && kind != "tmpfs" {
        return Err(Error::msg("mount: tmpcopyup needs a tmpfs"));
    }
    if options.extra & mount_flag::COPY_SYMLINK != 0 && !is_bind {
        return Err(Error::msg("mount: copy-symlink needs a bind"));
    }
    Ok(op)
}

/// The `SELinux` context a mount is given, or nothing when it takes none.
///
/// A bind carries the label of the filesystem it came from, so there is
/// nothing to set on it, and the kernel's own pseudo-filesystems refuse an
/// explicit one. A bundle that names a context itself has said what it wants
/// and is left alone.
fn selinux_context<'a>(
    label: &'a str,
    kind: &str,
    is_bind: bool,
    data: &str,
) -> Result<&'a str> {
    if label.is_empty()
        || is_bind
        || tables::labels_from_policy(kind)
        || names_a_context(data)
    {
        return Ok("");
    }
    // The older mount interface takes the label inside a quoted option, which
    // a label containing a quote would end early.
    if label.contains('"') {
        return Err(Error::msg("mountLabel: a label may not contain a quote"));
    }
    Ok(label)
}

/// True when a mount's own options already name an `SELinux` context.
fn names_a_context(data: &str) -> bool {
    data.split(',').any(|option| {
        matches!(
            option.split('=').next(),
            Some("context" | "fscontext" | "defcontext" | "rootcontext")
        )
    })
}

/// Applies one option to the accumulator.
fn apply(option: &str, out: &mut Options, data: &mut String) {
    match tables::mount_option(option) {
        Effect::Flag {
            ms_set,
            ms_clear,
            attr_set,
            attr_clear,
            recursive,
        } => {
            out.ms_flags |= ms_set;
            out.ms_flags &= !ms_clear;
            out.attr_set |= attr_set;
            out.attr_set &= !attr_clear;
            out.attr_clear |= attr_clear;
            out.attr_clear &= !attr_set;
            if recursive {
                out.recursive_attrs = true;
            }
        }
        Effect::Propagation { mode, recursive } => {
            out.propagation = mode | if recursive { ms::REC } else { 0 };
        }
        Effect::Bind { recursive } => {
            // A later `rbind` upgrades an earlier `bind`, which is how a
            // bundle that lists both means the recursive one.
            out.bind = Some(out.bind.unwrap_or(false) || recursive);
        }
        Effect::Atime(mode) => out.atime = Some(mode),
        Effect::Extra(flag) => out.extra |= flag,
        Effect::Ignore => {}
        Effect::Data => {
            if !data.is_empty() {
                data.push(',');
            }
            data.push_str(option);
        }
    }
}
