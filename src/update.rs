//! Changing a running container's resource limits.
//!
//! The limits arrive either as a fragment of a configuration or as individual
//! command line options. Both are turned into the same JSON and fed to the
//! same lowering `create` uses, so there is one path into the cgroup backends
//! rather than two.

use std::io::Read as _;

use anyhow::{Context as _, Result, bail};
use bumpalo::Bump;

use crate::{cli::Update, oci::json::Parser, state::Store};

/// Applies new limits to a running container.
pub fn run(store: &Store, options: &Update) -> Result<i32> {
    // The command line is checked before the container is looked up: an
    // option this runtime cannot honour is the caller's mistake whether or
    // not the container they named exists, and reporting the container
    // first would hide it.
    let (text, schema) = collect(options)?;
    let record = store.load_running(&options.id)?;
    let arena = Bump::new();
    let mut parser = Parser::new(text.as_bytes(), &arena);
    let resources = crate::oci::parse::resources(&mut parser)
        .context("parsing the new limits")?;

    let mut manager = crate::cgroup_for(&record)?;
    manager
        .apply(Some(&resources))
        .context("applying the new limits")?;

    // The cache and bandwidth allocation lives in a filesystem of its own,
    // and the container is already in a class there. A caller changing the
    // schema is changing that class, which is why the container has to have
    // been given one when it was created.
    if !schema.is_empty() {
        if record.rdt_class.is_empty() {
            bail!(
                "container {} was not created with a cache or bandwidth \
                 allocation, so there is no class to change",
                options.id
            );
        }
        let lines = format!("{}\n", schema.join("\n"));
        crate::rdt::reschedule(std::path::Path::new(&record.rdt_class), &lines)
            .context("changing the cache and bandwidth allocation")?;
    }
    Ok(0)
}

/// Produces the resources fragment to apply.
fn collect(options: &Update) -> Result<(String, Vec<String>)> {
    if let Some(source) = options.resources.as_deref() {
        let text = if source == "-" {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("reading the new limits from standard input")?;
            text
        } else {
            std::fs::read_to_string(source).with_context(|| {
                format!("reading the new limits from {source}")
            })?
        };
        return Ok((unwrap_fragment(&text), Vec::new()));
    }

    let mut memory = Vec::new();
    let mut cpu = Vec::new();
    let mut pids = Vec::new();
    let mut block_io = Vec::new();
    let mut schema: Vec<String> = Vec::new();
    for (name, value) in &options.values {
        match name.as_str() {
            "memory" => memory.push(("limit", value.clone())),
            "memory-reservation" => {
                memory.push(("reservation", value.clone()));
            }
            "memory-swap" => memory.push(("swap", value.clone())),
            // The unified hierarchy accounts kernel memory against the same
            // limit and the lowering refuses these there, which is the
            // honest answer. On the legacy hierarchy they are real files and
            // a caller adjusting them should not have to write a fragment by
            // hand to reach them.
            "kernel-memory" => memory.push(("kernel", value.clone())),
            "kernel-memory-tcp" => memory.push(("kernelTCP", value.clone())),
            "cpu-idle" => cpu.push(("idle", value.clone())),
            "blkio-weight" => block_io.push(("weight", value.clone())),
            // The cache and bandwidth allocation is not a cgroup file, so
            // it is collected here and applied separately below.
            "l3-cache-schema" | "mem-bw-schema" => {
                schema.push(value.clone());
            }
            "cpu-share" | "cpu-shares" => cpu.push(("shares", value.clone())),
            "cpu-period" => cpu.push(("period", value.clone())),
            "cpu-quota" => cpu.push(("quota", value.clone())),
            "cpu-burst" => cpu.push(("burst", value.clone())),
            "cpu-rt-period" => cpu.push(("realtimePeriod", value.clone())),
            "cpu-rt-runtime" => cpu.push(("realtimeRuntime", value.clone())),
            "cpuset-cpus" => cpu.push(("cpus", quoted(value))),
            "cpuset-mems" => cpu.push(("mems", quoted(value))),
            "pids-limit" => pids.push(("limit", value.clone())),
            other => bail!("unknown resource: --{other}"),
        }
    }

    let mut parts = Vec::new();
    for (name, fields) in [
        ("memory", &memory),
        ("cpu", &cpu),
        ("pids", &pids),
        ("blockIO", &block_io),
    ] {
        if fields.is_empty() {
            continue;
        }
        let body: Vec<String> = fields
            .iter()
            .map(|(key, value)| format!("\"{key}\": {value}"))
            .collect();
        parts.push(format!("\"{name}\": {{{}}}", body.join(", ")));
    }
    Ok((format!("{{{}}}", parts.join(", ")), schema))
}

/// Accepts both a bare resources object and a whole configuration.
///
/// Callers send both, so recognising the outer shape here is cheaper than
/// making every caller agree on one.
fn unwrap_fragment(text: &str) -> String {
    let trimmed = text.trim();
    extract(trimmed, "\"resources\"").unwrap_or_else(|| trimmed.to_owned())
}

/// Returns the object that follows `key`, by matching braces.
fn extract(text: &str, key: &str) -> Option<String> {
    let at = text.find(key)? + key.len();
    let rest = text.get(at..)?;
    let start = rest.find('{')?;
    let body = rest.get(start..)?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return body.get(..=index).map(str::to_owned);
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted(value: &str) -> String {
    format!("\"{value}\"")
}
