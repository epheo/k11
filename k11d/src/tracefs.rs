//! Parse tracepoint format files from tracefs to discover field offsets at runtime.
//!
//! This avoids hardcoding kernel struct offsets that can vary across kernel versions.
//! Format files live at `/sys/kernel/tracing/events/<cat>/<event>/format` (or the
//! legacy `/sys/kernel/debug/tracing/...` mount point).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Discovered field offsets for all tracepoints k11 attaches to.
pub struct TracepointOffsets {
    pub fork_child_pid: u32,
    pub exec_filename: u32,
    pub openat_filename: u32,
    pub openat_flags: u32,
    pub openat_ret: u32,
    pub connect_addr: u32,
    pub connect_ret: u32,
    // Tier 1+2 syscalls
    pub bind_addr: u32,
    pub bind_ret: u32,
    pub listen_backlog: u32,
    pub listen_ret: u32,
    pub unlink_pathname: u32,
    pub unlink_flags: u32,
    pub unlink_ret: u32,
    pub rename_oldname: u32,
    pub rename_newname: u32,
    pub rename_ret: u32,
    pub chmod_filename: u32,
    pub chmod_mode: u32,
    pub chmod_ret: u32,
    pub chown_filename: u32,
    pub chown_uid: u32,
    pub chown_gid: u32,
    pub chown_ret: u32,
    pub symlink_oldname: u32,
    pub symlink_newname: u32,
    pub symlink_ret: u32,
    pub ptrace_request: u32,
    pub ptrace_pid: u32,
    pub ptrace_ret: u32,
}

/// Discover tracepoint field offsets from the running kernel's tracefs.
pub fn discover_offsets() -> Result<TracepointOffsets> {
    let base = tracefs_base()?;

    let fork = parse_format(&base, "sched", "sched_process_fork")?;
    let exec = parse_format(&base, "sched", "sched_process_exec")?;
    let openat_enter = parse_format(&base, "syscalls", "sys_enter_openat")?;
    let openat_exit = parse_format(&base, "syscalls", "sys_exit_openat")?;
    let connect_enter = parse_format(&base, "syscalls", "sys_enter_connect")?;
    let connect_exit = parse_format(&base, "syscalls", "sys_exit_connect")?;

    // Tier 1+2 syscalls
    let bind_enter = parse_format(&base, "syscalls", "sys_enter_bind")?;
    let bind_exit = parse_format(&base, "syscalls", "sys_exit_bind")?;
    let listen_enter = parse_format(&base, "syscalls", "sys_enter_listen")?;
    let listen_exit = parse_format(&base, "syscalls", "sys_exit_listen")?;
    let unlink_enter = parse_format(&base, "syscalls", "sys_enter_unlinkat")?;
    let unlink_exit = parse_format(&base, "syscalls", "sys_exit_unlinkat")?;
    let rename_enter = parse_format(&base, "syscalls", "sys_enter_renameat2")?;
    let rename_exit = parse_format(&base, "syscalls", "sys_exit_renameat2")?;
    let chmod_enter = parse_format(&base, "syscalls", "sys_enter_fchmodat")?;
    let chmod_exit = parse_format(&base, "syscalls", "sys_exit_fchmodat")?;
    let chown_enter = parse_format(&base, "syscalls", "sys_enter_fchownat")?;
    let chown_exit = parse_format(&base, "syscalls", "sys_exit_fchownat")?;
    let symlink_enter = parse_format(&base, "syscalls", "sys_enter_symlinkat")?;
    let symlink_exit = parse_format(&base, "syscalls", "sys_exit_symlinkat")?;
    let ptrace_enter = parse_format(&base, "syscalls", "sys_enter_ptrace")?;
    let ptrace_exit = parse_format(&base, "syscalls", "sys_exit_ptrace")?;

    Ok(TracepointOffsets {
        fork_child_pid: lookup(&fork, "sched_process_fork", "child_pid")?,
        exec_filename: lookup(&exec, "sched_process_exec", "filename")?,
        openat_filename: lookup(&openat_enter, "sys_enter_openat", "filename")?,
        openat_flags: lookup(&openat_enter, "sys_enter_openat", "flags")?,
        openat_ret: lookup(&openat_exit, "sys_exit_openat", "ret")?,
        connect_addr: lookup(&connect_enter, "sys_enter_connect", "uservaddr")?,
        connect_ret: lookup(&connect_exit, "sys_exit_connect", "ret")?,
        bind_addr: lookup(&bind_enter, "sys_enter_bind", "umyaddr")?,
        bind_ret: lookup(&bind_exit, "sys_exit_bind", "ret")?,
        listen_backlog: lookup(&listen_enter, "sys_enter_listen", "backlog")?,
        listen_ret: lookup(&listen_exit, "sys_exit_listen", "ret")?,
        unlink_pathname: lookup(&unlink_enter, "sys_enter_unlinkat", "pathname")?,
        unlink_flags: lookup(&unlink_enter, "sys_enter_unlinkat", "flag")?,
        unlink_ret: lookup(&unlink_exit, "sys_exit_unlinkat", "ret")?,
        rename_oldname: lookup(&rename_enter, "sys_enter_renameat2", "oldname")?,
        rename_newname: lookup(&rename_enter, "sys_enter_renameat2", "newname")?,
        rename_ret: lookup(&rename_exit, "sys_exit_renameat2", "ret")?,
        chmod_filename: lookup(&chmod_enter, "sys_enter_fchmodat", "filename")?,
        chmod_mode: lookup(&chmod_enter, "sys_enter_fchmodat", "mode")?,
        chmod_ret: lookup(&chmod_exit, "sys_exit_fchmodat", "ret")?,
        chown_filename: lookup(&chown_enter, "sys_enter_fchownat", "filename")?,
        chown_uid: lookup(&chown_enter, "sys_enter_fchownat", "user")?,
        chown_gid: lookup(&chown_enter, "sys_enter_fchownat", "group")?,
        chown_ret: lookup(&chown_exit, "sys_exit_fchownat", "ret")?,
        symlink_oldname: lookup(&symlink_enter, "sys_enter_symlinkat", "oldname")?,
        symlink_newname: lookup(&symlink_enter, "sys_enter_symlinkat", "newname")?,
        symlink_ret: lookup(&symlink_exit, "sys_exit_symlinkat", "ret")?,
        ptrace_request: lookup(&ptrace_enter, "sys_enter_ptrace", "request")?,
        ptrace_pid: lookup(&ptrace_enter, "sys_enter_ptrace", "pid")?,
        ptrace_ret: lookup(&ptrace_exit, "sys_exit_ptrace", "ret")?,
    })
}

fn tracefs_base() -> Result<String> {
    for candidate in [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ] {
        if Path::new(candidate).is_dir() {
            return Ok(candidate.to_string());
        }
    }
    bail!(
        "tracefs not found at /sys/kernel/tracing/events or /sys/kernel/debug/tracing/events — \
         is tracefs mounted? does k11d have read access?"
    )
}

/// Parse a single tracepoint format file into a map of field_name → offset.
fn parse_format(
    base: &str,
    category: &str,
    event: &str,
) -> Result<HashMap<String, u32>> {
    let path = format!("{base}/{category}/{event}/format");
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {path} — check permissions (CAP_PERFMON or root)"))?;

    let mut fields = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("field:") {
            continue;
        }
        // Example line:
        //   field:pid_t child_pid;	offset:20;	size:4;	signed:1;
        let name = extract_field_name(line);
        let offset = extract_value(line, "offset:");

        if let (Some(name), Some(offset)) = (name, offset) {
            // Skip common_* fields — they're kernel-internal tracing metadata
            if !name.starts_with("common_") {
                fields.insert(name, offset);
            }
        }
    }

    Ok(fields)
}

/// Extract the field name from a format line.
/// Input:  `field:pid_t child_pid;  offset:20;  ...`
/// Output: `child_pid`
fn extract_field_name(line: &str) -> Option<String> {
    // The field declaration ends at the first ';'
    let decl = line.strip_prefix("field:")?.split(';').next()?;
    // The name is the last token before any array brackets
    // e.g. "char comm[16]" → "comm", "pid_t child_pid" → "child_pid"
    // e.g. "__data_loc char[] filename" → "filename"
    let decl = decl.trim();
    let name = decl.split_whitespace().last()?;
    // Strip array suffix: "comm[16]" → "comm"
    let name = name.split('[').next()?;
    Some(name.to_string())
}

/// Extract a numeric value following a key like "offset:" or "size:".
fn extract_value(line: &str, key: &str) -> Option<u32> {
    let rest = line.split(key).nth(1)?;
    let num_str = rest.split(';').next()?.trim();
    num_str.parse().ok()
}

fn lookup(fields: &HashMap<String, u32>, event: &str, field: &str) -> Result<u32> {
    fields.get(field).copied().with_context(|| {
        let available: Vec<_> = fields.keys().collect();
        format!(
            "field '{field}' not found in {event} tracepoint format (available: {available:?})"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORK_FORMAT: &str = r#"name: sched_process_fork
ID: 303
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:__data_loc char[] parent_comm;	offset:8;	size:4;	signed:0;
	field:pid_t parent_pid;	offset:12;	size:4;	signed:1;
	field:__data_loc char[] child_comm;	offset:16;	size:4;	signed:0;
	field:pid_t child_pid;	offset:20;	size:4;	signed:1;

print fmt: "comm=%s pid=%d child_comm=%s child_pid=%d", __get_str(parent_comm), REC->parent_pid, __get_str(child_comm), REC->child_pid"#;

    #[test]
    fn parse_fork_format() {
        let mut fields = HashMap::new();
        for line in FORK_FORMAT.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            let name = extract_field_name(line);
            let offset = extract_value(line, "offset:");
            if let (Some(name), Some(offset)) = (name, offset) {
                if !name.starts_with("common_") {
                    fields.insert(name, offset);
                }
            }
        }
        assert_eq!(fields["child_pid"], 20);
        assert_eq!(fields["parent_pid"], 12);
        assert_eq!(fields["parent_comm"], 8);
        assert_eq!(fields["child_comm"], 16);
        assert!(!fields.contains_key("common_type"));
    }

    #[test]
    fn extract_field_name_variants() {
        assert_eq!(
            extract_field_name("field:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;"),
            Some("child_pid".to_string())
        );
        assert_eq!(
            extract_field_name("field:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;"),
            Some("filename".to_string())
        );
        assert_eq!(
            extract_field_name("field:char comm[16];\toffset:8;\tsize:16;\tsigned:0;"),
            Some("comm".to_string())
        );
        assert_eq!(
            extract_field_name("field:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;"),
            Some("common_type".to_string())
        );
    }
}
