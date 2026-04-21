//! Read tracepoint field offsets from `/sys/kernel/debug/tracing/events/*/format`.
//!
//! Tracepoint field layouts differ between kernel versions, so rather than
//! hard-coding them (or baking them in via BTF, which doesn't cover syscall
//! tracepoints cleanly) we parse the kernel's self-describing `format` files
//! at daemon startup and push the offsets into the BPF `OFFSETS` map.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

#[derive(Default, Debug, Clone)]
pub struct TracepointOffsets {
    pub fork_child_pid: u32,
    pub exec_filename: u32,
    pub openat_filename: u32,
    pub openat_flags: u32,
    pub openat_ret: u32,
    pub connect_addr: u32,
    pub connect_ret: u32,
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

const TRACEFS: &str = "/sys/kernel/debug/tracing/events";

pub fn discover_offsets() -> Result<TracepointOffsets> {
    let mut o = TracepointOffsets::default();

    let fork = parse_format("sched", "sched_process_fork")?;
    o.fork_child_pid = lookup(&fork, "child_pid")?;

    let exec = parse_format("sched", "sched_process_exec")?;
    o.exec_filename = lookup(&exec, "filename")?;

    let openat_e = parse_format("syscalls", "sys_enter_openat")?;
    o.openat_filename = lookup(&openat_e, "filename")?;
    o.openat_flags = lookup(&openat_e, "flags")?;
    let openat_x = parse_format("syscalls", "sys_exit_openat")?;
    o.openat_ret = lookup(&openat_x, "ret")?;

    let connect_e = parse_format("syscalls", "sys_enter_connect")?;
    o.connect_addr = lookup(&connect_e, "uservaddr")?;
    let connect_x = parse_format("syscalls", "sys_exit_connect")?;
    o.connect_ret = lookup(&connect_x, "ret")?;

    let bind_e = parse_format("syscalls", "sys_enter_bind")?;
    o.bind_addr = lookup(&bind_e, "umyaddr")?;
    let bind_x = parse_format("syscalls", "sys_exit_bind")?;
    o.bind_ret = lookup(&bind_x, "ret")?;

    let listen_e = parse_format("syscalls", "sys_enter_listen")?;
    o.listen_backlog = lookup(&listen_e, "backlog")?;
    let listen_x = parse_format("syscalls", "sys_exit_listen")?;
    o.listen_ret = lookup(&listen_x, "ret")?;

    let unlink_e = parse_format("syscalls", "sys_enter_unlinkat")?;
    o.unlink_pathname = lookup(&unlink_e, "pathname")?;
    o.unlink_flags = lookup(&unlink_e, "flag")?;
    let unlink_x = parse_format("syscalls", "sys_exit_unlinkat")?;
    o.unlink_ret = lookup(&unlink_x, "ret")?;

    let rename_e = parse_format("syscalls", "sys_enter_renameat2")?;
    o.rename_oldname = lookup(&rename_e, "oldname")?;
    o.rename_newname = lookup(&rename_e, "newname")?;
    let rename_x = parse_format("syscalls", "sys_exit_renameat2")?;
    o.rename_ret = lookup(&rename_x, "ret")?;

    let chmod_e = parse_format("syscalls", "sys_enter_fchmodat")?;
    o.chmod_filename = lookup(&chmod_e, "filename")?;
    o.chmod_mode = lookup(&chmod_e, "mode")?;
    let chmod_x = parse_format("syscalls", "sys_exit_fchmodat")?;
    o.chmod_ret = lookup(&chmod_x, "ret")?;

    let chown_e = parse_format("syscalls", "sys_enter_fchownat")?;
    o.chown_filename = lookup(&chown_e, "filename")?;
    o.chown_uid = lookup(&chown_e, "user")?;
    o.chown_gid = lookup(&chown_e, "group")?;
    let chown_x = parse_format("syscalls", "sys_exit_fchownat")?;
    o.chown_ret = lookup(&chown_x, "ret")?;

    let symlink_e = parse_format("syscalls", "sys_enter_symlinkat")?;
    o.symlink_oldname = lookup(&symlink_e, "oldname")?;
    o.symlink_newname = lookup(&symlink_e, "newname")?;
    let symlink_x = parse_format("syscalls", "sys_exit_symlinkat")?;
    o.symlink_ret = lookup(&symlink_x, "ret")?;

    let ptrace_e = parse_format("syscalls", "sys_enter_ptrace")?;
    o.ptrace_request = lookup(&ptrace_e, "request")?;
    o.ptrace_pid = lookup(&ptrace_e, "pid")?;
    let ptrace_x = parse_format("syscalls", "sys_exit_ptrace")?;
    o.ptrace_ret = lookup(&ptrace_x, "ret")?;

    Ok(o)
}

fn parse_format(category: &str, event: &str) -> Result<Vec<(String, u32)>> {
    let path = PathBuf::from(format!("{TRACEFS}/{category}/{event}/format"));
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(extract_fields(&contents))
}

fn extract_fields(contents: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        let Some(body) = line.strip_prefix("field:") else {
            continue;
        };
        let Some(semi) = body.find(';') else { continue };
        let field_decl = &body[..semi];
        let rest = &body[semi + 1..];

        let Some(name) = extract_field_name(field_decl) else {
            continue;
        };
        let Some(offset) = rest
            .split(';')
            .find_map(|p| p.trim().strip_prefix("offset:"))
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            continue;
        };
        out.push((name, offset));
    }
    out
}

/// Extract the variable name from a C field declaration.
///
/// Examples:
///   "const char * filename"       → "filename"
///   "unsigned long arg0"          → "arg0"
///   "char common_preempt_count"   → "common_preempt_count"
///   "char parent_comm[16]"        → "parent_comm"
fn extract_field_name(decl: &str) -> Option<String> {
    let decl = decl.trim();
    // The variable name is the last C identifier, possibly followed by
    // array brackets. Walk from the end skipping brackets, then find the
    // identifier run.
    let bytes = decl.as_bytes();
    let mut end = bytes.len();
    // Strip trailing [N] or multiple dimensions.
    while end > 0 && bytes[end - 1] == b']' {
        match decl[..end].rfind('[') {
            Some(idx) => end = idx,
            None => break,
        }
    }
    // Now walk back over identifier chars.
    let mut start = end;
    while start > 0 {
        let c = bytes[start - 1] as char;
        if c.is_ascii_alphanumeric() || c == '_' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == end {
        return None;
    }
    Some(decl[start..end].to_string())
}

fn lookup(fields: &[(String, u32)], name: &str) -> Result<u32> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, o)| *o)
        .ok_or_else(|| anyhow!("tracepoint field '{name}' not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_field_name_variants() {
        assert_eq!(
            extract_field_name("const char * filename").as_deref(),
            Some("filename")
        );
        assert_eq!(
            extract_field_name("unsigned long arg0").as_deref(),
            Some("arg0")
        );
        assert_eq!(
            extract_field_name("char parent_comm[16]").as_deref(),
            Some("parent_comm")
        );
        assert_eq!(
            extract_field_name("unsigned short common_type").as_deref(),
            Some("common_type")
        );
    }

    #[test]
    fn parse_fork_format() {
        let input = "name: sched_process_fork\n\
ID: 305\n\
format:\n\
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:1;\n\
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:1;\n\
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;\n";
        let fields = extract_fields(input);
        let map: std::collections::HashMap<_, _> = fields.iter().cloned().collect();
        assert_eq!(map.get("child_pid"), Some(&44));
        assert_eq!(map.get("parent_pid"), Some(&24));
        assert_eq!(map.get("parent_comm"), Some(&8));
    }
}
