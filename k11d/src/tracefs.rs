//! Tracepoint layouts on the running kernel, read from tracefs.
//!
//! sched_* records changed layout across kernel versions, so their field
//! offsets are read here and handed to the probe through a map. syscalls/*
//! records have had one layout on 64-bit kernels since they were introduced
//! (argument slots from offset 16, return value at 16); the probe relies on
//! it and this module proves it holds before anything is attached.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use k11_common::{syscall_arg_offset, Syscall, SYSCALL_RET_OFFSET};

pub struct Tracefs {
    events: PathBuf,
}

pub struct SchedOffsets {
    pub fork_child_pid: u32,
    pub exec_filename: u32,
}

type Fields = HashMap<String, u32>;

impl Tracefs {
    pub fn open() -> Result<Self> {
        for candidate in [
            "/sys/kernel/tracing/events",
            "/sys/kernel/debug/tracing/events",
        ] {
            let events = Path::new(candidate);
            if events.is_dir() {
                return Ok(Self {
                    events: events.into(),
                });
            }
        }
        bail!(
            "tracefs not found at /sys/kernel/tracing/events or \
             /sys/kernel/debug/tracing/events: is tracefs mounted, and does \
             k11d run as root?"
        )
    }

    pub fn sched_offsets(&self) -> Result<SchedOffsets> {
        let fork = self.format("sched", "sched_process_fork")?;
        let exec = self.format("sched", "sched_process_exec")?;
        Ok(SchedOffsets {
            fork_child_pid: lookup(&fork, "sched_process_fork", "child_pid")?,
            exec_filename: lookup(&exec, "sched_process_exec", "filename")?,
        })
    }

    /// Ok(true) when both tracepoints exist and match the layout the probe
    /// reads, Ok(false) when this kernel has no such syscall, Err when the
    /// layout differs (attaching would read garbage).
    pub fn check_syscall(&self, sc: &Syscall) -> Result<bool> {
        let enter = format!("sys_enter_{}", sc.name);
        let Some(fields) = self.format_if_present("syscalls", &enter)? else {
            return Ok(false);
        };
        verify_enter(&fields, sc)?;
        let exit = format!("sys_exit_{}", sc.name);
        verify_exit(&self.format("syscalls", &exit)?, &exit)?;
        Ok(true)
    }

    fn format(&self, category: &str, event: &str) -> Result<Fields> {
        self.format_if_present(category, event)?
            .with_context(|| format!("tracepoint {category}/{event} not found on this kernel"))
    }

    fn format_if_present(&self, category: &str, event: &str) -> Result<Option<Fields>> {
        let path = self.events.join(category).join(event).join("format");
        match fs::read_to_string(&path) {
            Ok(content) => Ok(Some(parse_format(&content))),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| {
                format!(
                    "failed to read {}: needs root or CAP_PERFMON",
                    path.display()
                )
            }),
        }
    }
}

fn verify_enter(fields: &Fields, sc: &Syscall) -> Result<()> {
    let enter = format!("sys_enter_{}", sc.name);
    for (index, name) in sc.args {
        let offset = lookup(fields, &enter, name)?;
        let expected = syscall_arg_offset(*index) as u32;
        if offset != expected {
            bail!("{enter}: field {name} is at offset {offset}, the probe reads slot {index} at {expected}");
        }
    }
    Ok(())
}

fn verify_exit(fields: &Fields, exit: &str) -> Result<()> {
    let offset = lookup(fields, exit, "ret")?;
    if offset as usize != SYSCALL_RET_OFFSET {
        bail!("{exit}: ret is at offset {offset}, the probe reads {SYSCALL_RET_OFFSET}");
    }
    Ok(())
}

/// field name to offset, skipping the common_* tracing header fields.
fn parse_format(content: &str) -> Fields {
    content
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            // field:pid_t child_pid;	offset:20;	size:4;	signed:1;
            let decl = line.strip_prefix("field:")?.split(';').next()?.trim();
            let name = decl.split_whitespace().last()?.split('[').next()?;
            let offset = line
                .split("offset:")
                .nth(1)?
                .split(';')
                .next()?
                .trim()
                .parse()
                .ok()?;
            (!name.starts_with("common_")).then(|| (name.to_string(), offset))
        })
        .collect()
}

fn lookup(fields: &Fields, event: &str, field: &str) -> Result<u32> {
    fields.get(field).copied().with_context(|| {
        let available: Vec<_> = fields.keys().collect();
        format!("field '{field}' not found in {event} tracepoint format (available: {available:?})")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k11_common::SYSCALLS;

    const FORK_FORMAT: &str = "name: sched_process_fork
ID: 303
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;
\tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;

print fmt: \"comm=%s pid=%d\", __get_str(parent_comm), REC->parent_pid";

    const OPENAT_ENTER: &str = "
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;
\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;
\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;
\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;
\tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;";

    const OPENAT_EXIT: &str = "
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;
\tfield:long ret;\toffset:16;\tsize:8;\tsigned:1;";

    fn syscall(name: &str) -> &'static Syscall {
        SYSCALLS.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn parses_fields_and_skips_common_header() {
        let fields = parse_format(FORK_FORMAT);
        assert_eq!(fields["child_pid"], 20);
        assert_eq!(fields["parent_pid"], 12);
        assert_eq!(fields["parent_comm"], 8);
        assert!(!fields.contains_key("common_type"));
    }

    #[test]
    fn strips_array_suffix() {
        let fields = parse_format("\tfield:char comm[16];\toffset:8;\tsize:16;\tsigned:0;");
        assert_eq!(fields["comm"], 8);
    }

    #[test]
    fn accepts_fixed_syscall_layout() {
        verify_enter(&parse_format(OPENAT_ENTER), syscall("openat")).unwrap();
        verify_exit(&parse_format(OPENAT_EXIT), "sys_exit_openat").unwrap();
    }

    #[test]
    fn rejects_shifted_syscall_layout() {
        let shifted = OPENAT_ENTER.replace("offset:24", "offset:28");
        assert!(verify_enter(&parse_format(&shifted), syscall("openat")).is_err());
        let shifted = OPENAT_EXIT.replace("offset:16", "offset:24");
        assert!(verify_exit(&parse_format(&shifted), "sys_exit_openat").is_err());
    }

    #[test]
    fn rejects_missing_field() {
        let fields = parse_format("\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;");
        assert!(verify_enter(&fields, syscall("openat")).is_err());
    }
}
