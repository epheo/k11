//! Seed the probe's lineage maps from config and from /proc at startup.

use std::fs;

use anyhow::Result;
use aya::maps::{HashMap, MapData};
use k11_common::COMM_LEN;
use tracing::info;

/// A process discovered by scanning /proc at startup.
pub struct SeededProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub root_pid: u32,
    pub comm: String,
}

/// Populate WATCH_COMMS from config's binary names (truncated to the
/// kernel's 15-character comm like the kernel does).
pub fn load_watch_comms(
    watch_comms: &mut HashMap<&mut MapData, [u8; COMM_LEN], u8>,
    binaries: &[String],
) -> Result<()> {
    for name in binaries {
        let mut key = [0u8; COMM_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(COMM_LEN - 1);
        key[..len].copy_from_slice(&bytes[..len]);
        watch_comms.insert(key, 1, 0)?;
        info!(comm = %name, "watching comm");
    }
    Ok(())
}

/// Scan /proc for running processes matching the watch list and seed
/// WATCHED_PIDS with them and their descendants. Returns what was found so
/// the store can be pre-populated with correct parent linkage.
pub fn seed_from_proc(
    watched_pids: &mut HashMap<&mut MapData, u32, u32>,
    binaries: &[String],
) -> Result<Vec<SeededProcess>> {
    let mut seeded = Vec::new();
    for entry in fs::read_dir("/proc")?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(comm) = read_comm(pid) else { continue };
        if binaries.contains(&comm) {
            watched_pids.insert(pid, pid, 0)?;
            info!(pid, comm = %comm, "seeded watched PID from /proc");
            seeded.push(SeededProcess {
                pid,
                parent_pid: None,
                root_pid: pid,
                comm,
            });
            seed_children(watched_pids, pid, pid, &mut seeded)?;
        }
    }
    Ok(seeded)
}

fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

fn seed_children(
    watched_pids: &mut HashMap<&mut MapData, u32, u32>,
    pid: u32,
    root_pid: u32,
    seeded: &mut Vec<SeededProcess>,
) -> Result<()> {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Ok(());
    };
    for task in tasks.flatten() {
        let Ok(children) = fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        for child in children
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok())
        {
            watched_pids.insert(child, root_pid, 0)?;
            let comm = read_comm(child).unwrap_or_else(|| "<unknown>".into());
            info!(pid = child, root = root_pid, comm = %comm, "seeded child PID");
            seeded.push(SeededProcess {
                pid: child,
                parent_pid: Some(pid),
                root_pid,
                comm,
            });
            seed_children(watched_pids, child, root_pid, seeded)?;
        }
    }
    Ok(())
}
