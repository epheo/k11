use std::fs;

use anyhow::Result;
use aya::maps::{Array, HashMap};
use k11_common::{COMM_LEN, CONFIG_WATCH_ALL};
use tracing::info;

/// A process discovered by scanning /proc at startup.
pub struct SeededProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub root_pid: u32,
    pub comm: String,
}

/// Populate the WATCH_COMMS BPF map from config's binary names.
pub fn load_watch_comms(
    watch_comms: &mut HashMap<&mut aya::maps::MapData, [u8; COMM_LEN], u8>,
    binaries: &[String],
) -> Result<()> {
    for name in binaries {
        let mut key = [0u8; COMM_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(COMM_LEN);
        key[..len].copy_from_slice(&bytes[..len]);
        watch_comms.insert(key, 1, 0)?;
        info!(comm = %name, "watching comm");
    }
    Ok(())
}

/// Set the CONFIG watch_all flag.
pub fn set_watch_all(
    config_map: &mut Array<&mut aya::maps::MapData, u32>,
    enabled: bool,
) -> Result<()> {
    let val = if enabled { CONFIG_WATCH_ALL } else { 0 };
    config_map.set(0, val, 0)?;
    Ok(())
}

/// Scan /proc for running processes matching the watch list, seed WATCHED_PIDS.
/// Returns the discovered process lineage so the userspace store can be pre-populated.
pub fn seed_from_proc(
    watched_pids: &mut HashMap<&mut aya::maps::MapData, u32, u32>,
    binaries: &[String],
) -> Result<Vec<SeededProcess>> {
    let mut seeded = Vec::new();

    if binaries.is_empty() {
        return Ok(seeded);
    }

    let entries = fs::read_dir("/proc")?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();

        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm_path = format!("/proc/{pid}/comm");
        let comm = match fs::read_to_string(&comm_path) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };

        if binaries.iter().any(|b| b == &comm) {
            watched_pids.insert(pid, pid, 0)?;
            info!(pid, comm = %comm, "seeded watched PID from /proc");
            seeded.push(SeededProcess { pid, parent_pid: None, root_pid: pid, comm });
            seed_children(watched_pids, pid, pid, &mut seeded)?;
        }
    }

    Ok(seeded)
}

/// Recursively seed child PIDs of a watched process.
fn seed_children(
    watched_pids: &mut HashMap<&mut aya::maps::MapData, u32, u32>,
    pid: u32,
    root_pid: u32,
    seeded: &mut Vec<SeededProcess>,
) -> Result<()> {
    let task_dir = format!("/proc/{pid}/task");
    let tasks = match fs::read_dir(&task_dir) {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };

    for task in tasks.flatten() {
        let children_path = task.path().join("children");
        let children = match fs::read_to_string(&children_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for child_str in children.split_whitespace() {
            let child_pid: u32 = match child_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            watched_pids.insert(child_pid, root_pid, 0)?;
            let comm = fs::read_to_string(format!("/proc/{child_pid}/comm"))
                .map(|c| c.trim().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            info!(pid = child_pid, root = root_pid, comm = %comm, "seeded child PID");
            seeded.push(SeededProcess { pid: child_pid, parent_pid: Some(pid), root_pid, comm });
            seed_children(watched_pids, child_pid, root_pid, seeded)?;
        }
    }

    Ok(())
}
