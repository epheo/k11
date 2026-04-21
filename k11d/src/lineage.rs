//! Seed BPF maps from userspace config and the live `/proc` state.
//!
//! Two responsibilities:
//!
//! 1. Push the `WATCH_COMMS` set and `CONFIG` flags into BPF so the probe
//!    knows which binaries to track and whether to watch everything.
//! 2. Scan `/proc` at startup to discover already-running processes whose
//!    ancestor is a watched binary, seed them into `WATCHED_PIDS`, and
//!    return a list so the userspace event store can be pre-populated
//!    with correct lineage before BPF events start flowing.

use std::collections::{HashMap as StdHashMap, HashSet};
use std::fs;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, MapData};
use k11_common::{CONFIG_WATCH_ALL, COMM_LEN};
use tracing::info;

/// A process discovered by the /proc scan that belongs to a watched agent tree.
pub struct SeededProcess {
    pub root_pid: u32,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub comm: String,
}

/// Toggle the WATCH_ALL bit in the CONFIG map.
pub fn set_watch_all(config: &mut Array<&mut MapData, u32>, enabled: bool) -> Result<()> {
    let current = config.get(&0, 0).unwrap_or(0);
    let next = if enabled {
        current | CONFIG_WATCH_ALL
    } else {
        current & !CONFIG_WATCH_ALL
    };
    config.set(0, next, 0)?;
    Ok(())
}

/// Populate the WATCH_COMMS hash map with the configured binary names.
pub fn load_watch_comms(
    map: &mut HashMap<&mut MapData, [u8; COMM_LEN], u8>,
    binaries: &[String],
) -> Result<()> {
    for name in binaries {
        let mut key = [0u8; COMM_LEN];
        let bytes = name.as_bytes();
        let n = bytes.len().min(COMM_LEN);
        key[..n].copy_from_slice(&bytes[..n]);
        map.insert(key, 1u8, 0)?;
    }
    info!(count = binaries.len(), "seeded WATCH_COMMS");
    Ok(())
}

/// Scan /proc for processes whose comm (or any ancestor's comm) matches one
/// of `binaries`. Seed them into WATCHED_PIDS and return metadata so the
/// store can reconstruct lineage for pre-existing processes.
pub fn seed_from_proc(
    watched: &mut HashMap<&mut MapData, u32, u32>,
    binaries: &[String],
) -> Result<Vec<SeededProcess>> {
    if binaries.is_empty() {
        return Ok(Vec::new());
    }
    let wanted: HashSet<&str> = binaries.iter().map(String::as_str).collect();

    // Snapshot every /proc/<pid>/status once, so ancestor walks are O(1) per step.
    let mut all: StdHashMap<u32, (Option<u32>, String)> = StdHashMap::new();
    for entry in fs::read_dir("/proc").context("failed to read /proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Some(info) = read_status(pid) {
            all.insert(pid, info);
        }
    }

    // Roots: direct comm match.
    let roots: HashSet<u32> = all
        .iter()
        .filter(|(_, (_, comm))| wanted.contains(comm.as_str()))
        .map(|(pid, _)| *pid)
        .collect();

    if roots.is_empty() {
        return Ok(Vec::new());
    }

    let mut seeded = Vec::new();
    for (&pid, (parent, comm)) in &all {
        if let Some(root) = find_root(pid, &all, &roots) {
            let _ = watched.insert(pid, root, 0);
            seeded.push(SeededProcess {
                root_pid: root,
                pid,
                parent_pid: *parent,
                comm: comm.clone(),
            });
        }
    }
    info!(count = seeded.len(), "seeded WATCHED_PIDS from /proc");
    Ok(seeded)
}

fn read_status(pid: u32) -> Option<(Option<u32>, String)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut comm = None;
    let mut ppid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            comm = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        }
    }
    Some((ppid, comm?))
}

fn find_root(
    pid: u32,
    all: &StdHashMap<u32, (Option<u32>, String)>,
    roots: &HashSet<u32>,
) -> Option<u32> {
    if roots.contains(&pid) {
        return Some(pid);
    }
    let mut current = pid;
    // Bound the walk so corrupt /proc state can't loop.
    for _ in 0..128 {
        let (ppid, _) = all.get(&current)?;
        let ppid = (*ppid)?;
        if ppid == 0 || ppid == current {
            return None;
        }
        if roots.contains(&ppid) {
            return Some(ppid);
        }
        current = ppid;
    }
    None
}
