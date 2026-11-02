//! The probe's lineage maps: which processes start a tree, and the trees
//! already running when k11 starts.

use std::fs;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use k11_common::COMM_LEN;
use tracing::info;

/// A process found by scanning /proc at startup.
pub struct SeededProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub root_pid: u32,
    pub comm: String,
}

/// Owner of WATCHED_PIDS (tgid to tree root). The probe extends trees on
/// fork and ends entries on exit; this side only plants roots.
pub struct Lineage {
    pids: HashMap<MapData, u32, u32>,
}

impl Lineage {
    pub fn take(ebpf: &mut Ebpf) -> Result<Self> {
        let map = ebpf
            .take_map("WATCHED_PIDS")
            .context("WATCHED_PIDS map not found")?;
        Ok(Self {
            pids: HashMap::try_from(map)?,
        })
    }

    /// Make `pid` the root of a new tree; its descendants follow in the probe.
    pub fn watch(&mut self, pid: u32) -> Result<()> {
        self.pids
            .insert(pid, pid, 0)
            .context("lineage map full (probe.max_tracked_pids)")
    }

    /// Seed running processes whose comm is watched, with their descendants,
    /// so trees that predate k11 are recorded from now on.
    pub fn seed_from_proc(&mut self, binaries: &[String]) -> Result<Vec<SeededProcess>> {
        let mut seeded = Vec::new();
        if binaries.is_empty() {
            return Ok(seeded);
        }
        for entry in fs::read_dir("/proc")?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(comm) = read_comm(pid) else { continue };
            if binaries.contains(&comm) {
                self.pids.insert(pid, pid, 0)?;
                info!(pid, comm = %comm, "seeded watched process from /proc");
                seeded.push(SeededProcess {
                    pid,
                    parent_pid: None,
                    root_pid: pid,
                    comm,
                });
                self.seed_children(pid, pid, &mut seeded)?;
            }
        }
        Ok(seeded)
    }

    fn seed_children(
        &mut self,
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
                self.pids.insert(child, root_pid, 0)?;
                seeded.push(SeededProcess {
                    pid: child,
                    parent_pid: Some(pid),
                    root_pid,
                    comm: read_comm(child).unwrap_or_else(|| "<unknown>".into()),
                });
                self.seed_children(child, root_pid, seeded)?;
            }
        }
        Ok(())
    }
}

/// Populate WATCH_COMMS from config's binary names (truncated to the
/// kernel's 15-character comm like the kernel does).
pub fn load_watch_comms(ebpf: &mut Ebpf, binaries: &[String]) -> Result<()> {
    let mut comms: HashMap<&mut MapData, [u8; COMM_LEN], u8> = HashMap::try_from(
        ebpf.map_mut("WATCH_COMMS")
            .context("WATCH_COMMS map not found")?,
    )?;
    for name in binaries {
        let mut key = [0u8; COMM_LEN];
        let bytes = name.as_bytes();
        let len = bytes.len().min(COMM_LEN - 1);
        key[..len].copy_from_slice(&bytes[..len]);
        comms.insert(key, 1, 0)?;
        info!(comm = %name, "watching comm");
    }
    Ok(())
}

fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}
