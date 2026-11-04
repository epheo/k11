//! The probe's lineage maps: which program names start a tree, and which
//! processes belong to one.

use std::fs;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use k11_common::COMM_LEN;
use tracing::info;

use crate::cmdline::CommandLine;

/// A process found by scanning /proc at startup.
pub struct SeededProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub root_pid: u32,
    pub comm: String,
    pub cmd_line: Option<CommandLine>,
}

/// Owner of WATCHED_PIDS (tgid to tree root) and WATCH_COMMS (names whose
/// exec starts a tree). The probe extends trees on fork and ends entries on
/// exit; this side only plants roots.
pub struct Lineage {
    pids: HashMap<MapData, u32, u32>,
    comms: HashMap<MapData, [u8; COMM_LEN], u8>,
    names: Vec<String>,
}

impl Lineage {
    pub fn take(ebpf: &mut Ebpf) -> Result<Self> {
        let take = |ebpf: &mut Ebpf, name| {
            ebpf.take_map(name)
                .with_context(|| format!("{name} map not found"))
        };
        Ok(Self {
            pids: HashMap::try_from(take(ebpf, "WATCHED_PIDS")?)?,
            comms: HashMap::try_from(take(ebpf, "WATCH_COMMS")?)?,
            names: Vec::new(),
        })
    }

    /// The watched program names, as the kernel matches them.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Watch exactly these program names. A new name also seeds its running
    /// processes, returned for the store; a removed one starts no new tree,
    /// and trees already recorded finish recording.
    pub fn set_names(&mut self, names: &[String]) -> Result<Vec<SeededProcess>> {
        let mut wanted: Vec<String> = Vec::new();
        for name in names.iter().filter_map(|n| comm_name(n)) {
            if !wanted.contains(&name) {
                wanted.push(name);
            }
        }
        for gone in self.names.iter().filter(|n| !wanted.contains(n)) {
            let _ = self.comms.remove(&comm_key(gone));
            info!(comm = %gone, "no longer watching comm");
        }
        let added: Vec<String> = wanted
            .iter()
            .filter(|n| !self.names.contains(n))
            .cloned()
            .collect();
        for name in &added {
            self.comms
                .insert(comm_key(name), 1, 0)
                .context("too many watched names")?;
            info!(comm = %name, "watching comm");
        }
        self.names = wanted;
        self.seed_from_proc(&added)
    }

    /// Make `pid` the root of a new tree; its descendants follow in the probe.
    pub fn watch(&mut self, pid: u32) -> Result<()> {
        self.pids
            .insert(pid, pid, 0)
            .context("lineage map full (probe.max_tracked_pids)")
    }

    /// Seed running processes whose comm is watched, with their descendants,
    /// so trees that predate the name are recorded from now on.
    fn seed_from_proc(&mut self, binaries: &[String]) -> Result<Vec<SeededProcess>> {
        let mut seeded = Vec::new();
        if binaries.is_empty() {
            return Ok(seeded);
        }
        for entry in fs::read_dir("/proc")?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(comm) = read_comm(pid) else { continue };
            if binaries.contains(&comm) && self.unrecorded(pid) {
                self.pids.insert(pid, pid, 0)?;
                info!(pid, comm = %comm, "seeded watched process from /proc");
                seeded.push(SeededProcess {
                    pid,
                    parent_pid: None,
                    root_pid: pid,
                    comm,
                    cmd_line: read_cmd_line(pid),
                });
                self.seed_children(pid, pid, &mut seeded)?;
            }
        }
        Ok(seeded)
    }

    /// In no tree yet, and not k11 itself (recording the recorder feeds back).
    /// A process already in a tree stays there, as the probe does at exec.
    fn unrecorded(&self, pid: u32) -> bool {
        pid != std::process::id() && self.pids.get(&pid, 0).is_err()
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
            let children: Vec<u32> = children
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .filter(|&child| self.unrecorded(child))
                .collect();
            for child in children {
                self.pids.insert(child, root_pid, 0)?;
                seeded.push(SeededProcess {
                    pid: child,
                    parent_pid: Some(pid),
                    root_pid,
                    comm: read_comm(child).unwrap_or_else(|| "<unknown>".into()),
                    cmd_line: read_cmd_line(child),
                });
                self.seed_children(child, root_pid, seeded)?;
            }
        }
        Ok(())
    }
}

/// A program name as the kernel's comm holds it: at most 15 bytes, cut on a
/// character boundary. None for a blank name.
fn comm_name(name: &str) -> Option<String> {
    let name = name.trim();
    let mut end = name.len().min(COMM_LEN - 1);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    (end > 0).then(|| name[..end].to_string())
}

fn comm_key(name: &str) -> [u8; COMM_LEN] {
    let mut key = [0u8; COMM_LEN];
    key[..name.len()].copy_from_slice(name.as_bytes());
    key
}

fn read_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

/// What /proc shows now: a process may have rewritten its argv since exec.
fn read_cmd_line(pid: u32) -> Option<CommandLine> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    CommandLine::parse(&bytes, bytes.len())
}

#[cfg(test)]
mod tests {
    use super::comm_name;

    #[test]
    fn names_are_cut_as_the_kernel_cuts_comm() {
        assert_eq!(comm_name(" claude ").as_deref(), Some("claude"));
        assert_eq!(
            comm_name("a-very-long-agent-name").as_deref(),
            Some("a-very-long-age")
        );
        assert_eq!(comm_name("   "), None);
        assert_eq!(
            comm_name("aaaaaaaaaaaaaa\u{e9}").as_deref(),
            Some("aaaaaaaaaaaaaa")
        );
    }
}
