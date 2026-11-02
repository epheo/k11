//! Load, size, verify and attach the eBPF probe, and report what the running
//! kernel supports.
//!
//! Tracepoints are the baseline and must work. Everything above them is
//! probed and degrades: a syscall variant the kernel lacks is skipped, the
//! LSM layer (canonical paths, enforcement) is left off when BTF or BPF LSM
//! is missing, and in-kernel path resolution is left off when BTF lacks a
//! field it needs.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use k11_common::{
    Syscall, COMM_LEN, KOFF_COUNT, OFF_EXEC_FILENAME, OFF_FORK_CHILD_PID, STAT_COUNT, SYSCALLS,
    SYSCALL_EXIT_PROG,
};
use tracing::info;

use crate::btf_offsets;
use crate::config::Config;
use crate::lineage::{self, SeededProcess};
use crate::policy::PolicyMaps;
use crate::tracefs::Tracefs;

const SCHED_PROGRAMS: &[(&str, &str)] = &[
    ("k11_fork", "sched_process_fork"),
    ("k11_exec", "sched_process_exec"),
    ("k11_exit", "sched_process_exit"),
];
const LSM_PROG: &str = "k11_lsm_file_open";
const LSM_HOOK: &str = "file_open";

/// Names for the probe's per-CPU counters, in `STAT_*` index order.
pub const STAT_NAMES: [&str; STAT_COUNT as usize] = [
    "ring_full",
    "pending_full",
    "lineage_full",
    "read_failed",
    "enter_stash",
    "exit_orphan",
    "exit_submit",
];

pub struct Capabilities {
    pub kernel: String,
    pub ring_buffer_kb: u32,
    pub programs: usize,
    /// Why the LSM layer is off, or None when it is loaded.
    pub lsm_unavailable: Option<String>,
    pub syscalls: Vec<(&'static Syscall, bool)>,
}

impl Capabilities {
    pub fn report(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "kernel:       {}", self.kernel);
        let _ = writeln!(
            out,
            "programs:     {} loaded, verifier accepted",
            self.programs
        );
        let _ = writeln!(out, "ring buffer:  {} KB", self.ring_buffer_kb);
        let present: Vec<_> = self
            .syscalls
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(s, _)| s.name)
            .collect();
        let missing: Vec<_> = self
            .syscalls
            .iter()
            .filter(|(_, ok)| !*ok)
            .map(|(s, _)| s.name)
            .collect();
        let _ = writeln!(
            out,
            "syscalls:     {}/{} present: {}",
            present.len(),
            self.syscalls.len(),
            present.join(" ")
        );
        if !missing.is_empty() {
            let _ = writeln!(
                out,
                "              not on this kernel: {}",
                missing.join(" ")
            );
        }
        match &self.lsm_unavailable {
            None => {
                let _ = writeln!(
                    out,
                    "lsm:          file_open hook loaded: canonical paths, deny rules, enforcement"
                );
            }
            Some(reason) => {
                let _ = writeln!(out, "lsm:          off ({reason})");
                let _ = writeln!(
                    out,
                    "              opens are recorded as requested; deny rules cannot apply"
                );
            }
        }
        let _ = writeln!(
            out,
            "paths:        successful opens canonical via the LSM hook; failed opens and"
        );
        let _ = writeln!(
            out,
            "              metadata syscalls resolve relative paths via /proc"
        );
        out
    }
}

pub struct Probe {
    ebpf: Ebpf,
    lsm_loaded: bool,
    pub ring: RingBuf<MapData>,
    stats: PerCpuArray<MapData, u64>,
    pub policy: Arc<Mutex<PolicyMaps>>,
    pub seeded: Vec<SeededProcess>,
    pub capabilities: Capabilities,
}

impl Probe {
    /// Load and verify every program this kernel can host. Nothing is
    /// attached yet, so `--check` can stop here.
    pub fn load(config: &Config) -> Result<Self> {
        let tracefs = Tracefs::open()?;
        let sched = tracefs.sched_offsets()?;
        let syscalls: Vec<(&'static Syscall, bool)> = SYSCALLS
            .iter()
            .map(|sc| tracefs.check_syscall(sc).map(|present| (sc, present)))
            .collect::<Result<_>>()?;

        let mut k_offsets = [0u32; KOFF_COUNT];
        let mut lsm_unavailable = match btf_offsets::discover() {
            Ok(offsets) => {
                k_offsets = offsets.values;
                match (offsets.lsm_ready(), bpf_lsm_enabled()) {
                    (false, _) => Some(format!("BTF lacks {}", offsets.missing().join(", "))),
                    (true, Err(reason)) => Some(reason),
                    (true, Ok(())) => None,
                }
            }
            Err(e) => Some(format!("{e:#}")),
        };

        // Watch-all must hold every live task in the lineage map; the probe's
        // static default suits a single agent tree. Enlarge it only then.
        let watch_all = config.watch.binaries.is_empty();
        let mut loader = EbpfLoader::new();
        loader
            .set_max_entries("EVENTS", config.ring_buffer_bytes())
            .set_global("K_OFFSETS", &k_offsets[..], true);
        if watch_all {
            loader.set_max_entries("WATCHED_PIDS", config.probe.max_tracked_pids);
        }
        let mut ebpf = loader
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/k11-ebpf"
            )))
            .context("failed to load the eBPF object")?;

        {
            let mut offsets: Array<&mut MapData, u32> =
                Array::try_from(ebpf.map_mut("OFFSETS").context("OFFSETS map not found")?)?;
            offsets.set(OFF_FORK_CHILD_PID, sched.fork_child_pid, 0)?;
            offsets.set(OFF_EXEC_FILENAME, sched.exec_filename, 0)?;
        }

        let seeded = if watch_all {
            info!(
                max_tracked_pids = config.probe.max_tracked_pids,
                "no watch.binaries configured: watching all processes"
            );
            Vec::new()
        } else {
            info!(binaries = ?config.watch.binaries, "filtering by process lineage");
            let mut comms: BpfHashMap<&mut MapData, [u8; COMM_LEN], u8> = BpfHashMap::try_from(
                ebpf.map_mut("WATCH_COMMS")
                    .context("WATCH_COMMS map not found")?,
            )?;
            lineage::load_watch_comms(&mut comms, &config.watch.binaries)?;
            let mut pids: BpfHashMap<&mut MapData, u32, u32> = BpfHashMap::try_from(
                ebpf.map_mut("WATCHED_PIDS")
                    .context("WATCHED_PIDS map not found")?,
            )?;
            lineage::seed_from_proc(&mut pids, &config.watch.binaries)?
        };

        // Load (verify) every program before any map is taken or attached.
        // Some enter programs serve several syscalls; load each once.
        let enter_programs: BTreeSet<&str> = syscalls
            .iter()
            .filter(|(_, present)| *present)
            .map(|(sc, _)| sc.enter_prog)
            .collect();
        let mut programs = 0;
        for name in &enter_programs {
            load_tracepoint(&mut ebpf, name)?;
            programs += 1;
        }
        load_tracepoint(&mut ebpf, SYSCALL_EXIT_PROG)?;
        programs += 1;
        for (prog, _) in SCHED_PROGRAMS {
            load_tracepoint(&mut ebpf, prog)?;
            programs += 1;
        }
        let mut lsm_loaded = false;
        if lsm_unavailable.is_none() {
            match load_lsm(&mut ebpf) {
                Ok(()) => {
                    lsm_loaded = true;
                    programs += 1;
                }
                Err(e) => lsm_unavailable = Some(format!("{e:#}")),
            }
        }

        // Policy owns CONFIG and the deny maps; written before attach so the
        // first event sees the final flags.
        let policy = PolicyMaps::new(&mut ebpf, &config.policy, watch_all, lsm_loaded)?;
        let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map not found")?)?;
        let stats = PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map not found")?)?;

        Ok(Self {
            ebpf,
            lsm_loaded,
            ring,
            stats,
            policy: Arc::new(Mutex::new(policy)),
            seeded,
            capabilities: Capabilities {
                kernel: kernel_release(),
                ring_buffer_kb: config.probe.ring_buffer_kb,
                programs,
                lsm_unavailable,
                syscalls,
            },
        })
    }

    /// Start recording. Exit programs go live before their enter programs
    /// so no record is parked without something to finish it.
    pub fn attach(&mut self) -> Result<()> {
        for (prog, tracepoint) in SCHED_PROGRAMS {
            attach_tracepoint(&mut self.ebpf, prog, "sched", tracepoint)?;
        }
        for (sc, present) in &self.capabilities.syscalls {
            if !present {
                continue;
            }
            attach_tracepoint(
                &mut self.ebpf,
                SYSCALL_EXIT_PROG,
                "syscalls",
                &format!("sys_exit_{}", sc.name),
            )?;
            attach_tracepoint(
                &mut self.ebpf,
                sc.enter_prog,
                "syscalls",
                &format!("sys_enter_{}", sc.name),
            )?;
        }
        if self.lsm_loaded {
            let prog: &mut Lsm = self
                .ebpf
                .program_mut(LSM_PROG)
                .context("LSM program vanished")?
                .try_into()?;
            prog.attach()
                .with_context(|| format!("failed to attach {LSM_PROG} to LSM hook {LSM_HOOK}"))?;
        }
        Ok(())
    }

    /// Per-CPU counters summed, in `STAT_NAMES` order.
    pub fn stats(&self) -> Result<[u64; STAT_COUNT as usize]> {
        let mut out = [0u64; STAT_COUNT as usize];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.stats.get(&(i as u32), 0)?.iter().sum();
        }
        Ok(out)
    }
}

fn load_tracepoint(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("{name} not found in eBPF object"))?
        .try_into()?;
    prog.load()
        .with_context(|| format!("verifier rejected {name}"))
}

fn attach_tracepoint(ebpf: &mut Ebpf, name: &str, category: &str, tracepoint: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("{name} not found in eBPF object"))?
        .try_into()?;
    prog.attach(category, tracepoint)
        .with_context(|| format!("failed to attach {name} to {category}/{tracepoint}"))?;
    Ok(())
}

fn load_lsm(ebpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("kernel BTF unreadable")?;
    let prog: &mut Lsm = ebpf
        .program_mut(LSM_PROG)
        .with_context(|| format!("{LSM_PROG} not found in eBPF object"))?
        .try_into()?;
    prog.load(LSM_HOOK, &btf)
        .with_context(|| format!("verifier rejected {LSM_PROG}"))
}

/// Ok when the BPF LSM is active. Unreadable securityfs is not an answer,
/// so the load is attempted anyway in that case.
fn bpf_lsm_enabled() -> Result<(), String> {
    match std::fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(list) if list.split(',').any(|m| m.trim() == "bpf") => Ok(()),
        Ok(list) => Err(format!(
            "BPF LSM not enabled: active LSMs are {}; add lsm=...,bpf to the kernel command line",
            list.trim()
        )),
        Err(_) => Ok(()),
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}
