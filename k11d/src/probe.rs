//! Load, size, verify and attach the eBPF probe, and report what the running
//! kernel supports.
//!
//! Tracepoints are the baseline and must work. Everything above them is
//! probed and degrades: a syscall variant the kernel lacks is skipped, the
//! LSM layer (canonical paths, enforcement) is left off when BTF or BPF LSM
//! is missing, and process exits fall back to the leader's exit when the
//! kernel does not report `group_dead`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use k11_common::{
    Syscall, KOFF_COUNT, OFF_EXIT_GROUP_DEAD, STAT_COUNT, SYSCALLS, SYSCALL_EXIT_PROG,
};
use tracing::info;

use crate::btf_offsets;
use crate::config::Config;
use crate::lineage::{self, Lineage, SeededProcess};
use crate::policy::PolicyMaps;
use crate::tracefs::Tracefs;

/// (program, category, tracepoint) for process lifecycle.
const LIFECYCLE_PROGRAMS: &[(&str, &str, &str)] = &[
    ("k11_fork", "task", "task_newtask"),
    ("k11_exec", "sched", "sched_process_exec"),
    ("k11_exit", "sched", "sched_process_exit"),
];
const LSM_PROG: &str = "k11_lsm_file_open";
/// In-flight syscalls host-wide with watch.all (592 bytes each, preallocated).
const WATCH_ALL_PENDING: u32 = 10240;
const LSM_HOOK: &str = "file_open";

/// Names for the probe's per-CPU counters, in `STAT_*` index order.
pub const STAT_NAMES: [&str; STAT_COUNT as usize] =
    ["ring_full", "pending_full", "lineage_full", "read_failed"];

pub struct Capabilities {
    pub kernel: String,
    pub ring_buffer_kb: u32,
    pub programs: usize,
    /// The kernel reports when a thread's exit ends its process.
    pub group_dead: bool,
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
        let _ = writeln!(
            out,
            "exits:        {}",
            if self.group_dead {
                "process ends with its last thread (group_dead)"
            } else {
                "leader exit ends the process (kernel lacks group_dead)"
            }
        );
        match &self.lsm_unavailable {
            None => {
                let _ = writeln!(
                    out,
                    "lsm:          file_open hook loaded: canonical paths, deny rules, enforcement"
                );
                let _ = writeln!(
                    out,
                    "paths:        successful opens canonical; failed opens and metadata"
                );
                let _ = writeln!(
                    out,
                    "              syscalls resolve relative paths via /proc"
                );
            }
            Some(reason) => {
                let _ = writeln!(out, "lsm:          off ({reason})");
                let _ = writeln!(out, "              deny rules cannot apply");
                let _ = writeln!(
                    out,
                    "paths:        as requested; relative paths resolved via /proc"
                );
            }
        }
        out
    }
}

pub struct Probe {
    ebpf: Ebpf,
    lsm_loaded: bool,
    pub ring: RingBuf<MapData>,
    stats: PerCpuArray<MapData, u64>,
    pub policy: Arc<Mutex<PolicyMaps>>,
    pub lineage: Arc<Mutex<Lineage>>,
    pub seeded: Vec<SeededProcess>,
    pub capabilities: Capabilities,
}

impl Probe {
    /// Load and verify every program this kernel can host. Nothing is
    /// attached yet, so `--check` can stop here.
    pub fn load(config: &Config) -> Result<Self> {
        let object = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/k11-ebpf"));
        if object.is_empty() {
            bail!("this k11 was built without the BPF probe; build it with: cargo xtask build");
        }
        raise_memlock();
        let tracefs = Tracefs::open()?;
        let field_offsets = tracefs.field_offsets()?;
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
        // static default suits sessions and watched binaries.
        let watch_all = config.watch.all;
        let mut loader = EbpfLoader::new();
        loader
            .set_max_entries("EVENTS", config.ring_buffer_bytes())
            .set_global("K_OFFSETS", &k_offsets[..], true);
        if watch_all {
            loader
                .set_max_entries("WATCHED_PIDS", config.probe.max_tracked_pids)
                .set_max_entries("PENDING", WATCH_ALL_PENDING);
        }
        let mut ebpf = loader
            .load(object)
            .context("failed to load the eBPF object")?;

        {
            let mut offsets: Array<&mut MapData, u32> =
                Array::try_from(ebpf.map_mut("OFFSETS").context("OFFSETS map not found")?)?;
            for (index, &offset) in field_offsets.iter().enumerate() {
                offsets.set(index as u32, offset, 0)?;
            }
        }

        if watch_all {
            info!(
                max_tracked_pids = config.probe.max_tracked_pids,
                "watching all processes"
            );
        } else {
            info!(binaries = ?config.watch.binaries, "watching k11 run sessions and these binaries");
        }
        lineage::load_watch_comms(&mut ebpf, &config.watch.binaries)?;
        let mut lineage = Lineage::take(&mut ebpf)?;
        let seeded = lineage.seed_from_proc(&config.watch.binaries)?;

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
        for (prog, _, _) in LIFECYCLE_PROGRAMS {
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
            lineage: Arc::new(Mutex::new(lineage)),
            seeded,
            capabilities: Capabilities {
                kernel: kernel_release(),
                ring_buffer_kb: config.probe.ring_buffer_kb,
                programs,
                group_dead: field_offsets[OFF_EXIT_GROUP_DEAD as usize] != 0,
                lsm_unavailable,
                syscalls,
            },
        })
    }

    /// Start recording. Exit programs go live before their enter programs
    /// so no record is parked without something to finish it.
    pub fn attach(&mut self) -> Result<()> {
        for (prog, category, tracepoint) in LIFECYCLE_PROGRAMS {
            attach_tracepoint(&mut self.ebpf, prog, category, tracepoint)?;
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

/// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK, whose default is
/// far below what the maps need; later kernels ignore it.
fn raise_memlock() {
    let unlimited = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a valid rlimit; failure leaves the limit as it was.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) } != 0 {
        tracing::debug!("could not raise RLIMIT_MEMLOCK; kernels before 5.11 may refuse the maps");
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}
