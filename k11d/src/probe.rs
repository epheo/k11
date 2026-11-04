//! Load, size, verify and attach the eBPF probe, and report what the running
//! kernel supports.
//!
//! Tracepoints are the baseline and must work. Everything above them is
//! probed and degrades: a syscall variant the kernel lacks is skipped, the
//! LSM layer (canonical paths, enforcement) is left off when BTF or BPF LSM
//! is missing, and process exits fall back to the leader's exit when the
//! kernel does not report `group_dead`.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint, UProbe};
use aya::{Btf, Ebpf, EbpfLoader};
use k11_common::{
    Syscall, KOFF_COUNT, OFF_EXIT_GROUP_DEAD, STAT_COUNT, SYSCALLS, SYSCALL_EXIT_PROG,
};
use tracing::{info, warn};

use crate::btf_offsets::{self, ARGV_FIELDS, LSM_FIELDS};
use crate::config::Config;
use crate::cpu_cover;
use crate::lineage::{Lineage, SeededProcess};
use crate::policy::PolicyMaps;
use crate::tracefs::Tracefs;

/// (program, category, tracepoint) for process lifecycle.
const LIFECYCLE_PROGRAMS: &[(&str, &str, &str)] = &[
    ("k11_fork", "task", "task_newtask"),
    ("k11_exec", "sched", "sched_process_exec"),
    ("k11_exit", "sched", "sched_process_exit"),
];
const LSM_PROG: &str = "k11_lsm_file_open";
/// In-flight syscalls host-wide with watch.all (600 bytes each, preallocated).
const WATCH_ALL_PENDING: u32 = 10240;
const LSM_HOOK: &str = "file_open";

/// What `Probe::stats` counts: the probe's own counters in `STAT_*` order,
/// then the runs the kernel skipped. A skipped file_open run is an open no
/// deny rule checked, so it is counted apart.
pub const STAT_NAMES: [&str; STAT_COUNT as usize + 2] = [
    "ring_full",
    "pending_full",
    "lineage_full",
    "read_failed",
    "skipped",
    "skipped_file_open",
];

pub struct Capabilities {
    pub kernel: String,
    pub ring_buffer_kb: u32,
    pub programs: usize,
    /// The kernel reports when a thread's exit ends its process.
    pub group_dead: bool,
    /// Why the LSM layer is off, or None when it is loaded.
    pub lsm_unavailable: Option<String>,
    /// Why exec records carry no command line, or None when they do.
    pub argv_unavailable: Option<String>,
    /// The host's libc, where looked-up names are read; None: names are not.
    pub libc: Result<PathBuf, String>,
    pub syscalls: Vec<(&'static Syscall, bool)>,
    /// Enter tracepoints that need an event on every CPU (`cpu_cover`).
    pub cpu_cover: Vec<u64>,
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
        let _ = writeln!(
            out,
            "names:        {}",
            match &self.libc {
                Ok(libc) => format!(
                    "getaddrinfo in {} (and each container's libc)",
                    libc.display()
                ),
                Err(reason) => format!("addresses only ({reason})"),
            }
        );
        let _ = writeln!(
            out,
            "commands:     {}",
            match &self.argv_unavailable {
                None => "exec records carry the command line".to_string(),
                Some(reason) => format!("path only ({reason})"),
            }
        );
        if !self.cpu_cover.is_empty() {
            let _ = writeln!(
                out,
                "cpus:         {} syscall tracepoints opened on every CPU (kernel bug in 6.19 to 7.1)",
                self.cpu_cover.len()
            );
        }
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
    cpu_cover: Vec<OwnedFd>,
    /// libc files the getaddrinfo probes are attached to, by (device, inode).
    libcs: HashSet<(u64, u64)>,
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
        let kernel = kernel_release();
        let tracefs = Tracefs::open()?;
        let field_offsets = tracefs.field_offsets()?;
        let syscalls: Vec<(&'static Syscall, bool)> = SYSCALLS
            .iter()
            .map(|sc| tracefs.check_syscall(sc).map(|present| (sc, present)))
            .collect::<Result<_>>()?;
        // 7.2 runs syscall programs before the check `cpu_cover` works around.
        let cpu_cover: Vec<u64> = if release_before(&kernel, 7, 2) {
            syscalls
                .iter()
                .filter(|(_, present)| *present)
                .filter_map(|(sc, _)| tracefs.copying_enter_id(sc).transpose())
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };

        let mut k_offsets = [0u32; KOFF_COUNT];
        let (mut lsm_unavailable, argv_unavailable) = match btf_offsets::discover() {
            Ok(mut offsets) => {
                offsets.all_or_none(ARGV_FIELDS);
                k_offsets = offsets.values;
                let lacks = |fields| {
                    let missing = offsets.missing(fields);
                    (!missing.is_empty()).then(|| format!("BTF lacks {}", missing.join(", ")))
                };
                let lsm = lacks(LSM_FIELDS).or_else(|| bpf_lsm_enabled().err());
                (lsm, lacks(ARGV_FIELDS))
            }
            Err(e) => (Some(format!("{e:#}")), Some(format!("{e:#}"))),
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
        let mut lineage = Lineage::take(&mut ebpf)?;
        let seeded = lineage.set_names(&config.watch.binaries)?;

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
        let libc = match load_resolver(&mut ebpf) {
            Ok(()) => {
                programs += RESOLVER_PROGRAMS.len();
                host_libc().ok_or_else(|| "no libc found on the host".to_string())
            }
            Err(e) => Err(format!("{e:#}")),
        };
        let mut lsm_loaded = false;
        if lsm_unavailable.is_none() {
            match load_lsm(&mut ebpf) {
                Ok(()) => {
                    lsm_loaded = true;
                    programs += 1;
                }
                Err(e) => {
                    tracing::debug!("{e:#}");
                    lsm_unavailable = Some(if release_before(&kernel, 5, 15) {
                        "this kernel's BPF LSM cannot resolve paths (needs Linux 5.15)".into()
                    } else {
                        "the verifier rejected the file_open program; RUST_LOG=debug shows why"
                            .into()
                    });
                }
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
                kernel,
                ring_buffer_kb: config.probe.ring_buffer_kb,
                programs,
                group_dead: field_offsets[OFF_EXIT_GROUP_DEAD as usize] != 0,
                lsm_unavailable,
                argv_unavailable,
                libc,
                syscalls,
                cpu_cover,
            },
            cpu_cover: Vec::new(),
            libcs: HashSet::new(),
        })
    }

    /// Start recording. Exit programs go live before their enter programs
    /// so no record is parked without something to finish it.
    pub fn attach(&mut self) -> Result<()> {
        self.cpu_cover = cpu_cover::open(&self.capabilities.cpu_cover)?;
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
        if let Ok(libc) = self.capabilities.libc.clone() {
            self.watch_libc(&libc);
        }
        Ok(())
    }

    /// Read the names `pid` looks up: attach to the libc it maps, once per
    /// file. A container has its own; its first lookups before this can be
    /// missed.
    pub fn watch_libc_of(&mut self, pid: u32) {
        if self.capabilities.libc.is_err() {
            return;
        }
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return;
        };
        if let Some(path) = mapped_libc(&maps) {
            self.watch_libc(
                &Path::new(&format!("/proc/{pid}/root")).join(path.trim_start_matches('/')),
            );
        }
    }

    fn watch_libc(&mut self, libc: &Path) {
        let Ok(meta) = std::fs::metadata(libc) else {
            return;
        };
        if !self.libcs.insert((meta.dev(), meta.ino())) {
            return;
        }
        for name in RESOLVER_PROGRAMS {
            let attached = self
                .ebpf
                .program_mut(name)
                .and_then(|p| <&mut UProbe>::try_from(p).ok())
                .map(|p| p.attach(Some("getaddrinfo"), 0, libc, None));
            match attached {
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    return warn!(libc = %libc.display(), error = %e, "names from this libc are not read")
                }
                None => return,
            }
        }
        info!(libc = %libc.display(), "reading the names looked up through this libc");
    }

    /// Totals since load, in `STAT_NAMES` order.
    pub fn stats(&self) -> Result<[u64; STAT_NAMES.len()]> {
        let mut out = [0u64; STAT_NAMES.len()];
        let (probe, skipped) = out.split_at_mut(STAT_COUNT as usize);
        for (i, slot) in probe.iter_mut().enumerate() {
            *slot = self.stats.get(&(i as u32), 0)?.iter().sum();
        }
        for (name, prog) in self.ebpf.programs() {
            if let Ok(fd) = prog.fd() {
                skipped[usize::from(name == LSM_PROG)] += recursion_misses(fd.as_fd())?;
            }
        }
        Ok(out)
    }
}

/// Runs the kernel skipped because the program was already running on that
/// CPU, in a task it preempted: syscall programs can be since 7.2, LSM
/// programs always could. Linux 5.12+ counts them; aya does not expose it.
fn recursion_misses(prog: BorrowedFd<'_>) -> Result<u64> {
    #[repr(C)]
    struct InfoAttr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
    // SAFETY: a plain C struct; all zeroes is valid.
    let mut info: aya_obj::generated::bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut attr = InfoAttr {
        bpf_fd: prog.as_raw_fd() as u32,
        info_len: size_of_val(&info) as u32,
        info: &mut info as *mut _ as u64,
    };
    // SAFETY: attr points at info, which outlives the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr as *mut InfoAttr,
            size_of::<InfoAttr>(),
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("reading a program's info");
    }
    Ok(info.recursion_misses)
}

/// Entry and return of getaddrinfo.
const RESOLVER_PROGRAMS: [&str; 2] = ["k11_getaddrinfo", "k11_getaddrinfo_ret"];

fn load_resolver(ebpf: &mut Ebpf) -> Result<()> {
    for name in RESOLVER_PROGRAMS {
        let prog: &mut UProbe = ebpf
            .program_mut(name)
            .with_context(|| format!("{name} not found in eBPF object"))?
            .try_into()?;
        prog.load()
            .with_context(|| format!("verifier rejected {name}"))?;
    }
    Ok(())
}

/// Where distributions put glibc (k11 itself is static and maps none).
fn host_libc() -> Option<PathBuf> {
    [
        "/usr/lib64/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
        "/usr/lib/libc.so.6",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// The libc a process maps, as its own root sees it: glibc, or musl, whose
/// libc is its dynamic loader.
fn mapped_libc(maps: &str) -> Option<&str> {
    maps.lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .find(|path| {
            let name = path.rsplit('/').next().unwrap_or("");
            name == "libc.so.6" || (name.starts_with("ld-musl-") && name.ends_with(".so.1"))
        })
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

/// Whether `release` (e.g. `7.0.0-1017-azure`) is older than major.minor.
/// One that does not parse counts as new.
fn release_before(release: &str, major: u32, minor: u32) -> bool {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let mut next = || parts.next().and_then(|p| p.parse::<u32>().ok());
    matches!((next(), next()), (Some(a), Some(b)) if (a, b) < (major, minor))
}

#[cfg(test)]
mod tests {
    use super::release_before;

    #[test]
    fn compares_releases_by_major_and_minor() {
        assert!(release_before("7.0.0-1017-azure", 7, 2));
        assert!(release_before("6.19.3-200.fc43.x86_64", 7, 2));
        assert!(!release_before("7.2.8-200.fc44.x86_64", 7, 2));
        assert!(!release_before("7.10.0", 7, 2));
        assert!(release_before("5.10.23-200.fc33.x86_64", 5, 15));
        assert!(!release_before("unknown", 7, 2));
    }
}
