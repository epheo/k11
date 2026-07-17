mod btf_offsets;
mod config;
mod decode;
mod dns_cache;
mod enrich;
mod export;
mod grpc;
mod lineage;
mod ocsf;
mod policy;
mod store;
mod tracefs;

use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use maxminddb::Reader as GeoIpReader;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf, EbpfLoader};
use k11_common::{
    COMM_LEN, OFF_BIND_ADDR, OFF_BIND_RET,
    OFF_CHMOD_FILENAME, OFF_CHMOD_MODE, OFF_CHMOD_RET,
    OFF_CHOWN_FILENAME, OFF_CHOWN_GID, OFF_CHOWN_RET, OFF_CHOWN_UID,
    OFF_CONNECT_ADDR, OFF_CONNECT_RET, OFF_EXEC_FILENAME, OFF_FORK_CHILD_PID,
    OFF_LISTEN_BACKLOG, OFF_LISTEN_RET,
    OFF_OPENAT_FILENAME, OFF_OPENAT_FLAGS, OFF_OPENAT_RET,
    OFF_PTRACE_PID, OFF_PTRACE_REQUEST, OFF_PTRACE_RET,
    OFF_RENAME_NEWNAME, OFF_RENAME_OLDNAME, OFF_RENAME_RET,
    OFF_SYMLINK_NEWNAME, OFF_SYMLINK_OLDNAME, OFF_SYMLINK_RET,
    OFF_UNLINK_FLAGS, OFF_UNLINK_PATHNAME, OFF_UNLINK_RET,
};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use k11_proto::k11_server::K11Server;
use crate::store::EventStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = config::Config::load()?;

    // --- Discover struct offsets before loading BPF ---

    let tp_offsets = tracefs::discover_offsets()?;
    info!("discovered tracepoint field offsets from tracefs");

    let btf_off = btf_offsets::discover_offsets()?;
    info!("discovered LSM struct offsets from kernel BTF");

    // Load BPF object with FILE_F_PATH_OFF as a .rodata global.
    // The verifier needs this as a constant to resolve file_ptr + offset → struct path *.
    info!("loading eBPF probes");

    let mut ebpf = EbpfLoader::new()
        .set_global("FILE_F_PATH_OFF", &btf_off.file_f_path, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/k11-ebpf"
        )))?;

    // --- Seed BPF maps from config ---

    let watch_all = config.watch.binaries.is_empty();

    let seeded_processes = if watch_all {
        info!("no watch.binaries configured — watching ALL processes");
        let mut config_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
        lineage::set_watch_all(&mut config_map, true)?;
        Vec::new()
    } else {
        info!(binaries = ?config.watch.binaries, "filtering by process lineage");
        let mut watch_comms: HashMap<&mut aya::maps::MapData, [u8; COMM_LEN], u8> =
            HashMap::try_from(
                ebpf.map_mut("WATCH_COMMS")
                    .context("WATCH_COMMS map not found")?,
            )?;
        lineage::load_watch_comms(&mut watch_comms, &config.watch.binaries)?;

        let mut watched_pids: HashMap<&mut aya::maps::MapData, u32, u32> = HashMap::try_from(
            ebpf.map_mut("WATCHED_PIDS")
                .context("WATCHED_PIDS map not found")?,
        )?;
        lineage::seed_from_proc(&mut watched_pids, &config.watch.binaries)?
    };

    // Populate tracepoint + BTF offsets into BPF OFFSETS map
    {
        let mut offset_map: Array<&mut aya::maps::MapData, u32> =
            Array::try_from(ebpf.map_mut("OFFSETS").context("OFFSETS map not found")?)?;
        offset_map.set(OFF_FORK_CHILD_PID, tp_offsets.fork_child_pid, 0)?;
        offset_map.set(OFF_EXEC_FILENAME, tp_offsets.exec_filename, 0)?;
        offset_map.set(OFF_OPENAT_FILENAME, tp_offsets.openat_filename, 0)?;
        offset_map.set(OFF_OPENAT_FLAGS, tp_offsets.openat_flags, 0)?;
        offset_map.set(OFF_OPENAT_RET, tp_offsets.openat_ret, 0)?;
        offset_map.set(OFF_CONNECT_ADDR, tp_offsets.connect_addr, 0)?;
        offset_map.set(OFF_CONNECT_RET, tp_offsets.connect_ret, 0)?;
        // Tier 1+2 offsets
        offset_map.set(OFF_BIND_ADDR, tp_offsets.bind_addr, 0)?;
        offset_map.set(OFF_BIND_RET, tp_offsets.bind_ret, 0)?;
        offset_map.set(OFF_LISTEN_BACKLOG, tp_offsets.listen_backlog, 0)?;
        offset_map.set(OFF_LISTEN_RET, tp_offsets.listen_ret, 0)?;
        offset_map.set(OFF_UNLINK_PATHNAME, tp_offsets.unlink_pathname, 0)?;
        offset_map.set(OFF_UNLINK_FLAGS, tp_offsets.unlink_flags, 0)?;
        offset_map.set(OFF_UNLINK_RET, tp_offsets.unlink_ret, 0)?;
        offset_map.set(OFF_RENAME_OLDNAME, tp_offsets.rename_oldname, 0)?;
        offset_map.set(OFF_RENAME_NEWNAME, tp_offsets.rename_newname, 0)?;
        offset_map.set(OFF_RENAME_RET, tp_offsets.rename_ret, 0)?;
        offset_map.set(OFF_CHMOD_FILENAME, tp_offsets.chmod_filename, 0)?;
        offset_map.set(OFF_CHMOD_MODE, tp_offsets.chmod_mode, 0)?;
        offset_map.set(OFF_CHMOD_RET, tp_offsets.chmod_ret, 0)?;
        offset_map.set(OFF_CHOWN_FILENAME, tp_offsets.chown_filename, 0)?;
        offset_map.set(OFF_CHOWN_UID, tp_offsets.chown_uid, 0)?;
        offset_map.set(OFF_CHOWN_GID, tp_offsets.chown_gid, 0)?;
        offset_map.set(OFF_CHOWN_RET, tp_offsets.chown_ret, 0)?;
        offset_map.set(OFF_SYMLINK_OLDNAME, tp_offsets.symlink_oldname, 0)?;
        offset_map.set(OFF_SYMLINK_NEWNAME, tp_offsets.symlink_newname, 0)?;
        offset_map.set(OFF_SYMLINK_RET, tp_offsets.symlink_ret, 0)?;
        offset_map.set(OFF_PTRACE_REQUEST, tp_offsets.ptrace_request, 0)?;
        offset_map.set(OFF_PTRACE_PID, tp_offsets.ptrace_pid, 0)?;
        offset_map.set(OFF_PTRACE_RET, tp_offsets.ptrace_ret, 0)?;
    }

    // --- Attach tracepoints ---

    attach_tracepoint(&mut ebpf, "k11_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut ebpf, "k11_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "k11_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut ebpf, "k11_openat", "syscalls", "sys_enter_openat")?;
    attach_tracepoint(&mut ebpf, "k11_openat_exit", "syscalls", "sys_exit_openat")?;
    attach_tracepoint(&mut ebpf, "k11_connect", "syscalls", "sys_enter_connect")?;
    attach_tracepoint(&mut ebpf, "k11_connect_exit", "syscalls", "sys_exit_connect")?;
    // Tier 1+2 tracepoints
    attach_tracepoint(&mut ebpf, "k11_bind", "syscalls", "sys_enter_bind")?;
    attach_tracepoint(&mut ebpf, "k11_bind_exit", "syscalls", "sys_exit_bind")?;
    attach_tracepoint(&mut ebpf, "k11_listen", "syscalls", "sys_enter_listen")?;
    attach_tracepoint(&mut ebpf, "k11_listen_exit", "syscalls", "sys_exit_listen")?;
    attach_tracepoint(&mut ebpf, "k11_unlink", "syscalls", "sys_enter_unlinkat")?;
    attach_tracepoint(&mut ebpf, "k11_unlink_exit", "syscalls", "sys_exit_unlinkat")?;
    attach_tracepoint(&mut ebpf, "k11_rename", "syscalls", "sys_enter_renameat2")?;
    attach_tracepoint(&mut ebpf, "k11_rename_exit", "syscalls", "sys_exit_renameat2")?;
    attach_tracepoint(&mut ebpf, "k11_chmod", "syscalls", "sys_enter_fchmodat")?;
    attach_tracepoint(&mut ebpf, "k11_chmod_exit", "syscalls", "sys_exit_fchmodat")?;
    attach_tracepoint(&mut ebpf, "k11_chown", "syscalls", "sys_enter_fchownat")?;
    attach_tracepoint(&mut ebpf, "k11_chown_exit", "syscalls", "sys_exit_fchownat")?;
    attach_tracepoint(&mut ebpf, "k11_symlink", "syscalls", "sys_enter_symlinkat")?;
    attach_tracepoint(&mut ebpf, "k11_symlink_exit", "syscalls", "sys_exit_symlinkat")?;
    attach_tracepoint(&mut ebpf, "k11_ptrace", "syscalls", "sys_enter_ptrace")?;
    attach_tracepoint(&mut ebpf, "k11_ptrace_exit", "syscalls", "sys_exit_ptrace")?;

    info!("attached to 23 tracepoints — watching kernel events");

    // --- LSM enforcement ---
    // LSM programs must be loaded BEFORE take_map() — aya needs the maps
    // present in the Ebpf object to resolve BPF map relocations at load time.

    let btf = Btf::from_sys_fs()?;

    match attach_lsm(&mut ebpf, &btf, "k11_lsm_file_open", "file_open") {
        Ok(_) => info!(
            enforce = config.policy.enforce,
            "attached LSM file_open hook — deny rules audit, and enforce when enabled"
        ),
        Err(e) => warn!(error = ?e, "failed to load file_open LSM hook"),
    }

    // Now take owned map handles for runtime policy updates (after programs are loaded).
    let policy_maps = policy::PolicyMaps::new(&mut ebpf, &config.policy, watch_all)?;
    let policy_maps = Arc::new(Mutex::new(policy_maps));

    let ring_drops: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(ebpf.take_map("DROPS").context("DROPS map not found")?)?;

    // Compute offset to convert boot-relative timestamps to wall-clock epoch nanoseconds.
    // boot_offset_ns = wall_clock_now - uptime_now (both in nanoseconds since their respective epochs).
    let boot_offset_ns = {
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos() as u64;
        let uptime_str = std::fs::read_to_string("/proc/uptime")
            .expect("failed to read /proc/uptime");
        let uptime_secs: f64 = uptime_str
            .split_whitespace()
            .next()
            .expect("/proc/uptime empty")
            .parse()
            .expect("failed to parse uptime");
        let uptime_ns = (uptime_secs * 1_000_000_000.0) as u64;
        wall_ns.saturating_sub(uptime_ns)
    };

    // --- Set up event store + dashboard ---

    let store = Arc::new(Mutex::new(EventStore::new(config.store.max_events_per_agent)));
    if !seeded_processes.is_empty() {
        info!(count = seeded_processes.len(), "pre-populating store with seeded processes");
        let mut guard = store.lock().unwrap();
        for sp in &seeded_processes {
            guard.seed_process(sp.root_pid, sp.pid, sp.parent_pid, sp.comm.clone());
        }
    }
    let (event_tx, _) = tokio::sync::broadcast::channel::<store::Event>(1024);

    let geoip = match GeoIpReader::open_readfile(&config.geoip.database) {
        Ok(reader) => {
            info!(path = %config.geoip.database, "loaded GeoIP database");
            Some(Arc::new(reader))
        }
        Err(e) => {
            warn!(path = %config.geoip.database, error = %e, "GeoIP database not available — country lookup disabled");
            None
        }
    };

    let geoip_asn = match GeoIpReader::open_readfile(&config.geoip.asn_database) {
        Ok(reader) => {
            info!(path = %config.geoip.asn_database, "loaded GeoIP ASN database");
            Some(Arc::new(reader))
        }
        Err(e) => {
            warn!(path = %config.geoip.asn_database, error = %e, "GeoIP ASN database not available — ASN lookup disabled");
            None
        }
    };

    let dns_cache = Arc::new(dns_cache::DnsCache::new());
    let passwd_cache = Arc::new(enrich::PasswdCache::load());
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".into())
        .trim()
        .to_string();

    let svc = grpc::K11Service::new(
        Arc::clone(&store),
        event_tx.clone(),
        Arc::clone(&dns_cache),
        geoip.clone(),
        geoip_asn.clone(),
        Arc::clone(&passwd_cache),
        Arc::clone(&policy_maps),
        hostname.clone(),
    );

    let grpc_addr = config.grpc.listen.parse()
        .context("invalid grpc.listen address")?;
    info!(addr = %config.grpc.listen, "gRPC server listening");
    tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .accept_http1(true)
            .add_service(tonic_web::enable(K11Server::new(svc)))
            .serve(grpc_addr)
            .await
        {
            tracing::error!(error = %e, "gRPC server failed");
        }
    });

    // --- OCSF export ---

    if config.export.enabled {
        info!(output = %config.export.output, "starting OCSF event export");
        tokio::spawn(export::run_export(
            event_tx.subscribe(),
            config.export,
            hostname,
            Arc::clone(&dns_cache),
            geoip,
            geoip_asn,
            Arc::clone(&passwd_cache),
        ));
    }

    // --- Event loop ---

    let mut ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").context("EVENTS map not found")?)?;
    let fd = AsyncFd::with_interest(ring_buf.as_raw_fd(), Interest::READABLE)?;

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut maintenance = tokio::time::interval(Duration::from_secs(60));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let evict_ttl_ms = config.store.evict_exited_after_secs * 1000;
    let mut last_ring_drops: u64 = 0;

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("ctrl-c received, shutting down");
                break;
            }
            result = fd.readable() => {
                let mut guard = result?;
                decode::drain_events(&mut ring_buf, &store, &event_tx, boot_offset_ns);
                guard.clear_ready();
            }
            _ = maintenance.tick() => {
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let evicted = store.lock().unwrap().evict_exited(now_ms, evict_ttl_ms);
                if evicted > 0 {
                    info!(evicted, "evicted exited agent trees");
                }
                match ring_drop_total(&ring_drops) {
                    Ok(total) if total > last_ring_drops => {
                        warn!(
                            dropped = total - last_ring_drops,
                            total,
                            "BPF ring buffer dropped events — kernel emitted faster than the daemon drained"
                        );
                        last_ring_drops = total;
                    }
                    Ok(_) => {}
                    Err(e) => debug!(error = %e, "failed to read DROPS map"),
                }
            }
        }
    }

    Ok(())
}

/// Sum the per-CPU ring buffer drop counters.
fn ring_drop_total(map: &PerCpuArray<MapData, u64>) -> Result<u64> {
    let values = map.get(&0, 0)?;
    Ok(values.iter().sum())
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    tracepoint: &str,
) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} not found in eBPF object"))?
        .try_into()?;
    prog.load()?;
    prog.attach(category, tracepoint)
        .with_context(|| format!("failed to attach {prog_name} to {category}/{tracepoint}"))?;
    Ok(())
}

fn attach_lsm(ebpf: &mut Ebpf, btf: &Btf, prog_name: &str, hook_name: &str) -> Result<()> {
    let prog: &mut Lsm = ebpf
        .program_mut(prog_name)
        .with_context(|| format!("{prog_name} not found in eBPF object"))?
        .try_into()?;
    prog.load(hook_name, btf)
        .with_context(|| format!("failed to load LSM program {prog_name}"))?;
    prog.attach()
        .with_context(|| format!("failed to attach {prog_name} to LSM hook {hook_name}"))?;
    Ok(())
}

