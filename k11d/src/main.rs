mod btf_offsets;
mod classify;
mod config;
mod decode;
mod dns_cache;
mod enrich;
mod export;
mod grpc;
mod lineage;
mod ocsf;
mod policy;
mod probe;
mod store;
mod tracefs;
mod web;

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use k11_proto::k11_server::K11Server;

use crate::config::Config;
use crate::decode::Decoder;
use crate::enrich::Enricher;
use crate::probe::{Probe, STAT_NAMES};
use crate::store::{Event, EventStore};

#[derive(Parser)]
#[command(
    name = "k11d",
    version,
    about = "Black-box recorder for AI coding agents"
)]
struct Cli {
    /// Config file. Default: $K11_CONFIG, /etc/k11/k11.toml, config/k11.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Address for the dashboard and gRPC API (overrides grpc.listen).
    #[arg(long)]
    listen: Option<String>,
    /// Open the dashboard in a browser.
    #[arg(long)]
    open: bool,
    /// Load and verify the probe, print what this kernel supports, and exit.
    #[arg(long)]
    check: bool,
}

const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
const BROADCAST_CAPACITY: usize = 1024;
const EXPORT_QUEUE: usize = 4096;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let mut config = Config::load(cli.config.as_deref())?;
    if let Some(listen) = cli.listen {
        config.grpc.listen = listen;
    }

    let mut probe = Probe::load(&config)?;
    if cli.check {
        print!("{}", probe.capabilities.report());
        return Ok(());
    }
    for line in probe.capabilities.report().lines() {
        info!("{line}");
    }

    // --- Shared state ---

    let store = Arc::new(Mutex::new(EventStore::new(
        config.store.max_events_per_agent,
        config.store.max_total_events,
    )));
    if !probe.seeded.is_empty() {
        info!(
            count = probe.seeded.len(),
            "pre-populating store with seeded processes"
        );
        let mut guard = store.lock().unwrap();
        for sp in &probe.seeded {
            guard.seed_process(sp.root_pid, sp.pid, sp.parent_pid, &sp.comm);
        }
    }
    let (event_tx, _) = broadcast::channel::<Arc<Event>>(BROADCAST_CAPACITY);
    let enricher = Enricher::load(&config.geoip);
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());

    // --- Dashboard + gRPC-web on one origin, no CORS ---

    let svc = grpc::K11Service::new(
        Arc::clone(&store),
        event_tx.clone(),
        Arc::clone(&enricher),
        Arc::clone(&probe.policy),
        hostname.clone(),
    );
    let grpc_web = {
        use tower::Layer as _;
        tonic_web::GrpcWebLayer::new().layer(K11Server::new(svc))
    };
    let app = tonic::service::Routes::new(grpc_web)
        .into_axum_router()
        .fallback(web::static_handler);
    let listen_addr: std::net::SocketAddr = config
        .grpc
        .listen
        .parse()
        .context("invalid grpc.listen address")?;
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}: is another k11d running?"))?;
    let ui_url = if listen_addr.ip().is_unspecified() {
        format!("http://127.0.0.1:{}", listen_addr.port())
    } else {
        format!("http://{listen_addr}")
    };
    info!(url = %ui_url, "serving dashboard + gRPC-web API");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "http server failed");
        }
    });

    // --- OCSF export: lossless, flushed on a timer and at shutdown ---

    let mut export = None;
    if config.export.enabled {
        match export::open_writer(&config.export) {
            Ok(writer) => {
                info!(output = %config.export.output, "starting OCSF event export");
                let (tx, rx) = mpsc::channel::<Arc<Event>>(EXPORT_QUEUE);
                let task = tokio::spawn(export::run(rx, writer, hostname, Arc::clone(&enricher)));
                export = Some((tx, task));
            }
            Err(e) => {
                warn!(path = %config.export.output, error = %e, "failed to open export output, export disabled")
            }
        }
    }

    // --- Record ---

    probe.attach()?;
    info!("recording");
    if cli.open {
        web::open_browser(&ui_url);
    }

    let fd = AsyncFd::with_interest(probe.ring.as_raw_fd(), Interest::READABLE)?;
    let mut decoder = Decoder::new();
    let mut batch: Vec<Arc<Event>> = Vec::with_capacity(256);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let evict_ttl_ms = config.store.evict_exited_after_secs * 1000;
    let mut last_stats = [0u64; STAT_NAMES.len()];

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("ctrl-c received, shutting down");
                break;
            }
            result = fd.readable() => {
                let mut guard = result?;
                decoder.drain(&mut probe.ring, &mut batch);
                guard.clear_ready();
                if batch.is_empty() {
                    continue;
                }
                {
                    let mut store = store.lock().unwrap();
                    for event in &batch {
                        store.push(Arc::clone(event));
                    }
                }
                for event in batch.drain(..) {
                    let _ = event_tx.send(Arc::clone(&event));
                    if let Some((tx, _)) = &export {
                        // Backpressure: a slow writer stalls decoding and the
                        // kernel ring absorbs the burst.
                        if tx.send(event).await.is_err() {
                            warn!("OCSF export task stopped; export disabled");
                            export = None;
                        }
                    }
                }
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
                match probe.stats() {
                    Ok(stats) => {
                        for (i, name) in STAT_NAMES.iter().enumerate() {
                            if stats[i] > last_stats[i] {
                                warn!(counter = name, delta = stats[i] - last_stats[i], total = stats[i], "probe lost or refused events");
                            }
                        }
                        last_stats = stats;
                    }
                    Err(e) => warn!(error = %e, "failed to read probe stats"),
                }
            }
        }
    }

    if let Some((tx, task)) = export {
        drop(tx);
        let _ = task.await;
    }

    // Final counters, so a short run (a smoke test) shows what the probe lost
    // or refused without waiting for a maintenance tick.
    if let Ok(stats) = probe.stats() {
        let totals: Vec<String> = STAT_NAMES
            .iter()
            .zip(stats)
            .map(|(name, v)| format!("{name}={v}"))
            .collect();
        info!(stats = %totals.join(" "), "probe counters at shutdown");
    }
    Ok(())
}
