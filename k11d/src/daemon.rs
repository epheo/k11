//! `k11 daemon`: load the probe, record, serve the dashboard, the API and
//! the session socket until SIGINT or SIGTERM.

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use k11_proto::k11_server::K11Server;

use crate::config::Config;
use crate::control::{self, Token};
use crate::decode::Decoder;
use crate::enrich::Enricher;
use crate::ocsf::Host;
use crate::probe::{Probe, STAT_NAMES};
use crate::session::{self, Sessions};
use crate::state::{self, Kept};
use crate::store::{Event, EventStore};
use crate::{export, grpc, web};

#[derive(clap::Args)]
pub struct Args {
    /// Config file. Default: $K11_CONFIG, /etc/k11/k11.toml, config/k11.toml.
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// Address for the dashboard and gRPC API (overrides grpc.listen).
    #[arg(long)]
    pub listen: Option<String>,
    /// Open the dashboard in a browser.
    #[arg(long)]
    pub open: bool,
    /// Also record trees started by this program name, including those
    /// already running (adds to watch.binaries; repeatable). The dashboard
    /// edits the list while recording.
    #[arg(long, value_name = "NAME")]
    pub watch: Vec<String>,
}

const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);
const BROADCAST_CAPACITY: usize = 1024;
const EXPORT_QUEUE: usize = 4096;

pub async fn run(args: Args) -> Result<()> {
    let mut config = Config::load(args.config.as_deref())?;
    let kept = Kept::load(state::PATH)?;
    kept.apply(&mut config);
    if let Some(listen) = args.listen {
        config.grpc.listen = listen;
    }
    config.watch.binaries.extend(args.watch);

    let mut probe = Probe::load(&config)?;
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
            guard.seed_process(sp);
        }
    }
    let (event_tx, _) = broadcast::channel::<Arc<Event>>(BROADCAST_CAPACITY);
    let enricher = Enricher::load(&config.geoip);

    // --- Dashboard + gRPC-web on one origin, no CORS ---

    let listen_addr: std::net::SocketAddr = config
        .grpc
        .listen
        .parse()
        .context("invalid grpc.listen address")?;
    let ui_url = if listen_addr.ip().is_unspecified() {
        format!("http://127.0.0.1:{}", listen_addr.port())
    } else {
        format!("http://{listen_addr}")
    };
    let token = Token::generate()?;
    token.publish(&control::url_path(&config.session.socket), &ui_url)?;
    let control_url = token.url(&ui_url);

    let svc = grpc::K11Service::new(
        Arc::clone(&store),
        event_tx.clone(),
        Arc::clone(&enricher),
        grpc::Control {
            token,
            policy: Arc::clone(&probe.policy),
            lineage: Arc::clone(&probe.lineage),
            watch_all: config.watch.all,
            kept: Mutex::new(kept),
        },
    );
    let grpc_web = {
        use tower::Layer as _;
        tonic_web::GrpcWebLayer::new().layer(K11Server::new(svc))
    };
    let mut app = tonic::service::Routes::new(grpc_web)
        .into_axum_router()
        .fallback(web::static_handler);
    // Bound elsewhere, the operator fronts it with a proxy that sets Host.
    if listen_addr.ip().is_loopback() {
        app = app.layer(axum::middleware::from_fn(web::loopback_host_only));
    }
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}: is another k11 daemon running?"))?;
    info!(url = %ui_url, "dashboard (read-only; `k11 dashboard` opens it with control)");

    // --- Session socket for `k11 run` ---

    let sessions = Arc::new(Sessions {
        lineage: Arc::clone(&probe.lineage),
        store: Arc::clone(&store),
        enricher: Arc::clone(&enricher),
        ui_url: ui_url.clone(),
    });
    let socket = session::bind(&config.session.socket)?;
    info!(socket = %config.session.socket.display(), "accepting k11 run sessions");
    tokio::spawn(session::serve(socket, sessions));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "http server failed");
        }
    });

    // --- OCSF export: lossless, its own thread, synced at shutdown ---

    let mut export = None;
    if config.export.enabled {
        let (tx, rx) = mpsc::channel::<export::Item>(EXPORT_QUEUE);
        let started = export::Output::open(&config.export)
            .and_then(|out| export::spawn(rx, out, Host::detect(), Arc::clone(&enricher)));
        match started {
            Ok(thread) => {
                info!(output = %config.export.output, "exporting OCSF records");
                export = Some((tx, thread));
            }
            Err(e) => {
                warn!(path = %config.export.output, error = %e, "failed to start OCSF export, export disabled")
            }
        }
    }

    // --- Record ---

    probe.attach()?;
    info!("recording");
    if args.open {
        web::open_browser(&control_url);
    }

    let fd = AsyncFd::with_interest(probe.ring.as_raw_fd(), Interest::READABLE)?;
    let mut decoder = Decoder::new();
    let mut batch: Vec<Arc<Event>> = Vec::with_capacity(256);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut sigterm = signal(SignalKind::terminate())?;
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
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down");
                break;
            }
            result = fd.readable() => {
                // Clear before draining. The ring signals only when it goes
                // from empty to not empty for the reader: a record landing
                // between the drain and a later clear would lose its wakeup,
                // and every record after it would wait unseen.
                result?.clear_ready();
                decoder.drain(&mut probe.ring, &mut batch);
                deliver(&mut batch, &store, &event_tx, &mut export).await;
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
                report_losses(&probe, &mut last_stats, &export).await;
            }
        }
    }

    // What the ring still holds belongs in the record too.
    decoder.drain(&mut probe.ring, &mut batch);
    deliver(&mut batch, &store, &event_tx, &mut export).await;
    report_losses(&probe, &mut last_stats, &export).await;
    if let Some((tx, thread)) = export {
        drop(tx);
        let _ = tokio::task::spawn_blocking(move || thread.join()).await;
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

type Export = Option<(mpsc::Sender<export::Item>, std::thread::JoinHandle<()>)>;

/// Decoded events to the store, the live stream and the export.
async fn deliver(
    batch: &mut Vec<Arc<Event>>,
    store: &Mutex<EventStore>,
    event_tx: &broadcast::Sender<Arc<Event>>,
    export: &mut Export,
) {
    if batch.is_empty() {
        return;
    }
    {
        let mut store = store.lock().unwrap();
        for event in batch.iter() {
            store.push(Arc::clone(event));
        }
    }
    for event in batch.drain(..) {
        let _ = event_tx.send(Arc::clone(&event));
        if let Some((tx, _)) = export.as_ref() {
            // Backpressure: a slow writer stalls decoding and the kernel
            // ring absorbs the burst.
            if tx.send(export::Item::Event(event)).await.is_err() {
                warn!("OCSF export task stopped; export disabled");
                *export = None;
            }
        }
    }
}

/// Log and export what the probe lost since the last report.
async fn report_losses(probe: &Probe, last: &mut [u64; STAT_NAMES.len()], export: &Export) {
    let stats = match probe.stats() {
        Ok(stats) => stats,
        Err(e) => return warn!(error = %e, "failed to read probe stats"),
    };
    let lost: Vec<(&'static str, u64)> = STAT_NAMES
        .iter()
        .zip(stats.iter().zip(last.iter()))
        .filter(|(_, (now, before))| now > before)
        .map(|(name, (now, before))| (*name, now - before))
        .collect();
    *last = stats;
    if lost.is_empty() {
        return;
    }
    warn!(?lost, "probe lost or refused events");
    if let Some((tx, _)) = export {
        let _ = tx.send(export::Item::Loss(lost)).await;
    }
}
