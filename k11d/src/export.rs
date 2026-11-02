//! OCSF JSON Lines export: the durable record.
//!
//! Fed by a bounded, lossless channel from the decode loop. When the writer
//! falls behind, the decode loop waits and the kernel ring absorbs the burst,
//! so any loss is counted in one place (the probe's ring-full counter)
//! instead of silently dropped here. Lines are flushed on a short timer and
//! on shutdown; a crash loses at most one flush interval.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::ExportConfig;
use crate::enrich::Enricher;
use crate::ocsf;
use crate::store::Event;

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

pub fn open_writer(config: &ExportConfig) -> std::io::Result<Box<dyn Write + Send>> {
    Ok(if config.output == "-" {
        Box::new(std::io::stdout())
    } else {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.output)?;
        Box::new(std::io::BufWriter::new(file))
    })
}

pub async fn run(
    mut rx: mpsc::Receiver<Arc<Event>>,
    mut writer: Box<dyn Write + Send>,
    hostname: String,
    enricher: Arc<Enricher>,
) {
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut dirty = false;
    // Log write failures on state transitions only, so a full disk warns
    // once instead of once per event.
    let mut write_ok = true;

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break };
                let enriched = enricher.event(&event);
                let record = ocsf::record(&event, &enriched, &hostname);
                let result = serde_json::to_writer(&mut writer, &record)
                    .map_err(std::io::Error::from)
                    .and_then(|()| writer.write_all(b"\n"));
                dirty = true;
                match result {
                    Ok(()) if !write_ok => {
                        info!("OCSF export writes recovered");
                        write_ok = true;
                    }
                    Err(e) if write_ok => {
                        warn!(error = %e, "OCSF export write failed: events are being lost");
                        write_ok = false;
                    }
                    _ => {}
                }
            }
            _ = flush.tick(), if dirty => {
                dirty = false;
                if let Err(e) = writer.flush() {
                    if write_ok {
                        warn!(error = %e, "OCSF export flush failed");
                        write_ok = false;
                    }
                }
            }
        }
    }
    if let Err(e) = writer.flush() {
        warn!(error = %e, "OCSF export final flush failed");
    }
}
