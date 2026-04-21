//! Async export task — subscribes to the event broadcast channel, enriches
//! each event (DNS, GeoIP, ASN, uid→username), and writes one OCSF JSON
//! record per line to a file or stdout.

use std::io::Write;
use std::sync::Arc;

use maxminddb::Reader as GeoIpReader;
use tokio::sync::broadcast;
use tracing::warn;

use crate::config::ExportConfig;
use crate::dns_cache::DnsCache;
use crate::enrich::{self, PasswdCache};
use crate::ocsf;
use crate::store::Event;

#[allow(clippy::too_many_arguments)]
pub async fn run_export(
    mut rx: broadcast::Receiver<Event>,
    config: ExportConfig,
    hostname: String,
    dns_cache: Arc<DnsCache>,
    geoip: Option<Arc<GeoIpReader<Vec<u8>>>>,
    geoip_asn: Option<Arc<GeoIpReader<Vec<u8>>>>,
    passwd: Arc<PasswdCache>,
) {
    let mut writer: Box<dyn Write + Send> = if config.output == "-" {
        Box::new(std::io::stdout())
    } else {
        let file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.output)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(path = %config.output, error = %e, "failed to open export file — export disabled");
                return;
            }
        };
        Box::new(std::io::BufWriter::new(file))
    };

    loop {
        match rx.recv().await {
            Ok(event) => {
                let enriched = enrich::enrich_event(
                    &event,
                    &dns_cache,
                    &geoip,
                    &geoip_asn,
                    &passwd,
                )
                .await;
                let record = ocsf::to_ocsf(&event, &enriched, &hostname);
                // Write compact JSON + newline; ignore write errors (best-effort).
                let line = serde_json::to_string(&record).unwrap();
                let _ = writeln!(writer, "{line}");
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(missed = n, "OCSF export lagged — dropped events");
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}
