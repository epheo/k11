//! OCSF JSON Lines export: the durable record.
//!
//! Fed by a bounded, lossless channel from the decode loop. When the writer
//! falls behind, the decode loop waits and the kernel ring absorbs the burst,
//! so loss happens in one place (the probe's ring-full counter). The writer
//! runs on its own thread so a slow disk or pipe never blocks the runtime;
//! it flushes whenever the queue runs dry and syncs the file at shutdown.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Stdout, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::mpsc::{self, error::TryRecvError};
use tracing::{info, warn};

use crate::config::ExportConfig;
use crate::enrich::Enricher;
use crate::ocsf::{self, Host};
use crate::store::Event;

pub enum Output {
    Stdout(Stdout),
    File(BufWriter<File>),
}

impl Output {
    /// The file holds every path the agent touched: owner-only.
    pub fn open(config: &ExportConfig) -> io::Result<Self> {
        if config.output == "-" {
            return Ok(Self::Stdout(io::stdout()));
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&config.output)?;
        Ok(Self::File(BufWriter::new(file)))
    }

    fn writer(&mut self) -> &mut dyn Write {
        match self {
            Self::Stdout(out) => out,
            Self::File(out) => out,
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        self.writer().flush()?;
        match self {
            Self::File(out) => out.get_ref().sync_data(),
            Self::Stdout(_) => Ok(()),
        }
    }
}

pub fn spawn(
    rx: mpsc::Receiver<Arc<Event>>,
    out: Output,
    host: Host,
    enricher: Arc<Enricher>,
) -> io::Result<JoinHandle<()>> {
    // Enrichment starts DNS lookups on the runtime's blocking pool.
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("ocsf-export".into())
        .spawn(move || {
            let _runtime = runtime.enter();
            run(rx, out, &host, &enricher);
        })
}

fn run(mut rx: mpsc::Receiver<Arc<Event>>, mut out: Output, host: &Host, enricher: &Arc<Enricher>) {
    let mut line = Vec::with_capacity(2048);
    // Failures are logged on state changes, so a full disk warns once.
    let mut lost: u64 = 0;
    loop {
        let event = match rx.try_recv() {
            Ok(event) => event,
            Err(TryRecvError::Empty) => {
                if let Err(e) = out.writer().flush() {
                    warn!(error = %e, "OCSF export flush failed");
                }
                match rx.blocking_recv() {
                    Some(event) => event,
                    None => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        line.clear();
        let enriched = enricher.event(&event);
        serde_json::to_writer(&mut line, &ocsf::record(&event, &enriched, host))
            .expect("OCSF records serialize");
        line.push(b'\n');
        match out.writer().write_all(&line) {
            Ok(()) if lost > 0 => {
                info!(lost, "OCSF export writes recovered");
                lost = 0;
            }
            Ok(()) => {}
            Err(e) => {
                if lost == 0 {
                    warn!(error = %e, "OCSF export write failed: records are being lost");
                }
                lost += 1;
            }
        }
    }
    if lost > 0 {
        warn!(lost, "OCSF export ended with records lost");
    }
    if let Err(e) = out.finish() {
        warn!(error = %e, "OCSF export final flush failed");
    }
}
