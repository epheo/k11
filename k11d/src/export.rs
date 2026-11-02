//! OCSF JSON Lines export: the durable record.
//!
//! Fed by a bounded, lossless channel from the decode loop. When the writer
//! falls behind, the decode loop waits and the kernel ring absorbs the burst,
//! so loss happens in one place (the probe's ring-full counter). The writer
//! runs on its own thread so a slow disk or pipe never blocks the runtime;
//! it flushes whenever the queue runs dry, syncs the file at shutdown, and
//! rotates it by size.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Stdout, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::mpsc::{self, error::TryRecvError};
use tracing::{info, warn};

use crate::config::ExportConfig;
use crate::enrich::Enricher;
use crate::ocsf::{self, Host};
use crate::store::Event;

/// What the export writes.
pub enum Item {
    Event(Arc<Event>),
    /// Probe counters that grew since the last report: name and delta.
    Loss(Vec<(&'static str, u64)>),
}

pub enum Output {
    Stdout(Stdout),
    File(LogFile),
}

impl Output {
    pub fn open(config: &ExportConfig) -> io::Result<Self> {
        if config.output == "-" {
            return Ok(Self::Stdout(io::stdout()));
        }
        LogFile::open(PathBuf::from(&config.output), config.max_mb * 1024 * 1024).map(Self::File)
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.write_all(line),
            Self::File(file) => file.write_line(line),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.flush(),
            Self::File(file) => file.out.flush(),
        }
    }

    fn finish(&mut self) -> io::Result<()> {
        self.flush()?;
        match self {
            Self::File(file) => file.out.get_ref().sync_data(),
            Self::Stdout(_) => Ok(()),
        }
    }
}

/// The export file, rotated to `<path>.1` past `max` bytes.
pub struct LogFile {
    path: PathBuf,
    out: BufWriter<File>,
    written: u64,
    max: u64,
}

impl LogFile {
    fn open(path: PathBuf, max: u64) -> io::Result<Self> {
        let file = Self::create(&path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path,
            out: BufWriter::new(file),
            written,
            max,
        })
    }

    /// It holds every path the agent touched: owner-only.
    fn create(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if self.max > 0 && self.written > 0 && self.written + line.len() as u64 > self.max {
            self.rotate()?;
        }
        self.out.write_all(line)?;
        self.written += line.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.out.flush()?;
        self.out.get_ref().sync_data()?;
        let mut previous = self.path.clone().into_os_string();
        previous.push(".1");
        std::fs::rename(&self.path, previous)?;
        self.out = BufWriter::new(Self::create(&self.path)?);
        self.written = 0;
        info!(path = %self.path.display(), "OCSF export rotated");
        Ok(())
    }
}

pub fn spawn(
    rx: mpsc::Receiver<Item>,
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

fn run(mut rx: mpsc::Receiver<Item>, mut out: Output, host: &Host, enricher: &Arc<Enricher>) {
    let mut line = Vec::with_capacity(2048);
    // Failures are logged on state changes, so a full disk warns once.
    let mut lost: u64 = 0;
    loop {
        let item = match rx.try_recv() {
            Ok(item) => item,
            Err(TryRecvError::Empty) => {
                if let Err(e) = out.flush() {
                    warn!(error = %e, "OCSF export flush failed");
                }
                match rx.blocking_recv() {
                    Some(item) => item,
                    None => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        line.clear();
        let written = match item {
            Item::Event(event) => {
                let enriched = enricher.event(&event);
                serde_json::to_writer(&mut line, &ocsf::record(&event, &enriched, host))
            }
            Item::Loss(lost) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
                serde_json::to_writer(&mut line, &ocsf::LossRecord::new(&lost, now, host))
            }
        };
        written.expect("OCSF records serialize");
        line.push(b'\n');
        match out.write_line(&line) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_past_the_size_limit() {
        let dir = std::env::temp_dir().join(format!("k11-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ocsf.jsonl");
        let mut file = LogFile::open(path.clone(), 10).unwrap();
        file.write_line(b"0123456\n").unwrap();
        file.write_line(b"abcdefg\n").unwrap();
        file.out.flush().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"abcdefg\n");
        assert_eq!(
            std::fs::read(dir.join("ocsf.jsonl.1")).unwrap(),
            b"0123456\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
