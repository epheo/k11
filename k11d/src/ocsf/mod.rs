//! `store::Event` to OCSF 1.1.0 records, one per event, for JSON Lines.
//!
//! Three classes: Process Activity (1007) for Execve, Fork, Exit, Ptrace;
//! File System Activity (1001) for Openat, Unlink, Rename, Chmod, Chown,
//! Symlink; Network Activity (4001) for Connect, UnixConnect, Bind, Listen.
//! Every record carries the shared envelope built by `Record::new`.

mod envelope;
mod file;
mod network;
mod process;

pub use envelope::Record;

use crate::enrich::EnrichedEvent;
use crate::store::{Event, Payload};

pub fn record<'a>(event: &'a Event, enriched: &'a EnrichedEvent, hostname: &'a str) -> Record<'a> {
    match &event.payload {
        Payload::Execve { .. } => process::execve(event, enriched, hostname),
        Payload::Fork { .. } => process::fork(event, enriched, hostname),
        Payload::Exit => process::exit(event, enriched, hostname),
        Payload::Ptrace { .. } => process::ptrace(event, enriched, hostname),
        Payload::Openat { .. } => file::openat(event, enriched, hostname),
        Payload::Unlink { .. } => file::unlink(event, enriched, hostname),
        Payload::Rename { .. } => file::rename(event, enriched, hostname),
        Payload::Chmod { .. } => file::chmod(event, enriched, hostname),
        Payload::Chown { .. } => file::chown(event, enriched, hostname),
        Payload::Symlink { .. } => file::symlink(event, enriched, hostname),
        Payload::Connect { .. } => network::connect(event, enriched, hostname),
        Payload::UnixConnect { .. } => network::unix_connect(event, enriched, hostname),
        Payload::Bind { .. } => network::bind(event, enriched, hostname),
        Payload::Listen { .. } => network::listen(event, enriched, hostname),
    }
}

#[cfg(test)]
mod tests;
