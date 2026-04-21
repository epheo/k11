//! Pure mapping from `store::Event` to OCSF 1.1.0 JSON records.
//!
//! Each event produces one `serde_json::Value`, suitable for JSON Lines output.
//! Covers three OCSF event classes:
//!   - Process Activity (1007): Execve, Fork, Exit, Ptrace
//!   - File System Activity (1001): Openat, Unlink, Rename, Chmod, Chown, Symlink
//!   - Network Activity (4001): Connect, UnixConnect, Bind, Listen
//!
//! Every record carries: metadata, time (epoch ms) + time_dt (RFC3339),
//! message, severity_id, status_id, disposition_id, class_uid, category_uid,
//! activity_id, type_uid, device, src_endpoint, observables[], and an
//! `enrichments[]` entry with the k11 composite risk score.

mod envelope;
mod file;
mod network;
mod process;

use serde_json::Value;

use crate::enrich::EnrichedEvent;
use crate::store::Event;

/// Convert a `store::Event` to an OCSF 1.1.0 JSON record.
pub fn to_ocsf(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    match event {
        Event::Execve { .. } => process::execve(event, enriched, hostname),
        Event::Fork { .. } => process::fork(event, enriched, hostname),
        Event::Exit { .. } => process::exit(event, enriched, hostname),
        Event::Ptrace { .. } => process::ptrace(event, enriched, hostname),
        Event::Openat { .. } => file::openat(event, enriched, hostname),
        Event::Unlink { .. } => file::unlink(event, enriched, hostname),
        Event::Rename { .. } => file::rename(event, enriched, hostname),
        Event::Chmod { .. } => file::chmod(event, enriched, hostname),
        Event::Chown { .. } => file::chown(event, enriched, hostname),
        Event::Symlink { .. } => file::symlink(event, enriched, hostname),
        Event::Connect { .. } => network::connect(event, enriched, hostname),
        Event::UnixConnect { .. } => network::unix_connect(event, enriched, hostname),
        Event::Bind { .. } => network::bind(event, enriched, hostname),
        Event::Listen { .. } => network::listen(event, enriched, hostname),
    }
}

#[cfg(test)]
mod tests;
