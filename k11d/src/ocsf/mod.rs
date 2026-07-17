//! Pure mapping from `store::Event` to OCSF 1.1.0 JSON records.
//!
//! Each event produces one `serde_json::Value`, suitable for JSON Lines output.
//! Covers three OCSF event classes:
//!   - Process Activity (1007): Execve, Fork, Exit, Ptrace
//!   - File System Activity (1001): Openat, Unlink, Rename, Chmod, Chown, Symlink
//!   - Network Activity (4001): Connect, UnixConnect, Bind, Listen
//!
//! Every record carries: metadata (with per-agent correlation_uid), time
//! (epoch ms) + time_dt (RFC3339), message, severity_id, status_id,
//! disposition_id, class_uid, category_uid, activity_id, type_uid, device,
//! src_endpoint, actor.process, observables[], and an `enrichments[]` entry
//! with the k11 composite risk score.

mod envelope;
mod file;
mod network;
mod process;

use serde_json::Value;

use crate::enrich::EnrichedEvent;
use crate::store::{Event, Payload};

/// Convert a `store::Event` to an OCSF 1.1.0 JSON record.
pub fn to_ocsf(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
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
