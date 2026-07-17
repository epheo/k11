//! OCSF envelope builder, risk scoring, observables, and RFC3339 formatter.
//!
//! The envelope is the common set of fields every OCSF record carries
//! (metadata, time, severity, class/activity/type, device, actor, agent
//! correlation). Class-specific payloads (process/file/network objects) are
//! added by the per-class modules.

use serde_json::{json, Value};

use crate::enrich::EnrichedEvent;
use crate::store::{self, Event, Payload};

// --- OCSF class / category UIDs ---
pub const CLASS_FILE_SYSTEM_ACTIVITY: u32 = 1001;
pub const CLASS_PROCESS_ACTIVITY: u32 = 1007;
pub const CLASS_NETWORK_ACTIVITY: u32 = 4001;

pub const CATEGORY_SYSTEM: u32 = 1;
pub const CATEGORY_NETWORK: u32 = 4;

// --- OCSF severity / status / disposition ---
pub const SEV_INFO: u32 = 1;
pub const SEV_LOW: u32 = 2;
pub const SEV_MEDIUM: u32 = 3;
pub const SEV_HIGH: u32 = 4;
pub const SEV_CRITICAL: u32 = 5;

pub const STATUS_SUCCESS: u32 = 1;
pub const STATUS_FAILURE: u32 = 2;

pub const DISPOSITION_ALLOWED: u32 = 1;
pub const DISPOSITION_BLOCKED: u32 = 2;

/// Flags that imply the file's contents will be modified:
/// O_WRONLY | O_RDWR | O_TRUNC | O_APPEND. Deliberately excludes O_CREAT —
/// creating a file is distinct from writing to it, and OCSF splits the two.
pub const MODIFY_FLAGS: i32 = 0x1 | 0x2 | 0x200 | 0x400;
/// O_CREAT
pub const O_CREAT: i32 = 0x40;

static PRODUCT: &str = "k11";
static VENDOR: &str = "k11";
static VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the shared envelope fields. Class-specific objects (process/file/
/// network) are inserted by the caller.
///
/// Every record carries a uniform `actor.process` (the acting process from
/// event meta) and `metadata.correlation_uid` keyed on the agent tree's root
/// pid, so SIEM queries can group a whole agent session.
pub fn envelope(
    class_uid: u32,
    category_uid: u32,
    activity_id: u32,
    hostname: &str,
    event: &Event,
    enriched: &EnrichedEvent,
    message: String,
) -> Value {
    let meta = &event.meta;
    let (risk_score, severity_id) = risk(event, enriched);
    let (status_id, disposition_id) = status_and_disposition(event);
    let type_uid = class_uid * 100 + activity_id;
    let time_ms = meta.timestamp_ns / 1_000_000;

    let mut v = json!({
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": PRODUCT,
                "vendor_name": VENDOR,
                "version": VERSION,
            },
            "correlation_uid": format!("k11-agent-{}", meta.root_pid),
        },
        "time": time_ms,
        "time_dt": rfc3339_millis(meta.timestamp_ns),
        "message": message,
        "severity_id": severity_id,
        "status_id": status_id,
        "disposition_id": disposition_id,
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": activity_id,
        "type_uid": type_uid,
        "device": {
            "hostname": hostname,
        },
        "src_endpoint": {
            "hostname": hostname,
        },
        "actor": {
            "process": {
                "pid": meta.pid,
                "name": meta.comm,
                "user": user_object(meta.uid, enriched.username.as_deref()),
            },
        },
        "enrichments": [
            {
                "name": "k11.risk_score",
                "value": risk_score,
                "provider": "k11",
            }
        ],
    });

    push_observable(&mut v, "actor.process.name", OBS_PROCESS_NAME, &meta.comm);
    if let Some(name) = enriched.username.as_deref() {
        push_observable(&mut v, "actor.process.user.name", OBS_USER_NAME, name);
    }
    v
}

/// Compose an OCSF `file` object from a path.
pub fn file_object(path: &str) -> Value {
    let name = path.rsplit('/').next().unwrap_or(path);
    json!({
        "path": path,
        "name": name,
    })
}

/// Compose an OCSF `user` object from a uid + optional username.
pub fn user_object(uid: u32, username: Option<&str>) -> Value {
    match username {
        Some(name) => json!({ "uid": uid.to_string(), "name": name }),
        None => json!({ "uid": uid.to_string() }),
    }
}

/// Append one observable to the `observables` array on the envelope.
pub fn push_observable(v: &mut Value, name: &str, type_id: u32, value: &str) {
    let obs = v.as_object_mut().unwrap()
        .entry("observables")
        .or_insert_with(|| json!([]));
    obs.as_array_mut().unwrap().push(json!({
        "name": name,
        "type_id": type_id,
        "value": value,
    }));
}

// OCSF observable type_ids (https://schema.ocsf.io/1.1.0/objects/observable)
pub const OBS_HOSTNAME: u32 = 1;
pub const OBS_IP: u32 = 2;
pub const OBS_USER_NAME: u32 = 4;
pub const OBS_FILE_PATH: u32 = 7;
pub const OBS_PROCESS_NAME: u32 = 20;

/// Risk score + severity. Composes denial, sensitive-path, external-address,
/// and syscall-error signals into a 0..=N score and maps to OCSF severity.
///
/// Denied: +10 (CRITICAL); sensitive path touched: +3; external address
/// contacted: +2; syscall error (ret < 0, not denied): +1.
pub fn risk(event: &Event, enriched: &EnrichedEvent) -> (u32, u32) {
    let mut score = 0u32;
    if event.is_denied() { score += 10; }
    if touches_sensitive_path(event) { score += 3; }
    if touches_external_addr(event, enriched) { score += 2; }
    if event.is_error() { score += 1; }

    let severity_id = match score {
        0 => SEV_INFO,
        1..=2 => SEV_LOW,
        3..=5 => SEV_MEDIUM,
        6..=9 => SEV_HIGH,
        _ => SEV_CRITICAL,
    };
    (score, severity_id)
}

fn touches_sensitive_path(event: &Event) -> bool {
    match &event.payload {
        Payload::Execve { filename }
        | Payload::Openat { filename, .. }
        | Payload::Unlink { filename, .. }
        | Payload::Chmod { filename, .. }
        | Payload::Chown { filename, .. } => store::is_sensitive_path(filename),
        Payload::Rename { old_path, new_path, .. } => {
            store::is_sensitive_path(old_path) || store::is_sensitive_path(new_path)
        }
        Payload::Symlink { target, linkpath, .. } => {
            store::is_sensitive_path(target) || store::is_sensitive_path(linkpath)
        }
        _ => false,
    }
}

fn touches_external_addr(event: &Event, _enriched: &EnrichedEvent) -> bool {
    match &event.payload {
        Payload::Connect { addr, .. } | Payload::Bind { addr, .. } => {
            store::is_external_addr(addr)
        }
        _ => false,
    }
}

/// OCSF status_id + disposition_id derived from event state.
fn status_and_disposition(event: &Event) -> (u32, u32) {
    if event.is_denied() {
        (STATUS_FAILURE, DISPOSITION_BLOCKED)
    } else if event.is_error() {
        (STATUS_FAILURE, DISPOSITION_ALLOWED)
    } else {
        (STATUS_SUCCESS, DISPOSITION_ALLOWED)
    }
}

// ---------------------------------------------------------------------------
// RFC3339 formatter — no external date crate.
// Derived from Howard Hinnant's date algorithms (civil_from_days).
// ---------------------------------------------------------------------------

/// Format epoch nanoseconds as RFC3339 with millisecond precision: `YYYY-MM-DDTHH:MM:SS.sssZ`.
pub fn rfc3339_millis(ns_epoch: u64) -> String {
    let total_secs = ns_epoch / 1_000_000_000;
    let millis = (ns_epoch / 1_000_000) % 1_000;
    let days = (total_secs / 86_400) as i64;
    let tod = total_secs % 86_400;
    let hour = (tod / 3600) as u32;
    let minute = ((tod / 60) % 60) as u32;
    let second = (tod % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_epoch_zero() {
        assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn rfc3339_known_instant() {
        // 2026-04-18T12:00:00Z → 1 propagated-Gregorian seconds since 1970-01-01
        // seconds = (days from 1970-01-01 to 2026-04-18) * 86400 + 12*3600
        let days: u64 = 20_561; // verified via `date -u -d '2026-04-18' +%s` / 86400
        let ns = (days * 86400 + 12 * 3600) * 1_000_000_000;
        assert_eq!(rfc3339_millis(ns), "2026-04-18T12:00:00.000Z");
    }

    #[test]
    fn rfc3339_millis_precision() {
        // Unix timestamp 1_234_567_890.123 s → 2009-02-13T23:31:30.123Z.
        let ns = 1_234_567_890_123_000_000;
        assert_eq!(rfc3339_millis(ns), "2009-02-13T23:31:30.123Z");
    }
}
