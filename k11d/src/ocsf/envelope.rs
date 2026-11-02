//! The OCSF record type, risk scoring, and the RFC3339 formatter.
//!
//! One `Record` struct covers all three classes: fields a class does not use
//! stay `None` and are skipped on output. Typed serialization is both the
//! schema and the fast path (no intermediate JSON tree).

use serde::Serialize;

use crate::enrich::EnrichedEvent;
use crate::store::{Event, Policy};

pub const CLASS_FILE_SYSTEM_ACTIVITY: u32 = 1001;
pub const CLASS_PROCESS_ACTIVITY: u32 = 1007;
pub const CLASS_NETWORK_ACTIVITY: u32 = 4001;

pub const CATEGORY_SYSTEM: u32 = 1;
pub const CATEGORY_NETWORK: u32 = 4;

pub const SEV_INFO: u32 = 1;
pub const SEV_LOW: u32 = 2;
pub const SEV_MEDIUM: u32 = 3;
pub const SEV_HIGH: u32 = 4;
pub const SEV_CRITICAL: u32 = 5;

pub const STATUS_SUCCESS: u32 = 1;
pub const STATUS_FAILURE: u32 = 2;

pub const DISPOSITION_ALLOWED: u32 = 1;
pub const DISPOSITION_BLOCKED: u32 = 2;
/// Matched a rule, logged, allowed: audit mode.
pub const DISPOSITION_DETECTED: u32 = 15;

// OCSF observable type_ids (https://schema.ocsf.io/1.1.0/objects/observable)
pub const OBS_HOSTNAME: u32 = 1;
pub const OBS_IP: u32 = 2;
pub const OBS_USER_NAME: u32 = 4;
pub const OBS_FILE_PATH: u32 = 7;
pub const OBS_PROCESS_NAME: u32 = 20;

/// Flags that imply the file's contents will be modified:
/// O_WRONLY | O_RDWR | O_TRUNC | O_APPEND. Excludes O_CREAT: creating a
/// file is distinct from writing to it, and OCSF splits the two.
pub const MODIFY_FLAGS: i32 = 0x1 | 0x2 | 0x200 | 0x400;
pub const O_CREAT: i32 = 0x40;

const PRODUCT: &str = "k11";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
pub struct Record<'a> {
    pub metadata: Metadata,
    /// Epoch milliseconds.
    pub time: u64,
    pub time_dt: String,
    pub message: String,
    pub severity_id: u32,
    pub status_id: u32,
    pub disposition_id: u32,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity_id: u32,
    pub type_uid: u32,
    pub device: Endpoint<'a>,
    pub src_endpoint: Endpoint<'a>,
    pub actor: Actor<'a>,
    pub enrichments: [Enrichment; 1],
    pub observables: Vec<Observable<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_result: Option<File<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<DstEndpoint<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_info: Option<ConnectionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_type_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_type: Option<String>,
    /// Facts OCSF 1.1.0 has no field for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<Unmapped>,
}

#[derive(Serialize)]
pub struct Metadata {
    pub version: &'static str,
    pub product: Product,
    /// Groups a whole agent session: `k11-agent-<root pid>`.
    pub correlation_uid: String,
}

#[derive(Serialize)]
pub struct Product {
    pub name: &'static str,
    pub vendor_name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct Endpoint<'a> {
    pub hostname: &'a str,
}

#[derive(Serialize)]
pub struct Actor<'a> {
    pub process: Process<'a>,
}

#[derive(Serialize)]
pub struct Process<'a> {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User<'a>>,
}

impl<'a> Process<'a> {
    pub fn new(pid: u32, name: &'a str) -> Self {
        Self {
            pid,
            name: Some(name),
            cmd_line: None,
            file: None,
            user: None,
        }
    }
}

#[derive(Serialize)]
pub struct User<'a> {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
}

impl<'a> User<'a> {
    pub fn new(uid: u32, name: Option<&'a str>) -> Self {
        Self {
            uid: uid.to_string(),
            name,
        }
    }
}

#[derive(Serialize)]
pub struct File<'a> {
    pub path: &'a str,
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<&'a str>,
}

impl<'a> File<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            path,
            name: path.rsplit('/').next().unwrap_or(path),
            type_id: None,
            attributes: None,
            mode: None,
            owner: None,
            target: None,
        }
    }
}

#[derive(Serialize)]
pub struct Enrichment {
    pub name: &'static str,
    pub value: u32,
    pub provider: &'static str,
}

#[derive(Serialize)]
pub struct Observable<'a> {
    pub name: &'static str,
    pub type_id: u32,
    pub value: &'a str,
}

#[derive(Serialize, Default)]
pub struct DstEndpoint<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<&'a str>,
    /// Unix socket path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autonomous_system: Option<AutonomousSystem<'a>>,
}

#[derive(Serialize)]
pub struct Location<'a> {
    pub country: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<&'a str>,
}

#[derive(Serialize)]
pub struct AutonomousSystem<'a> {
    pub name: &'a str,
}

#[derive(Serialize)]
pub struct ConnectionInfo {
    pub direction_id: u32,
    pub direction: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_name: Option<&'static str>,
}

#[derive(Serialize, Default)]
pub struct Unmapped {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backlog: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<&'static str>,
}

impl<'a> Record<'a> {
    /// The envelope every record shares: metadata with the agent correlation
    /// id, timing, scoring, and a uniform `actor.process`.
    pub fn new(
        class_uid: u32,
        category_uid: u32,
        activity_id: u32,
        hostname: &'a str,
        event: &'a Event,
        enriched: &'a EnrichedEvent,
        message: String,
    ) -> Self {
        let meta = &event.meta;
        let (risk_score, severity_id) = risk(event);
        let (status_id, disposition_id) = status_and_disposition(event);
        let username = enriched.username.as_deref();

        let mut actor = Process::new(meta.pid, &meta.comm);
        actor.user = Some(User::new(meta.uid, username));

        let mut record = Self {
            metadata: Metadata {
                version: "1.1.0",
                product: Product {
                    name: PRODUCT,
                    vendor_name: PRODUCT,
                    version: VERSION,
                },
                correlation_uid: format!("k11-agent-{}", meta.root_pid),
            },
            time: meta.timestamp_ns / 1_000_000,
            time_dt: rfc3339_millis(meta.timestamp_ns),
            message,
            severity_id,
            status_id,
            disposition_id,
            class_uid,
            category_uid,
            activity_id,
            type_uid: class_uid * 100 + activity_id,
            device: Endpoint { hostname },
            src_endpoint: Endpoint { hostname },
            actor: Actor { process: actor },
            enrichments: [Enrichment {
                name: "k11.risk_score",
                value: risk_score,
                provider: PRODUCT,
            }],
            observables: Vec::with_capacity(4),
            process: None,
            file: None,
            file_result: None,
            dst_endpoint: None,
            connection_info: None,
            injection_type_id: None,
            injection_type: None,
            unmapped: None,
        };
        record.observe("actor.process.name", OBS_PROCESS_NAME, &meta.comm);
        if let Some(name) = username {
            record.observe("actor.process.user.name", OBS_USER_NAME, name);
        }
        record
    }

    pub fn observe(&mut self, name: &'static str, type_id: u32, value: &'a str) {
        self.observables.push(Observable {
            name,
            type_id,
            value,
        });
    }
}

/// Risk score and severity. Denied: +10 (critical). Audited (a deny rule
/// matched but enforcement is off): +6 (high). Sensitive path: +3.
/// External address: +2. Syscall error: +1.
pub fn risk(event: &Event) -> (u32, u32) {
    let mut score = match event.policy() {
        Policy::Denied => 10,
        Policy::Audited => 6,
        Policy::Allowed => 0,
    };
    if event.is_sensitive() {
        score += 3;
    }
    if event.is_external() {
        score += 2;
    }
    if event.is_error() {
        score += 1;
    }
    let severity_id = match score {
        0 => SEV_INFO,
        1..=2 => SEV_LOW,
        3..=5 => SEV_MEDIUM,
        6..=9 => SEV_HIGH,
        _ => SEV_CRITICAL,
    };
    (score, severity_id)
}

fn status_and_disposition(event: &Event) -> (u32, u32) {
    let status = if event.is_error() {
        STATUS_FAILURE
    } else {
        STATUS_SUCCESS
    };
    match event.policy() {
        Policy::Denied => (STATUS_FAILURE, DISPOSITION_BLOCKED),
        Policy::Audited => (status, DISPOSITION_DETECTED),
        Policy::Allowed => (status, DISPOSITION_ALLOWED),
    }
}

// ---------------------------------------------------------------------------
// RFC3339 formatter, no date crate. Howard Hinnant's civil_from_days.
// ---------------------------------------------------------------------------

/// Epoch nanoseconds as `YYYY-MM-DDTHH:MM:SS.sssZ`.
pub fn rfc3339_millis(ns_epoch: u64) -> String {
    let total_secs = ns_epoch / 1_000_000_000;
    let millis = (ns_epoch / 1_000_000) % 1_000;
    let days = (total_secs / 86_400) as i64;
    let tod = total_secs % 86_400;
    let (hour, minute, second) = (tod / 3600, (tod / 60) % 60, tod % 60);
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
        let days: u64 = 20_561; // 2026-04-18, via `date -u -d '2026-04-18' +%s` / 86400
        let ns = (days * 86400 + 12 * 3600) * 1_000_000_000;
        assert_eq!(rfc3339_millis(ns), "2026-04-18T12:00:00.000Z");
    }

    #[test]
    fn rfc3339_millis_precision() {
        assert_eq!(
            rfc3339_millis(1_234_567_890_123_000_000),
            "2009-02-13T23:31:30.123Z"
        );
    }
}
