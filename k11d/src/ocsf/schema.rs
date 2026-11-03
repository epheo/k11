//! OCSF 1.1.0 record types, the shared envelope, risk scoring and the
//! RFC3339 formatter. Typed serialization is both the schema and the fast
//! path (no intermediate JSON tree); fields a record does not use stay None
//! and are skipped.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use serde::Serialize;

use crate::classify::{errno_name, failed};
use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::{Event, Payload, Policy};

pub const CLASS_FILE_SYSTEM: u32 = 1001;
pub const CLASS_PROCESS: u32 = 1007;
pub const CLASS_NETWORK: u32 = 4001;

const OBS_HOSTNAME: u32 = 1;
const OBS_IP: u32 = 2;
const OBS_USER_NAME: u32 = 4;
const OBS_FILE_NAME: u32 = 7;
const OBS_PROCESS_NAME: u32 = 9;

pub const FILE_UNKNOWN: u32 = 0;
pub const FILE_REGULAR: u32 = 1;
pub const FILE_FOLDER: u32 = 2;
pub const FILE_SYMLINK: u32 = 7;

const STATUS_SUCCESS: u32 = 1;
const STATUS_FAILURE: u32 = 2;

const PRODUCT: Product = Product {
    name: "k11",
    vendor_name: "k11",
    version: env!("CARGO_PKG_VERSION"),
};

/// What every record says about the machine it comes from.
pub struct Host {
    pub hostname: String,
    /// Changes every boot: with the root pid it names an agent session that
    /// outlives a daemon restart.
    pub boot_id: String,
}

impl Host {
    pub fn detect() -> Self {
        let read = |path: &str| {
            std::fs::read_to_string(path)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into())
        };
        Self {
            hostname: read("/proc/sys/kernel/hostname"),
            boot_id: read("/proc/sys/kernel/random/boot_id"),
        }
    }
}

#[derive(Serialize)]
pub struct Record<'a> {
    pub metadata: Metadata,
    /// Epoch milliseconds.
    pub time: u64,
    pub time_dt: String,
    pub message: String,
    pub severity_id: u32,
    pub status_id: u32,
    /// errno name of a failed syscall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<Cow<'static, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_id: Option<u32>,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_name: Option<&'static str>,
    pub type_uid: u32,
    pub device: Device<'a>,
    /// The container profile: where the acting process runs, if not on the host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container<'a>>,
    pub actor: Actor<'a>,
    pub observables: Vec<Observable<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enrichments: Vec<Enrichment<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_result: Option<File<'a>>,
    /// Open flags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_mask: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_endpoint: Option<Endpoint<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_info: Option<ConnectionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_type_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_type: Option<Cow<'static, str>>,
    /// What OCSF 1.1.0 has no field for, typed so a reader can rebuild the event.
    pub unmapped: Unmapped<'a>,
}

#[derive(Serialize)]
pub struct Container<'a> {
    pub uid: &'a str,
    pub runtime: &'static str,
}

#[derive(Serialize)]
pub struct Metadata {
    pub version: &'static str,
    pub product: Product,
    pub profiles: Vec<&'static str>,
    /// One agent session: `<boot id>:<root pid>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_uid: Option<String>,
    /// Daemon decode order; a gap is a lost record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

/// The probe lost records: written when its loss counters grow, so a
/// reader of the log knows where it has gaps. A Base Event (class 0).
#[derive(Serialize)]
pub struct LossRecord<'a> {
    pub metadata: Metadata,
    pub time: u64,
    pub time_dt: String,
    pub message: String,
    pub severity_id: u32,
    pub class_uid: u32,
    pub category_uid: u32,
    pub activity_id: u32,
    pub activity_name: &'static str,
    pub type_uid: u32,
    pub device: Device<'a>,
    /// Records lost since the previous loss record.
    pub count: u64,
    /// Per probe counter.
    pub unmapped: std::collections::BTreeMap<&'static str, u64>,
}

impl<'a> LossRecord<'a> {
    pub fn new(lost: &[(&'static str, u64)], timestamp_ns: u64, host: &'a Host) -> Self {
        let count = lost.iter().map(|(_, n)| n).sum();
        let detail: Vec<String> = lost.iter().map(|(name, n)| format!("{n} {name}")).collect();
        Self {
            metadata: Metadata {
                version: "1.1.0",
                product: PRODUCT,
                profiles: vec!["host", "datetime"],
                correlation_uid: None,
                sequence: None,
            },
            time: timestamp_ns / 1_000_000,
            time_dt: rfc3339_millis(timestamp_ns),
            message: format!("k11 lost {count} records ({})", detail.join(", ")),
            severity_id: 3,
            class_uid: 0,
            category_uid: 0,
            activity_id: 99,
            activity_name: "Records lost",
            type_uid: 99,
            device: Device {
                hostname: &host.hostname,
                type_id: 0,
            },
            count,
            unmapped: lost.iter().copied().collect(),
        }
    }
}

#[derive(Serialize)]
pub struct Product {
    pub name: &'static str,
    pub vendor_name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct Device<'a> {
    pub hostname: &'a str,
    /// Unknown: k11 cannot tell a server from a laptop.
    pub type_id: u32,
}

#[derive(Serialize)]
pub struct Actor<'a> {
    pub process: Process<'a>,
}

#[derive(Serialize, Clone, Default)]
pub struct Process<'a> {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<File<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<ProcessRef>,
}

#[derive(Serialize, Clone)]
pub struct ProcessRef {
    pub pid: u32,
}

#[derive(Serialize, Clone)]
pub struct User<'a> {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
}

#[derive(Serialize, Clone)]
pub struct File<'a> {
    pub name: &'a str,
    pub path: &'a str,
    pub type_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<User<'a>>,
}

#[derive(Serialize, Default)]
pub struct Endpoint<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<&'a str>,
    /// Unix socket path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location<'a>>,
}

#[derive(Serialize)]
pub struct Location<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<&'a str>,
}

#[derive(Serialize)]
pub struct ConnectionInfo {
    pub direction_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_ver_id: Option<u32>,
}

#[derive(Serialize)]
pub struct Observable<'a> {
    pub name: &'static str,
    pub type_id: u32,
    pub value: Cow<'a, str>,
}

/// 1.1.0 has no autonomous system object; the ASN rides on the IP.
#[derive(Serialize)]
pub struct Enrichment<'a> {
    pub name: &'static str,
    pub value: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub provider: &'static str,
    pub data: AsnData<'a>,
}

#[derive(Serialize)]
pub struct AsnData<'a> {
    pub asn: &'a str,
}

#[derive(Serialize, Default)]
pub struct Unmapped<'a> {
    pub root_pid: u32,
    pub risk_score: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backlog: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptrace_request: Option<u32>,
}

impl<'a> Record<'a> {
    /// The envelope every record shares. Opens pass the deny rules, so they
    /// carry the security_control profile and its action and disposition.
    pub fn new(
        class_uid: u32,
        activity_id: u32,
        event: &'a Event,
        enriched: &'a EnrichedEvent,
        host: &'a Host,
    ) -> Self {
        let m = &event.meta;
        let (risk_score, severity_id) = risk(event);
        let controlled = matches!(event.payload, Payload::Open { .. });
        let (action_id, disposition_id) = match event.policy() {
            _ if !controlled => (None, None),
            Policy::Denied => (Some(2), Some(2)),
            Policy::Audited => (Some(1), Some(15)),
            Policy::Allowed => (Some(1), Some(1)),
        };
        let username = enriched.username.as_deref();
        let mut r = Self {
            metadata: Metadata {
                version: "1.1.0",
                product: PRODUCT,
                profiles: [
                    Some("host"),
                    controlled.then_some("security_control"),
                    m.container.is_some().then_some("container"),
                    Some("datetime"),
                ]
                .into_iter()
                .flatten()
                .collect(),
                correlation_uid: Some(format!("{}:{}", host.boot_id, m.root_pid)),
                sequence: Some(m.seq),
            },
            time: m.timestamp_ns / 1_000_000,
            time_dt: rfc3339_millis(m.timestamp_ns),
            message: event.describe(),
            severity_id,
            status_id: if event.is_denied() || event.is_error() {
                STATUS_FAILURE
            } else {
                STATUS_SUCCESS
            },
            status_code: failed(m.ret).then(|| errno_name(m.ret)),
            action_id,
            disposition_id,
            class_uid,
            category_uid: class_uid / 1000,
            activity_id,
            activity_name: None,
            type_uid: class_uid * 100 + activity_id,
            device: Device {
                hostname: &host.hostname,
                type_id: 0,
            },
            container: m.container.as_deref().map(|c| Container {
                uid: &c.id,
                runtime: c.runtime,
            }),
            actor: Actor {
                process: Process {
                    pid: m.pid,
                    name: Some(&m.comm),
                    user: Some(User {
                        uid: m.uid.to_string(),
                        name: username,
                    }),
                    ..Process::default()
                },
            },
            observables: Vec::with_capacity(4),
            enrichments: Vec::new(),
            process: None,
            file: None,
            file_result: None,
            access_mask: None,
            src_endpoint: None,
            dst_endpoint: None,
            connection_info: None,
            injection_type_id: None,
            injection_type: None,
            unmapped: Unmapped {
                root_pid: m.root_pid,
                risk_score,
                ..Unmapped::default()
            },
        };
        r.observe("actor.process.name", OBS_PROCESS_NAME, &*m.comm);
        if let Some(name) = username {
            r.observe("actor.process.user.name", OBS_USER_NAME, name);
        }
        r.observe("device.hostname", OBS_HOSTNAME, &host.hostname);
        r
    }

    fn observe(&mut self, name: &'static str, type_id: u32, value: impl Into<Cow<'a, str>>) {
        self.observables.push(Observable {
            name,
            type_id,
            value: value.into(),
        });
    }

    /// A file object, observed by name at `attr`.
    pub fn file(&mut self, attr: &'static str, path: &'a str, type_id: u32) -> File<'a> {
        let name = path.rsplit('/').next().unwrap_or(path);
        self.observe(attr, OBS_FILE_NAME, name);
        File {
            name,
            path,
            type_id,
            owner: None,
        }
    }

    /// The remote end of a connect, with what enrichment knows about it.
    pub fn remote(&mut self, addr: SocketAddr, known: Option<&'a EnrichedAddr>) -> Endpoint<'a> {
        let ip = addr.ip().to_canonical();
        self.observe("dst_endpoint.ip", OBS_IP, ip.to_string());
        let mut endpoint = Endpoint {
            ip: Some(ip),
            port: Some(addr.port()),
            ..Endpoint::default()
        };
        let Some(known) = known else {
            return endpoint;
        };
        if let Some(hostname) = &known.hostname {
            self.observe("dst_endpoint.hostname", OBS_HOSTNAME, hostname.as_str());
            endpoint.hostname = Some(hostname);
        }
        if known.country.is_some() || known.city.is_some() {
            endpoint.location = Some(Location {
                country: known.country.as_deref(),
                city: known.city.as_deref(),
            });
        }
        if let Some(asn) = &known.asn {
            self.enrichments.push(Enrichment {
                name: "dst_endpoint.ip",
                value: ip.to_string(),
                kind: "asn",
                provider: "MaxMind GeoLite2",
                data: AsnData { asn },
            });
        }
        endpoint
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
    score += 3 * event.is_sensitive() as u32;
    score += 2 * event.is_external() as u32;
    score += event.is_error() as u32;
    let severity_id = match score {
        0 => 1,     // Informational
        1..=2 => 2, // Low
        3..=5 => 3, // Medium
        6..=9 => 4, // High
        _ => 5,     // Critical
    };
    (score, severity_id)
}

/// Epoch nanoseconds as `YYYY-MM-DDTHH:MM:SS.sssZ`, no date crate (Howard
/// Hinnant's civil_from_days).
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
