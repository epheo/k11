//! OCSF records back to `store::Event`: the inverse of `record`, for the
//! records k11 writes, so `k11 report` replays a log through the same store
//! as the live daemon. Only what an event needs is read.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::Deserialize;

use super::schema::{CLASS_FILE_SYSTEM, CLASS_NETWORK, CLASS_PROCESS, FILE_FOLDER};
use super::{AT_REMOVEDIR, CREATE, DELETE, INJECT, LAUNCH, NET_OTHER, OPEN, RENAME};
use super::{SET_SECURITY, TERMINATE};
use crate::classify::errno_ret;
use crate::cmdline::CommandLine;
use crate::container::Container;
use crate::enrich::EnrichedAddr;
use crate::store::{Event, EventMeta, Payload, Policy};

pub enum Line {
    Event(Box<Replayed>),
    /// A loss marker: records the daemon could not write.
    Lost(u64),
}

/// One event of one session, and what the record knew of its peer.
pub struct Replayed {
    /// `metadata.correlation_uid`: `<boot id>:<root pid>`.
    pub session: String,
    pub event: Event,
    pub peer: Option<(IpAddr, EnrichedAddr)>,
}

/// None for what is neither: a record from another product or class.
pub fn replay(line: &str) -> serde_json::Result<Option<Line>> {
    let r: In = serde_json::from_str(line)?;
    if r.class_uid == 0 {
        return Ok(r.count.map(Line::Lost));
    }
    let (Some(session), Some(payload), Some(actor)) = (
        r.metadata.correlation_uid.clone(),
        payload(&r),
        r.actor.as_ref(),
    ) else {
        return Ok(None);
    };
    let actor = &actor.process;
    let peer = match (&payload, &r.dst_endpoint) {
        (Payload::Connect { addr }, Some(dst)) => Some((addr.ip(), dst.known(&r.enrichments))),
        _ => None,
    };
    let event = Event {
        meta: EventMeta {
            seq: r.metadata.sequence.unwrap_or(0),
            pid: actor.pid,
            root_pid: r.unmapped.root_pid,
            uid: actor
                .user
                .as_ref()
                .and_then(|u| u.uid.parse().ok())
                .unwrap_or(0),
            comm: actor.name.as_deref().unwrap_or_default().into(),
            timestamp_ns: r.time.saturating_mul(1_000_000),
            ret: r.status_code.as_deref().and_then(errno_ret).unwrap_or(0),
            container: r.container.as_ref().and_then(|c| {
                let runtime = ["podman", "docker", "containerd", "cri-o", "lxc"]
                    .into_iter()
                    .find(|known| *known == c.runtime)?;
                Some(Arc::new(Container {
                    runtime,
                    id: c.uid.clone(),
                    name: c.name.clone(),
                    image: c.image.as_ref().map(|i| i.name.clone()),
                }))
            }),
        },
        payload,
    };
    Ok(Some(Line::Event(Box::new(Replayed {
        session,
        event,
        peer,
    }))))
}

fn payload(r: &In) -> Option<Payload> {
    let file = || r.file.as_ref().map(|f| f.path.clone());
    Some(match (r.class_uid, r.activity_id) {
        (CLASS_PROCESS, LAUNCH) => {
            let p = r.process.as_ref()?;
            match (&p.file, &p.parent_process) {
                (Some(f), _) => Payload::Execve {
                    filename: f.path.clone(),
                    cmd_line: p
                        .cmd_line
                        .as_deref()
                        .and_then(CommandLine::from_shell)
                        .map(Arc::new),
                },
                (None, Some(_)) => Payload::Fork { child_pid: p.pid },
                (None, None) => return None,
            }
        }
        (CLASS_PROCESS, TERMINATE) => Payload::Exit,
        (CLASS_PROCESS, INJECT) => Payload::Ptrace {
            request: r.unmapped.ptrace_request?,
            target_pid: r.process.as_ref()?.pid,
        },
        (CLASS_FILE_SYSTEM, OPEN) => Payload::Open {
            filename: file()?,
            flags: r.access_mask.unwrap_or(0),
            policy: match r.disposition_id {
                Some(2) => Policy::Denied,
                Some(15) => Policy::Audited,
                _ => Policy::Allowed,
            },
        },
        (CLASS_FILE_SYSTEM, DELETE) => Payload::Unlink {
            filename: file()?,
            flags: match r.file.as_ref()?.type_id {
                FILE_FOLDER => AT_REMOVEDIR,
                _ => 0,
            },
        },
        (CLASS_FILE_SYSTEM, RENAME) => Payload::Rename {
            old_path: file()?,
            new_path: r.file_result.as_ref()?.path.clone(),
        },
        (CLASS_FILE_SYSTEM, SET_SECURITY) => match r.unmapped.mode {
            Some(mode) => Payload::Chmod {
                filename: file()?,
                mode,
            },
            None => Payload::Chown {
                filename: file()?,
                owner_uid: r.file.as_ref()?.owner.as_ref()?.uid.parse().ok()?,
                owner_gid: r.unmapped.owner_gid?,
            },
        },
        (CLASS_FILE_SYSTEM, CREATE) => Payload::Symlink {
            target: r.unmapped.symlink_target.clone()?,
            linkpath: file()?,
        },
        (CLASS_NETWORK, NET_OTHER) => {
            let dst = r.dst_endpoint.as_ref()?;
            match r.activity_name.as_deref()? {
                "Bind" => Payload::Bind {
                    addr: SocketAddr::new(dst.ip?, dst.port?),
                },
                "Listen" => Payload::Listen {
                    backlog: r.unmapped.backlog?,
                },
                _ => return None,
            }
        }
        (CLASS_NETWORK, _) => {
            let dst = r.dst_endpoint.as_ref()?;
            match dst.ip {
                Some(ip) => Payload::Connect {
                    addr: SocketAddr::new(ip, dst.port?),
                },
                None => Payload::UnixConnect {
                    path: dst.name.clone()?,
                },
            }
        }
        _ => return None,
    })
}

#[derive(Deserialize)]
struct In {
    #[serde(default)]
    metadata: MetadataIn,
    time: u64,
    status_code: Option<String>,
    disposition_id: Option<u32>,
    class_uid: u32,
    activity_id: u32,
    activity_name: Option<String>,
    container: Option<ContainerIn>,
    actor: Option<ActorIn>,
    /// Loss markers.
    count: Option<u64>,
    #[serde(default)]
    enrichments: Vec<EnrichmentIn>,
    process: Option<ProcessIn>,
    file: Option<FileIn>,
    file_result: Option<FileIn>,
    access_mask: Option<i32>,
    dst_endpoint: Option<EndpointIn>,
    #[serde(default)]
    unmapped: UnmappedIn,
}

#[derive(Deserialize, Default)]
struct MetadataIn {
    correlation_uid: Option<String>,
    sequence: Option<u64>,
}

#[derive(Deserialize)]
struct ContainerIn {
    uid: String,
    runtime: String,
    name: Option<String>,
    image: Option<ImageIn>,
}

#[derive(Deserialize)]
struct ImageIn {
    name: String,
}

#[derive(Deserialize)]
struct ActorIn {
    process: ProcessIn,
}

#[derive(Deserialize)]
struct ProcessIn {
    pid: u32,
    name: Option<String>,
    file: Option<FileIn>,
    cmd_line: Option<String>,
    user: Option<UserIn>,
    parent_process: Option<ProcessRefIn>,
}

#[derive(Deserialize)]
struct ProcessRefIn {}

#[derive(Deserialize)]
struct UserIn {
    uid: String,
}

#[derive(Deserialize)]
struct FileIn {
    path: String,
    type_id: u32,
    owner: Option<UserIn>,
}

#[derive(Deserialize)]
struct EndpointIn {
    ip: Option<IpAddr>,
    port: Option<u16>,
    hostname: Option<String>,
    name: Option<String>,
    location: Option<LocationIn>,
}

impl EndpointIn {
    fn known(&self, enrichments: &[EnrichmentIn]) -> EnrichedAddr {
        EnrichedAddr {
            hostname: self.hostname.clone(),
            country: self.location.as_ref().and_then(|l| l.country.clone()),
            city: self.location.as_ref().and_then(|l| l.city.clone()),
            asn: enrichments
                .iter()
                .find(|e| e.name == "dst_endpoint.ip")
                .map(|e| e.data.asn.clone()),
        }
    }
}

#[derive(Deserialize)]
struct LocationIn {
    country: Option<String>,
    city: Option<String>,
}

#[derive(Deserialize)]
struct EnrichmentIn {
    name: String,
    data: AsnIn,
}

#[derive(Deserialize)]
struct AsnIn {
    asn: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UnmappedIn {
    root_pid: u32,
    mode: Option<u32>,
    owner_gid: Option<u32>,
    symlink_target: Option<String>,
    backlog: Option<i32>,
    ptrace_request: Option<u32>,
}
