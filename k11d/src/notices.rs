//! What a person should hear about as it happens: an agent reaching a host,
//! opening a port to other hosts, touching a sensitive file, matching a deny
//! rule, tracing a process. Once per agent tree and target, so a notice is
//! news, not a log. The dashboard lists them and can raise a desktop
//! notification; one that names a file can become a deny rule in one answer.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use k11_proto as proto;

use crate::classify::is_sensitive_path;
use crate::enrich::EnrichedAddr;
use crate::store::{Event, Payload, Policy};

/// Past this many the oldest give way, and what was seen starts over.
const MAX_NOTICES: usize = 500;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Kind {
    Host,
    Exposed,
    Sensitive,
    Rule,
    Ptrace,
}

/// What the notice is about; with the tree and the kind, what makes it news.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Subject {
    Path(String),
    Peer(SocketAddr),
    Pid(u32),
}

pub struct Notice {
    pub id: u64,
    pub timestamp_ms: u64,
    pub root_pid: u32,
    pub agent: String,
    pub pid: u32,
    pub comm: Arc<str>,
    pub kind: Kind,
    pub subject: Subject,
    /// The event's line.
    pub summary: String,
}

pub struct Notices {
    list: VecDeque<Notice>,
    seen: HashSet<(u32, Kind, Subject)>,
    last_id: u64,
    /// When this daemon started, in ms: ids start over with it.
    epoch: u64,
}

impl Notices {
    pub fn new() -> Self {
        Self {
            list: VecDeque::new(),
            seen: HashSet::new(),
            last_id: 0,
            epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        }
    }

    /// `agent` names the event's tree.
    pub fn observe(&mut self, event: &Event, agent: &str) {
        let Some((kind, subject)) = notable(event) else {
            return;
        };
        if self.seen.len() >= 4 * MAX_NOTICES {
            self.seen.clear();
        }
        if !self
            .seen
            .insert((event.meta.root_pid, kind, subject.clone()))
        {
            return;
        }
        if self.list.len() >= MAX_NOTICES {
            self.list.pop_front();
        }
        self.last_id += 1;
        self.list.push_back(Notice {
            id: self.last_id,
            timestamp_ms: event.meta.timestamp_ns / 1_000_000,
            root_pid: event.meta.root_pid,
            agent: agent.to_string(),
            pid: event.meta.pid,
            comm: Arc::clone(&event.meta.comm),
            kind,
            subject,
            summary: event.describe(),
        });
    }

    /// Notices after `id`, oldest first.
    pub fn view(
        &self,
        after: u64,
        enrich: &dyn Fn(std::net::IpAddr) -> EnrichedAddr,
    ) -> proto::GetNoticesResponse {
        proto::GetNoticesResponse {
            epoch: self.epoch,
            notices: self
                .list
                .iter()
                .filter(|n| n.id > after)
                .map(|n| n.view(enrich))
                .collect(),
        }
    }
}

fn notable(event: &Event) -> Option<(Kind, Subject)> {
    // A failed attempt is news too: probing for a key that is not there.
    match &event.payload {
        Payload::Open {
            filename, policy, ..
        } if *policy != Policy::Allowed => Some((Kind::Rule, Subject::Path(filename.clone()))),
        Payload::Connect { addr } | Payload::Bind { addr } if event.is_external() => {
            let kind = match event.payload {
                Payload::Connect { .. } => Kind::Host,
                _ => Kind::Exposed,
            };
            Some((kind, Subject::Peer(*addr)))
        }
        Payload::Ptrace { target_pid, .. } => Some((Kind::Ptrace, Subject::Pid(*target_pid))),
        _ => event
            .paths()
            .find(|p| is_sensitive_path(p))
            .map(|p| (Kind::Sensitive, Subject::Path(p.to_string()))),
    }
}

impl Notice {
    fn view(&self, enrich: &dyn Fn(std::net::IpAddr) -> EnrichedAddr) -> proto::Notice {
        use proto::NoticeKind as K;
        let (path, peer, peer_name) = match &self.subject {
            Subject::Path(p) => (p.clone(), String::new(), String::new()),
            Subject::Peer(addr) => {
                let known = enrich(addr.ip());
                let name: Vec<String> = [known.hostname, known.asn].into_iter().flatten().collect();
                (String::new(), addr.to_string(), name.join(", "))
            }
            Subject::Pid(_) => Default::default(),
        };
        proto::Notice {
            id: self.id,
            timestamp_ms: self.timestamp_ms,
            root_pid: self.root_pid,
            agent: self.agent.clone(),
            pid: self.pid,
            comm: self.comm.to_string(),
            kind: match self.kind {
                Kind::Host => K::Host,
                Kind::Exposed => K::Exposed,
                Kind::Sensitive => K::Sensitive,
                Kind::Rule => K::Rule,
                Kind::Ptrace => K::Ptrace,
            } as i32,
            summary: self.summary.clone(),
            path,
            peer,
            peer_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::EventMeta;

    fn ev(root_pid: u32, ret: i32, payload: Payload) -> Event {
        Event {
            meta: EventMeta {
                seq: 0,
                pid: root_pid + 1,
                root_pid,
                uid: 1000,
                comm: "claude".into(),
                timestamp_ns: 5_000_000,
                ret,
                container: None,
            },
            payload,
        }
    }

    fn open(path: &str, policy: Policy) -> Payload {
        Payload::Open {
            filename: path.into(),
            flags: 0,
            policy,
        }
    }

    fn kinds(n: &Notices) -> Vec<(u64, Kind)> {
        n.list.iter().map(|n| (n.id, n.kind)).collect()
    }

    #[test]
    fn news_once_per_tree_and_target() {
        let mut n = Notices::new();
        let external: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:1100".parse().unwrap();
        for root in [100, 100, 200] {
            n.observe(&ev(root, 0, Payload::Connect { addr: external }), "claude");
        }
        n.observe(&ev(100, 0, Payload::Connect { addr: local }), "claude");
        n.observe(&ev(100, 0, open("/tmp/x", Policy::Allowed)), "claude");
        n.observe(
            &ev(300, 0, Payload::ResolverConnect { addr: external }),
            "claude",
        );
        assert_eq!(kinds(&n), [(1, Kind::Host), (2, Kind::Host)]);
        assert_eq!(n.view(1, &|_| EnrichedAddr::default()).notices.len(), 1);
    }

    #[test]
    fn probing_for_a_secret_is_news_and_names_the_file() {
        let mut n = Notices::new();
        n.observe(
            &ev(100, -2, open("/home/u/.aws/credentials", Policy::Allowed)),
            "claude",
        );
        n.observe(
            &ev(100, 3, open("/home/u/.ssh/id_ed25519", Policy::Audited)),
            "claude",
        );
        n.observe(
            &ev(
                100,
                0,
                Payload::Ptrace {
                    request: 16,
                    target_pid: 7,
                },
            ),
            "claude",
        );
        assert_eq!(
            kinds(&n),
            [(1, Kind::Sensitive), (2, Kind::Rule), (3, Kind::Ptrace)]
        );
        let view = n.view(0, &|_| EnrichedAddr::default());
        assert_eq!(view.notices[0].path, "/home/u/.aws/credentials");
        assert!(view.notices[0].summary.ends_with("ENOENT"));
    }
}
