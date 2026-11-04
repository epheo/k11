//! What a person should hear about as it happens: an agent reaching a host,
//! opening a port to other hosts, touching a sensitive file, matching a deny
//! rule, tracing a process. Once per agent tree and target, so a notice is
//! news, not a log. The dashboard lists them and can raise a desktop
//! notification; one that names a file can become a deny rule in one answer,
//! and any can be quieted: what is expected stops being news.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
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

/// What the notice is about.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Subject {
    Path(String),
    /// With the name the tree looked up for it, if it did.
    Peer {
        addr: SocketAddr,
        name: Option<String>,
    },
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

impl Notice {
    /// What makes it news within its tree, and what a quiet rule names: a
    /// host by the name looked up (a CDN answers from many addresses), else
    /// by address; a port by address and port; a file by path. None for
    /// what is never quieted.
    fn key(kind: Kind, subject: &Subject) -> Option<String> {
        match (kind, subject) {
            (_, Subject::Path(p)) => Some(p.clone()),
            (Kind::Host, Subject::Peer { name: Some(n), .. }) => Some(n.clone()),
            (Kind::Host, Subject::Peer { addr, .. }) => Some(addr.ip().to_string()),
            (_, Subject::Peer { addr, .. }) => Some(addr.to_string()),
            (_, Subject::Pid(_)) => None,
        }
    }
}

pub struct Notices {
    list: VecDeque<Notice>,
    seen: HashSet<(u32, Kind, String)>,
    /// Names each tree looked up, by the address it got.
    names: HashMap<(u32, IpAddr), String>,
    /// Keys that make no notice, as the person chose.
    quiet: BTreeSet<String>,
    last_id: u64,
    /// When this daemon started, in ms: ids start over with it.
    epoch: u64,
}

impl Notices {
    pub fn new() -> Self {
        Self {
            list: VecDeque::new(),
            seen: HashSet::new(),
            names: HashMap::new(),
            quiet: BTreeSet::new(),
            last_id: 0,
            epoch: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
        }
    }

    /// `agent` names the event's tree.
    pub fn observe(&mut self, event: &Event, agent: &str) {
        let root = event.meta.root_pid;
        if let Payload::Resolve { name, addrs } = &event.payload {
            if self.names.len() >= 4 * MAX_NOTICES {
                self.names.clear();
            }
            for ip in addrs {
                self.names.insert((root, ip.to_canonical()), name.clone());
            }
            return;
        }
        let Some((kind, mut subject)) = notable(event) else {
            return;
        };
        if let Subject::Peer { addr, name } = &mut subject {
            *name = self.names.get(&(root, addr.ip().to_canonical())).cloned();
        }
        let key = Notice::key(kind, &subject);
        if key.as_ref().is_some_and(|k| self.quiet.contains(k)) {
            return;
        }
        if self.seen.len() >= 4 * MAX_NOTICES {
            self.seen.clear();
        }
        let news = key.unwrap_or_else(|| format!("{subject:?}"));
        if !self.seen.insert((root, kind, news)) {
            return;
        }
        if self.list.len() >= MAX_NOTICES {
            self.list.pop_front();
        }
        self.last_id += 1;
        self.list.push_back(Notice {
            id: self.last_id,
            timestamp_ms: event.meta.timestamp_ns / 1_000_000,
            root_pid: root,
            agent: agent.to_string(),
            pid: event.meta.pid,
            comm: Arc::clone(&event.meta.comm),
            kind,
            subject,
            summary: event.describe(),
        });
    }

    pub fn quiet(&self) -> Vec<String> {
        self.quiet.iter().cloned().collect()
    }

    /// Replace what makes no notice; the notices it covers go too.
    pub fn set_quiet(&mut self, quiet: impl IntoIterator<Item = String>) {
        self.quiet = quiet.into_iter().filter(|k| !k.is_empty()).collect();
        let quiet = &self.quiet;
        self.list
            .retain(|n| !Notice::key(n.kind, &n.subject).is_some_and(|k| quiet.contains(&k)));
    }

    /// Notices after `id`, oldest first.
    pub fn view(
        &self,
        after: u64,
        enrich: &dyn Fn(IpAddr) -> EnrichedAddr,
    ) -> proto::GetNoticesResponse {
        proto::GetNoticesResponse {
            epoch: self.epoch,
            notices: self
                .list
                .iter()
                .filter(|n| n.id > after)
                .map(|n| n.view(enrich))
                .collect(),
            quiet: self.quiet(),
            writable: false,
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
            Some((
                kind,
                Subject::Peer {
                    addr: *addr,
                    name: None,
                },
            ))
        }
        Payload::Ptrace { target_pid, .. } => Some((Kind::Ptrace, Subject::Pid(*target_pid))),
        _ => event
            .paths()
            .find(|p| is_sensitive_path(p))
            .map(|p| (Kind::Sensitive, Subject::Path(p.to_string()))),
    }
}

impl Notice {
    fn view(&self, enrich: &dyn Fn(IpAddr) -> EnrichedAddr) -> proto::Notice {
        use proto::NoticeKind as K;
        let (path, peer, peer_name) = match &self.subject {
            Subject::Path(p) => (p.clone(), String::new(), String::new()),
            Subject::Peer { addr, name } => {
                let known = enrich(addr.ip());
                let name: Vec<String> = [name.clone().or(known.hostname), known.asn]
                    .into_iter()
                    .flatten()
                    .collect();
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
            quiet_key: Notice::key(self.kind, &self.subject).unwrap_or_default(),
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

    #[test]
    fn a_host_is_news_once_by_the_name_looked_up() {
        let mut n = Notices::new();
        let addrs: Vec<IpAddr> = vec![
            "203.0.113.10".parse().unwrap(),
            "203.0.113.11".parse().unwrap(),
        ];
        n.observe(
            &ev(
                100,
                0,
                Payload::Resolve {
                    name: "api.example.com".into(),
                    addrs: addrs.clone(),
                },
            ),
            "claude",
        );
        for ip in &addrs {
            n.observe(
                &ev(
                    100,
                    0,
                    Payload::Connect {
                        addr: SocketAddr::new(*ip, 443),
                    },
                ),
                "claude",
            );
        }
        let view = n.view(0, &|_| EnrichedAddr::default());
        assert_eq!(view.notices.len(), 1);
        assert_eq!(view.notices[0].quiet_key, "api.example.com");
        assert_eq!(view.notices[0].peer_name, "api.example.com");
    }

    #[test]
    fn quiet_is_no_longer_news() {
        let mut n = Notices::new();
        n.observe(
            &ev(100, 0, open("/home/u/.npmrc", Policy::Allowed)),
            "claude",
        );
        n.observe(
            &ev(100, 0, open("/home/u/.ssh/id_rsa", Policy::Allowed)),
            "claude",
        );
        n.set_quiet(["/home/u/.npmrc".to_string()]);
        assert_eq!(kinds(&n).len(), 1, "the quieted notice goes");
        n.observe(
            &ev(200, 0, open("/home/u/.npmrc", Policy::Allowed)),
            "codex",
        );
        assert_eq!(kinds(&n).len(), 1, "and makes none for another tree");
        let ptrace = ev(
            100,
            0,
            Payload::Ptrace {
                request: 16,
                target_pid: 7,
            },
        );
        n.observe(&ptrace, "claude");
        assert_eq!(
            n.view(0, &|_| EnrichedAddr::default()).notices[1].quiet_key,
            ""
        );
    }
}
