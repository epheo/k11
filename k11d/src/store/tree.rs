//! One agent tree: its process table and the aggregates kept as events arrive.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use k11_proto as proto;
use tracing::warn;

use crate::classify::{
    errno_name, failed, is_exposed, is_external, is_sensitive_path, opens_for_write,
};
use crate::cmdline::CommandLine;
use crate::container::Container;
use crate::enrich::EnrichedAddr;

use super::{Event, EventMeta, Payload, Policy};

/// Cap on unique keys per aggregate map (files, peers, unix sockets): a
/// runaway crawler must not OOM the daemon. Existing keys keep updating.
const MAX_AGGREGATE_KEYS: usize = 20_000;

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

/// Accumulator behind every aggregate. Errors are keyed by errno number and
/// comms are shared `Arc`s, so recording an access allocates nothing.
/// `updated` is the store version of the last change, for delta views.
struct Accumulator {
    count: u32,
    errors: BTreeMap<i32, u32>,
    comms: Vec<Arc<str>>,
    first_ns: u64,
    last_ns: u64,
    updated: u64,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self {
            count: 0,
            errors: BTreeMap::new(),
            comms: Vec::new(),
            first_ns: u64::MAX,
            last_ns: 0,
            updated: 0,
        }
    }
}

impl Accumulator {
    fn record(&mut self, meta: &EventMeta, version: u64) {
        self.count += 1;
        if failed(meta.ret) {
            *self.errors.entry(meta.ret).or_insert(0) += 1;
        }
        if !self.comms.contains(&meta.comm) {
            self.comms.push(Arc::clone(&meta.comm));
        }
        self.first_ns = self.first_ns.min(meta.timestamp_ns);
        self.last_ns = self.last_ns.max(meta.timestamp_ns);
        self.updated = version;
    }

    fn view(&self) -> Option<proto::Access> {
        Some(proto::Access {
            count: self.count,
            errors: self
                .errors
                .iter()
                .map(|(e, n)| (errno_name(*e).into_owned(), *n))
                .collect(),
            comms: self.comms.iter().map(|c| c.to_string()).collect(),
            first_seen_ms: self.first_ns / 1_000_000,
            last_seen_ms: self.last_ns / 1_000_000,
        })
    }
}

#[derive(Default)]
struct FileAgg {
    acc: Accumulator,
    modified: bool,
    deleted: bool,
    renamed: bool,
    perm_changed: bool,
    owner_changed: bool,
    is_symlink: bool,
    denied: bool,
    audited: bool,
}

pub(super) struct ProcessEntry {
    comm: Arc<str>,
    /// Of its latest image.
    pub(super) cmd_line: Option<Arc<CommandLine>>,
    container: Option<Arc<Container>>,
    pub(super) parent_pid: Option<u32>,
    running: bool,
    file_count: u32,
    net_count: u32,
    unix_count: u32,
    exec_count: u32,
    first_seen_ms: u64,
    last_seen_ms: u64,
    updated: u64,
}

impl ProcessEntry {
    fn view(&self, pid: u32) -> proto::ProcessInfo {
        proto::ProcessInfo {
            pid,
            comm: self.comm.to_string(),
            cmd_line: self
                .cmd_line
                .as_ref()
                .map(|c| c.to_string())
                .unwrap_or_default(),
            parent_pid: self.parent_pid,
            running: self.running,
            file_count: self.file_count,
            net_count: self.net_count,
            unix_count: self.unix_count,
            exec_count: self.exec_count,
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            container: self.container.as_deref().map(Into::into),
        }
    }
}

/// Update or insert an aggregate. A hit costs one lookup and no allocation;
/// new keys are refused past the cap, with `capped` set so the caller can
/// log once.
fn upsert<K, Q, V>(map: &mut HashMap<K, V>, key: &Q, capped: &mut bool, update: impl FnOnce(&mut V))
where
    K: Borrow<Q> + Hash + Eq,
    Q: Hash + Eq + ToOwned<Owned = K> + ?Sized,
    V: Default,
{
    if let Some(v) = map.get_mut(key) {
        update(v);
    } else if map.len() >= MAX_AGGREGATE_KEYS {
        *capped = true;
    } else {
        let mut v = V::default();
        update(&mut v);
        map.insert(key.to_owned(), v);
    }
}

/// Everything known about one agent tree. The summary is the counters
/// themselves, kept current as events arrive.
pub(super) struct AgentTree {
    pub(super) summary: proto::AgentSummary,
    /// Store version of the last change.
    pub(super) version: u64,
    pub(super) events: VecDeque<Arc<Event>>,
    processes: HashMap<u32, ProcessEntry>,
    files: HashMap<String, FileAgg>,
    conns: HashMap<SocketAddr, Accumulator>,
    binds: HashMap<SocketAddr, Accumulator>,
    unix_sockets: HashMap<String, Accumulator>,
}

impl AgentTree {
    /// `live`: the root is a process on this machine now, not in a log.
    pub(super) fn new(root_pid: u32, comm: &str, live: bool) -> Self {
        Self {
            summary: proto::AgentSummary {
                root_pid,
                root_comm: comm.to_string(),
                // Read once: several agents of one name differ by project.
                root_cwd: live
                    .then(|| std::fs::read_link(format!("/proc/{root_pid}/cwd")).ok())
                    .flatten()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                ..Default::default()
            },
            version: 0,
            events: VecDeque::new(),
            processes: HashMap::new(),
            files: HashMap::new(),
            conns: HashMap::new(),
            binds: HashMap::new(),
            unix_sockets: HashMap::new(),
        }
    }

    /// The process entry for `pid`, created (and counted as running) on
    /// first sight.
    /// Threads name themselves ("Bun Pool 7", "HTTP Client"): an event is
    /// told under its process's name, which only exec changes.
    pub(super) fn named(&self, mut event: Arc<Event>) -> Arc<Event> {
        if matches!(event.payload, Payload::Execve { .. }) {
            return event;
        }
        if let Some(p) = self.processes.get(&event.meta.pid) {
            if p.comm != event.meta.comm {
                Arc::make_mut(&mut event).meta.comm = Arc::clone(&p.comm);
            }
        }
        event
    }

    pub(super) fn process(
        &mut self,
        pid: u32,
        comm: &Arc<str>,
        timestamp_ns: u64,
    ) -> &mut ProcessEntry {
        let summary = &mut self.summary;
        let entry = self.processes.entry(pid).or_insert_with(|| {
            summary.process_count += 1;
            summary.running_count += 1;
            ProcessEntry {
                comm: Arc::clone(comm),
                cmd_line: None,
                container: None,
                parent_pid: None,
                running: true,
                file_count: 0,
                net_count: 0,
                unix_count: 0,
                exec_count: 0,
                first_seen_ms: 0,
                last_seen_ms: 0,
                updated: 0,
            }
        });
        let ts_ms = timestamp_ns / 1_000_000;
        if entry.first_seen_ms == 0 {
            entry.first_seen_ms = ts_ms;
        }
        entry.last_seen_ms = entry.last_seen_ms.max(ts_ms);
        entry.updated = self.version;
        entry
    }

    fn file(&mut self, meta: &EventMeta, path: &str, mark: impl FnOnce(&mut FileAgg)) {
        let version = self.version;
        upsert(
            &mut self.files,
            path,
            &mut self.summary.aggregates_capped,
            |agg| {
                agg.acc.record(meta, version);
                mark(agg);
            },
        );
    }

    fn fs_modification(&mut self, meta: &EventMeta) {
        self.summary.file_count += 1;
        self.summary.fs_mod_count += 1;
        self.process(meta.pid, &meta.comm, meta.timestamp_ns)
            .file_count += 1;
    }

    pub(super) fn ingest(&mut self, event: Arc<Event>, version: u64, max_events: usize) {
        let meta = &event.meta;
        let ts = meta.timestamp_ns;
        self.version = version;
        let s = &mut self.summary;
        s.last_seen_ms = s.last_seen_ms.max(ts / 1_000_000);
        if s.first_seen_ms == 0 {
            s.first_seen_ms = ts / 1_000_000;
        }
        s.has_sensitive_files |= event.is_sensitive();
        let was_capped = s.aggregates_capped;
        // The latest event says where a process runs: a runtime moves its
        // container's first process in before the exec.
        if meta.pid == self.summary.root_pid {
            self.summary.container = meta.container.as_deref().map(Into::into);
        }
        self.process(meta.pid, &meta.comm, ts).container = meta.container.clone();

        match &event.payload {
            Payload::Fork { child_pid } => {
                self.process(meta.pid, &meta.comm, ts);
                // At fork comm and cgroup are the parent's; the child keeps
                // them until it execs or moves.
                let child = self.process(*child_pid, &meta.comm, ts);
                child.parent_pid = Some(meta.pid);
                child.container = meta.container.clone();
            }
            Payload::Execve { cmd_line, .. } => {
                self.summary.exec_count += 1;
                let ran = !failed(meta.ret);
                // A `k11 run` root read back from a log, where its label is
                // not: the session is named after what it ran.
                if ran && self.summary.root_comm == "k11" {
                    self.summary.root_comm = meta.comm.to_string();
                }
                let entry = self.process(meta.pid, &meta.comm, ts);
                if ran {
                    entry.comm = Arc::clone(&meta.comm);
                    entry.cmd_line = cmd_line.clone();
                }
                entry.exec_count += 1;
            }
            Payload::Open {
                filename,
                flags,
                policy,
            } => {
                let s = &mut self.summary;
                s.file_count += 1;
                match policy {
                    Policy::Denied => s.deny_count += 1,
                    Policy::Audited => s.audit_count += 1,
                    Policy::Allowed => {}
                }
                let writes = opens_for_write(*flags);
                s.has_sensitive_writes |= writes && is_sensitive_path(filename);
                self.process(meta.pid, &meta.comm, ts).file_count += 1;
                self.file(meta, filename, |agg| {
                    agg.modified |= writes;
                    agg.denied |= *policy == Policy::Denied;
                    agg.audited |= *policy == Policy::Audited;
                });
            }
            Payload::Connect { addr } => {
                self.summary.net_count += 1;
                self.summary.has_external_net |= is_external(addr.ip());
                self.process(meta.pid, &meta.comm, ts).net_count += 1;
                let version = self.version;
                upsert(
                    &mut self.conns,
                    addr,
                    &mut self.summary.aggregates_capped,
                    |acc| acc.record(meta, version),
                );
            }
            Payload::Bind { addr } => {
                self.summary.bind_count += 1;
                self.process(meta.pid, &meta.comm, ts).net_count += 1;
                let version = self.version;
                upsert(
                    &mut self.binds,
                    addr,
                    &mut self.summary.aggregates_capped,
                    |acc| acc.record(meta, version),
                );
            }
            Payload::Listen { .. } => {
                self.summary.has_listener |= meta.ret == 0;
                self.process(meta.pid, &meta.comm, ts);
            }
            Payload::UnixConnect { path } => {
                self.summary.unix_count += 1;
                self.process(meta.pid, &meta.comm, ts).unix_count += 1;
                let version = self.version;
                upsert(
                    &mut self.unix_sockets,
                    path.as_str(),
                    &mut self.summary.aggregates_capped,
                    |acc| acc.record(meta, version),
                );
            }
            Payload::Exit => {
                let entry = self.process(meta.pid, &meta.comm, ts);
                if std::mem::replace(&mut entry.running, false) {
                    self.summary.running_count -= 1;
                }
            }
            Payload::Unlink { filename, .. } => {
                self.fs_modification(meta);
                self.summary.has_sensitive_delete |= is_sensitive_path(filename);
                self.file(meta, filename, |agg| agg.deleted = true);
            }
            Payload::Rename { old_path, new_path } => {
                self.fs_modification(meta);
                self.file(meta, old_path, |agg| agg.renamed = true);
                self.file(meta, new_path, |agg| agg.renamed = true);
            }
            Payload::Chmod { filename, .. } => {
                self.fs_modification(meta);
                self.file(meta, filename, |agg| agg.perm_changed = true);
            }
            Payload::Chown { filename, .. } => {
                self.fs_modification(meta);
                self.file(meta, filename, |agg| agg.owner_changed = true);
            }
            Payload::Symlink { target, linkpath } => {
                self.fs_modification(meta);
                self.file(meta, target, |_| {});
                self.file(meta, linkpath, |agg| agg.is_symlink = true);
            }
            Payload::Ptrace { .. } => {
                self.summary.ptrace_count += 1;
                self.summary.has_ptrace = true;
                self.process(meta.pid, &meta.comm, ts);
            }
            Payload::Resolve { .. } | Payload::ResolverConnect { .. } => {
                self.process(meta.pid, &meta.comm, ts);
            }
        }

        if self.summary.aggregates_capped && !was_capped {
            warn!(
                root_pid = self.summary.root_pid,
                cap = MAX_AGGREGATE_KEYS,
                "aggregate cap reached: new paths and addresses no longer tracked in detail view"
            );
        }
        if self.events.len() >= max_events {
            self.drop_oldest();
        }
        self.events.push_back(event);
    }

    /// The summary with its risk assessment.
    pub(super) fn summary(&self) -> proto::AgentSummary {
        let s = &self.summary;
        let reasons = |checks: Vec<(bool, String)>| -> Vec<String> {
            checks
                .into_iter()
                .filter_map(|(on, reason)| on.then_some(reason))
                .collect()
        };
        let mut high = reasons(vec![
            (s.deny_count > 0, format!("{} denied", s.deny_count)),
            (s.has_sensitive_writes, "sensitive writes".into()),
            (s.has_sensitive_delete, "sensitive deletion".into()),
            (s.has_ptrace, "ptrace".into()),
        ]);
        let medium = reasons(vec![
            (s.audit_count > 0, format!("{} audited", s.audit_count)),
            (s.has_sensitive_files, "sensitive files".into()),
            (s.has_external_net, "external network".into()),
            (s.has_listener, "listening socket".into()),
        ]);
        let risk = match (high.is_empty(), medium.is_empty()) {
            (false, _) => "high",
            (true, false) => "medium",
            (true, true) => "low",
        };
        high.extend(medium);
        proto::AgentSummary {
            risk: risk.into(),
            risk_reasons: high,
            ..s.clone()
        }
    }

    pub(super) fn drop_oldest(&mut self) {
        if self.events.pop_front().is_some() {
            self.summary.events_dropped += 1;
        }
    }

    /// Processes and aggregates changed after store version `since`.
    pub(super) fn detail(
        &self,
        since: u64,
        enrich: &dyn Fn(IpAddr) -> EnrichedAddr,
    ) -> proto::AgentDetail {
        let files = self
            .files
            .iter()
            .filter(|(_, agg)| agg.acc.updated > since)
            .map(|(path, agg)| proto::FileAccess {
                path: path.clone(),
                access: agg.acc.view(),
                sensitive: is_sensitive_path(path),
                modified: agg.modified,
                deleted: agg.deleted,
                renamed: agg.renamed,
                perm_changed: agg.perm_changed,
                owner_changed: agg.owner_changed,
                is_symlink: agg.is_symlink,
                denied: agg.denied,
                audited: agg.audited,
            })
            .collect();
        let peers = |map: &HashMap<SocketAddr, Accumulator>,
                     external: fn(&SocketAddr) -> bool,
                     enrich: &dyn Fn(IpAddr) -> EnrichedAddr| {
            map.iter()
                .filter(|(_, acc)| acc.updated > since)
                .map(|(addr, acc)| {
                    let known = enrich(addr.ip());
                    proto::ConnectionAccess {
                        addr: addr.ip().to_string(),
                        port: addr.port() as u32,
                        access: acc.view(),
                        external: external(addr),
                        hostname: known.hostname,
                        country: known.country,
                        city: known.city,
                        asn: known.asn,
                    }
                })
                .collect()
        };
        proto::AgentDetail {
            summary: Some(self.summary()),
            processes: self
                .processes
                .iter()
                .filter(|(_, p)| p.updated > since)
                .map(|(&pid, p)| p.view(pid))
                .collect(),
            files,
            connections: peers(&self.conns, |a| is_external(a.ip()), enrich),
            binds: peers(&self.binds, |a| is_exposed(a.ip(), a.port()), &|_| {
                EnrichedAddr::default()
            }),
            unix_sockets: self
                .unix_sockets
                .iter()
                .filter(|(_, acc)| acc.updated > since)
                .map(|(path, acc)| proto::UnixSocketAccess {
                    path: path.clone(),
                    access: acc.view(),
                })
                .collect(),
        }
    }
}
