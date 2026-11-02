//! In-memory view of every agent tree: process table, per-path and per-peer
//! aggregates maintained as events arrive, and a bounded raw event ring for
//! the dashboard's log. The OCSF export is the durable record; this store
//! only has to answer the dashboard quickly.

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

use tracing::warn;

use crate::classify::{errno_name, is_external_addr, is_sensitive_path, status};
use crate::enrich::EnrichedAddr;

/// Cap on unique keys per aggregate map (files, peers, unix sockets): a
/// runaway crawler must not OOM the daemon. Existing keys keep updating.
const MAX_AGGREGATE_KEYS: usize = 20_000;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Fields shared by every event, mirroring the probe's `EventHeader`.
/// `root_pid` makes each event attributable to its agent tree on its own.
#[derive(Clone)]
pub struct EventMeta {
    /// Acting process (for fork: the parent).
    pub pid: u32,
    pub root_pid: u32,
    pub uid: u32,
    /// Interned by the decoder: one allocation per distinct name, not per event.
    pub comm: Arc<str>,
    /// Wall-clock epoch nanoseconds.
    pub timestamp_ns: u64,
}

/// What the deny rules said about an open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// No rule matched.
    Allowed,
    /// A rule matched in audit mode; the open went ahead.
    Audited,
    /// A rule matched while enforcing; the open failed with EPERM.
    Denied,
}

#[derive(Clone)]
pub struct Event {
    pub meta: EventMeta,
    pub payload: Payload,
}

#[derive(Clone)]
pub enum Payload {
    Execve {
        filename: String,
    },
    Openat {
        filename: String,
        flags: i32,
        ret: i32,
        policy: Policy,
    },
    Connect {
        addr: String,
        port: u16,
        ret: i32,
    },
    UnixConnect {
        path: String,
        ret: i32,
    },
    Fork {
        child_pid: u32,
    },
    Exit,
    Bind {
        addr: String,
        port: u16,
        ret: i32,
    },
    Listen {
        backlog: i32,
        ret: i32,
    },
    Unlink {
        filename: String,
        flags: i32,
        ret: i32,
    },
    Rename {
        old_path: String,
        new_path: String,
        ret: i32,
    },
    Chmod {
        filename: String,
        mode: u32,
        ret: i32,
    },
    Chown {
        filename: String,
        owner_uid: u32,
        owner_gid: u32,
        ret: i32,
    },
    Symlink {
        target: String,
        linkpath: String,
        ret: i32,
    },
    Ptrace {
        request: u32,
        target_pid: u32,
        ret: i32,
    },
}

impl Event {
    pub fn policy(&self) -> Policy {
        match self.payload {
            Payload::Openat { policy, .. } => policy,
            _ => Policy::Allowed,
        }
    }

    pub fn is_denied(&self) -> bool {
        self.policy() == Policy::Denied
    }

    pub fn ret(&self) -> Option<i32> {
        match &self.payload {
            Payload::Openat { ret, .. }
            | Payload::Connect { ret, .. }
            | Payload::UnixConnect { ret, .. }
            | Payload::Bind { ret, .. }
            | Payload::Listen { ret, .. }
            | Payload::Unlink { ret, .. }
            | Payload::Rename { ret, .. }
            | Payload::Chmod { ret, .. }
            | Payload::Chown { ret, .. }
            | Payload::Symlink { ret, .. }
            | Payload::Ptrace { ret, .. } => Some(*ret),
            Payload::Execve { .. } | Payload::Fork { .. } | Payload::Exit => None,
        }
    }

    /// The syscall failed on its own, not because k11 denied it.
    pub fn is_error(&self) -> bool {
        !self.is_denied() && self.ret().is_some_and(|r| r < 0)
    }

    /// Filesystem paths this event names.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        let (a, b): (Option<&str>, Option<&str>) = match &self.payload {
            Payload::Execve { filename }
            | Payload::Openat { filename, .. }
            | Payload::Unlink { filename, .. }
            | Payload::Chmod { filename, .. }
            | Payload::Chown { filename, .. } => (Some(filename), None),
            Payload::Rename {
                old_path, new_path, ..
            } => (Some(old_path), Some(new_path)),
            Payload::Symlink {
                target, linkpath, ..
            } => (Some(target), Some(linkpath)),
            _ => (None, None),
        };
        [a, b].into_iter().flatten()
    }

    pub fn is_sensitive(&self) -> bool {
        self.paths().any(is_sensitive_path)
    }

    /// Remote or local IP address for connect and bind.
    pub fn addr(&self) -> Option<&str> {
        match &self.payload {
            Payload::Connect { addr, .. } | Payload::Bind { addr, .. } => Some(addr),
            _ => None,
        }
    }

    pub fn is_external(&self) -> bool {
        self.addr().is_some_and(is_external_addr)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.meta;
        write!(f, "pid={} root={} comm={} ", m.pid, m.root_pid, m.comm)?;
        match &self.payload {
            Payload::Execve { filename } => write!(f, "execve filename={filename}"),
            Payload::Openat {
                filename,
                flags,
                ret,
                policy,
            } => {
                write!(
                    f,
                    "openat filename={filename} flags=0x{flags:x} ret={ret} [{}] policy={policy:?}",
                    status(*ret)
                )
            }
            Payload::Connect { addr, port, ret } => {
                write!(
                    f,
                    "connect addr={addr} port={port} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::UnixConnect { path, ret } => {
                write!(f, "unix_connect path={path} ret={ret} [{}]", status(*ret))
            }
            Payload::Fork { child_pid } => write!(f, "fork child_pid={child_pid}"),
            Payload::Exit => write!(f, "exit"),
            Payload::Bind { addr, port, ret } => {
                write!(
                    f,
                    "bind addr={addr} port={port} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::Listen { backlog, ret } => {
                write!(f, "listen backlog={backlog} ret={ret} [{}]", status(*ret))
            }
            Payload::Unlink { filename, ret, .. } => {
                write!(f, "unlink filename={filename} ret={ret} [{}]", status(*ret))
            }
            Payload::Rename {
                old_path,
                new_path,
                ret,
            } => {
                write!(
                    f,
                    "rename old={old_path} new={new_path} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::Chmod {
                filename,
                mode,
                ret,
            } => {
                write!(
                    f,
                    "chmod filename={filename} mode=0o{mode:o} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::Chown {
                filename,
                owner_uid,
                owner_gid,
                ret,
            } => {
                write!(
                    f,
                    "chown filename={filename} uid={owner_uid} gid={owner_gid} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::Symlink {
                target,
                linkpath,
                ret,
            } => {
                write!(
                    f,
                    "symlink target={target} linkpath={linkpath} ret={ret} [{}]",
                    status(*ret)
                )
            }
            Payload::Ptrace {
                request,
                target_pid,
                ret,
            } => {
                write!(
                    f,
                    "ptrace request={request} target={target_pid} ret={ret} [{}]",
                    status(*ret)
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// API views
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AgentSummary {
    pub root_pid: u32,
    pub root_comm: String,
    pub process_count: usize,
    pub running_count: usize,
    pub exited_count: usize,
    pub file_count: usize,
    pub net_count: usize,
    pub unix_count: usize,
    pub exec_count: usize,
    pub deny_count: usize,
    pub audit_count: usize,
    pub fs_mod_count: usize,
    pub bind_count: usize,
    pub ptrace_count: usize,
    pub has_sensitive_files: bool,
    pub has_sensitive_writes: bool,
    pub has_sensitive_delete: bool,
    pub has_external_net: bool,
    pub has_listener: bool,
    pub has_ptrace: bool,
    pub events_dropped: u64,
}

#[derive(Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub parent_pid: Option<u32>,
    pub running: bool,
    pub file_count: usize,
    pub net_count: usize,
    pub unix_count: usize,
    pub exec_count: usize,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// What every aggregate (file, peer, unix socket) records about its accesses.
#[derive(Clone, Default)]
pub struct Access {
    pub count: usize,
    /// Per-errno failure counts, e.g. {"ENOENT": 3, "EACCES": 1}.
    pub errors: BTreeMap<String, usize>,
    pub comms: Vec<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct FileAccess {
    pub path: String,
    pub access: Access,
    pub sensitive: bool,
    pub modified: bool,
    pub deleted: bool,
    pub renamed: bool,
    pub perm_changed: bool,
    pub owner_changed: bool,
    pub is_symlink: bool,
    /// An open of this path was refused by a deny rule.
    pub denied: bool,
    /// An open of this path matched a deny rule in audit mode.
    pub audited: bool,
}

#[derive(Clone)]
pub struct ConnectionAccess {
    pub addr: String,
    pub port: u16,
    pub access: Access,
    pub external: bool,
    pub enrich: EnrichedAddr,
}

#[derive(Clone)]
pub struct UnixSocketAccess {
    pub path: String,
    pub access: Access,
}

#[derive(Clone)]
pub struct AgentDetail {
    pub root_pid: u32,
    pub root_comm: String,
    /// Bumped on every ingested event, so a client can skip unchanged detail.
    pub version: u64,
    pub processes: Vec<ProcessInfo>,
    pub files: Vec<FileAccess>,
    pub connections: Vec<ConnectionAccess>,
    pub binds: Vec<ConnectionAccess>,
    pub unix_sockets: Vec<UnixSocketAccess>,
    pub summary: AgentSummary,
}

// ---------------------------------------------------------------------------
// Incremental state
// ---------------------------------------------------------------------------

struct ProcessEntry {
    comm: Arc<str>,
    parent_pid: Option<u32>,
    running: bool,
    file_count: usize,
    net_count: usize,
    unix_count: usize,
    exec_count: usize,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

impl ProcessEntry {
    fn new(comm: Arc<str>, parent_pid: Option<u32>) -> Self {
        Self {
            comm,
            parent_pid,
            running: true,
            file_count: 0,
            net_count: 0,
            unix_count: 0,
            exec_count: 0,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    fn touch(&mut self, timestamp_ns: u64) {
        let ts_ms = timestamp_ns / 1_000_000;
        if self.first_seen_ms == 0 {
            self.first_seen_ms = ts_ms;
        }
        self.last_seen_ms = self.last_seen_ms.max(ts_ms);
    }
}

/// Accumulator behind every aggregate. Errors are keyed by errno number and
/// comms are shared `Arc`s, so recording an access allocates nothing.
struct Accumulator {
    count: usize,
    errors: BTreeMap<i32, usize>,
    comms: Vec<Arc<str>>,
    first_ns: u64,
    last_ns: u64,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self {
            count: 0,
            errors: BTreeMap::new(),
            comms: Vec::new(),
            first_ns: u64::MAX,
            last_ns: 0,
        }
    }
}

impl Accumulator {
    fn record(&mut self, comm: &Arc<str>, ret: i32, timestamp_ns: u64) {
        self.count += 1;
        if ret < 0 {
            *self.errors.entry(ret).or_insert(0) += 1;
        }
        if !self.comms.iter().any(|c| c == comm) {
            self.comms.push(Arc::clone(comm));
        }
        self.first_ns = self.first_ns.min(timestamp_ns);
        self.last_ns = self.last_ns.max(timestamp_ns);
    }

    fn view(&self) -> Access {
        Access {
            count: self.count,
            errors: self
                .errors
                .iter()
                .map(|(e, n)| (errno_name(*e).into_owned(), *n))
                .collect(),
            comms: self.comms.iter().map(|c| c.to_string()).collect(),
            first_seen_ms: if self.count == 0 {
                0
            } else {
                self.first_ns / 1_000_000
            },
            last_seen_ms: self.last_ns / 1_000_000,
        }
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

/// Update or insert an aggregate. A hit costs one lookup and no allocation;
/// new keys are refused past the cap, with `overflowed` set so the caller
/// can log once.
fn upsert<'k, K, Q, V>(
    map: &mut HashMap<K, V>,
    key: &'k Q,
    overflowed: &mut bool,
    update: impl FnOnce(&mut V),
) where
    K: Borrow<Q> + Hash + Eq + From<&'k Q>,
    Q: Hash + Eq + ?Sized,
    V: Default,
{
    if let Some(v) = map.get_mut(key) {
        update(v);
        return;
    }
    if map.len() >= MAX_AGGREGATE_KEYS {
        *overflowed = true;
        return;
    }
    let mut v = V::default();
    update(&mut v);
    map.insert(K::from(key), v);
}

/// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
const WRITE_FLAGS: i32 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400;

/// Peers keyed by address, then port: connects to one host on many ports
/// share the address string.
type PeerMap = HashMap<String, BTreeMap<u16, Accumulator>>;

pub struct AgentTree {
    pub root_pid: u32,
    pub root_comm: Arc<str>,
    events: VecDeque<Arc<Event>>,
    processes: HashMap<u32, ProcessEntry>,
    running_count: usize,
    files: HashMap<String, FileAgg>,
    conns: PeerMap,
    binds: PeerMap,
    unix_sockets: HashMap<String, Accumulator>,
    aggregates_overflowed: bool,
    events_dropped: u64,
    version: u64,
    last_event_ms: u64,
    file_count: usize,
    net_count: usize,
    unix_count: usize,
    exec_count: usize,
    deny_count: usize,
    audit_count: usize,
    fs_mod_count: usize,
    bind_count: usize,
    ptrace_count: usize,
    has_sensitive_files: bool,
    has_sensitive_writes: bool,
    has_sensitive_delete: bool,
    has_external_net: bool,
    has_listener: bool,
    has_ptrace: bool,
}

impl AgentTree {
    fn new(root_pid: u32, comm: Arc<str>) -> Self {
        let mut processes = HashMap::new();
        processes.insert(root_pid, ProcessEntry::new(Arc::clone(&comm), None));
        Self {
            root_pid,
            root_comm: comm,
            events: VecDeque::new(),
            processes,
            running_count: 1,
            files: HashMap::new(),
            conns: HashMap::new(),
            binds: HashMap::new(),
            unix_sockets: HashMap::new(),
            aggregates_overflowed: false,
            events_dropped: 0,
            version: 0,
            last_event_ms: 0,
            file_count: 0,
            net_count: 0,
            unix_count: 0,
            exec_count: 0,
            deny_count: 0,
            audit_count: 0,
            fs_mod_count: 0,
            bind_count: 0,
            ptrace_count: 0,
            has_sensitive_files: false,
            has_sensitive_writes: false,
            has_sensitive_delete: false,
            has_external_net: false,
            has_listener: false,
            has_ptrace: false,
        }
    }

    fn insert_process(
        &mut self,
        pid: u32,
        comm: Arc<str>,
        parent_pid: Option<u32>,
    ) -> &mut ProcessEntry {
        self.running_count += 1;
        self.processes
            .entry(pid)
            .or_insert_with(|| ProcessEntry::new(comm, parent_pid))
    }

    fn process(&mut self, pid: u32, comm: &Arc<str>) -> &mut ProcessEntry {
        if !self.processes.contains_key(&pid) {
            return self.insert_process(pid, Arc::clone(comm), None);
        }
        self.processes.get_mut(&pid).expect("checked above")
    }

    fn file(&mut self, path: &str, update: impl FnOnce(&mut FileAgg)) {
        upsert(
            &mut self.files,
            path,
            &mut self.aggregates_overflowed,
            update,
        );
    }

    fn touch_file(
        &mut self,
        meta: &EventMeta,
        path: &str,
        ret: i32,
        mark: impl FnOnce(&mut FileAgg),
    ) {
        self.file(path, |agg| {
            agg.acc.record(&meta.comm, ret, meta.timestamp_ns);
            mark(agg);
        });
    }

    fn fs_modification(&mut self, meta: &EventMeta) {
        self.file_count += 1;
        self.fs_mod_count += 1;
        let entry = self.process(meta.pid, &meta.comm);
        entry.file_count += 1;
        entry.touch(meta.timestamp_ns);
    }

    fn ingest(&mut self, event: Arc<Event>, max_events: usize) {
        let meta = &event.meta;
        let ts = meta.timestamp_ns;
        self.version += 1;
        self.last_event_ms = self.last_event_ms.max(ts / 1_000_000);
        let was_overflowed = self.aggregates_overflowed;
        if event.is_sensitive() {
            self.has_sensitive_files = true;
        }

        match &event.payload {
            Payload::Fork { child_pid } => {
                // In sched_process_fork comm is the parent's; the child
                // inherits it until its first exec.
                self.process(meta.pid, &meta.comm).touch(ts);
                let child = match self.processes.contains_key(child_pid) {
                    true => self.processes.get_mut(child_pid).expect("checked above"),
                    false => {
                        self.insert_process(*child_pid, Arc::clone(&meta.comm), Some(meta.pid))
                    }
                };
                child.parent_pid = Some(meta.pid);
                child.touch(ts);
            }
            Payload::Execve { .. } => {
                self.exec_count += 1;
                let entry = self.process(meta.pid, &meta.comm);
                entry.comm = Arc::clone(&meta.comm);
                entry.exec_count += 1;
                entry.touch(ts);
            }
            Payload::Openat {
                filename,
                flags,
                ret,
                policy,
            } => {
                self.file_count += 1;
                match policy {
                    Policy::Denied => self.deny_count += 1,
                    Policy::Audited => self.audit_count += 1,
                    Policy::Allowed => {}
                }
                let entry = self.process(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                let writes = (flags & WRITE_FLAGS) != 0;
                if writes && is_sensitive_path(filename) {
                    self.has_sensitive_writes = true;
                }
                self.touch_file(meta, filename, *ret, |agg| {
                    agg.modified |= writes;
                    agg.denied |= *policy == Policy::Denied;
                    agg.audited |= *policy == Policy::Audited;
                });
            }
            Payload::Connect { addr, port, ret } => {
                self.net_count += 1;
                let entry = self.process(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
                if is_external_addr(addr) {
                    self.has_external_net = true;
                }
                upsert(
                    &mut self.conns,
                    addr.as_str(),
                    &mut self.aggregates_overflowed,
                    |ports| {
                        ports.entry(*port).or_default().record(&meta.comm, *ret, ts);
                    },
                );
            }
            Payload::UnixConnect { path, ret } => {
                self.unix_count += 1;
                let entry = self.process(meta.pid, &meta.comm);
                entry.unix_count += 1;
                entry.touch(ts);
                upsert(
                    &mut self.unix_sockets,
                    path.as_str(),
                    &mut self.aggregates_overflowed,
                    |acc| {
                        acc.record(&meta.comm, *ret, ts);
                    },
                );
            }
            Payload::Exit => {
                let entry = self.process(meta.pid, &meta.comm);
                let was_running = std::mem::replace(&mut entry.running, false);
                entry.touch(ts);
                if was_running {
                    self.running_count -= 1;
                }
            }
            Payload::Bind { addr, port, ret } => {
                self.bind_count += 1;
                self.net_count += 1;
                let entry = self.process(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
                upsert(
                    &mut self.binds,
                    addr.as_str(),
                    &mut self.aggregates_overflowed,
                    |ports| {
                        ports.entry(*port).or_default().record(&meta.comm, *ret, ts);
                    },
                );
            }
            Payload::Listen { ret, .. } => {
                if *ret == 0 {
                    self.has_listener = true;
                }
                let entry = self.process(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
            }
            Payload::Unlink { filename, ret, .. } => {
                self.fs_modification(meta);
                if is_sensitive_path(filename) {
                    self.has_sensitive_delete = true;
                }
                self.touch_file(meta, filename, *ret, |agg| agg.deleted = true);
            }
            Payload::Rename {
                old_path,
                new_path,
                ret,
            } => {
                self.fs_modification(meta);
                self.touch_file(meta, old_path, *ret, |agg| agg.renamed = true);
                self.touch_file(meta, new_path, *ret, |agg| agg.renamed = true);
            }
            Payload::Chmod { filename, ret, .. } => {
                self.fs_modification(meta);
                self.touch_file(meta, filename, *ret, |agg| agg.perm_changed = true);
            }
            Payload::Chown { filename, ret, .. } => {
                self.fs_modification(meta);
                self.touch_file(meta, filename, *ret, |agg| agg.owner_changed = true);
            }
            Payload::Symlink {
                target,
                linkpath,
                ret,
            } => {
                self.fs_modification(meta);
                self.touch_file(meta, target, *ret, |_| {});
                self.touch_file(meta, linkpath, *ret, |agg| agg.is_symlink = true);
            }
            Payload::Ptrace { .. } => {
                self.ptrace_count += 1;
                self.has_ptrace = true;
                self.process(meta.pid, &meta.comm).touch(ts);
            }
        }

        if self.aggregates_overflowed && !was_overflowed {
            warn!(
                root_pid = self.root_pid,
                cap = MAX_AGGREGATE_KEYS,
                "aggregate cap reached: new paths and addresses no longer tracked in detail view"
            );
        }

        if self.events.len() >= max_events {
            self.drop_oldest();
        }
        self.events.push_back(event);
    }

    fn drop_oldest(&mut self) {
        if self.events.pop_front().is_some() {
            self.events_dropped += 1;
        }
    }

    fn summary(&self) -> AgentSummary {
        AgentSummary {
            root_pid: self.root_pid,
            root_comm: self.root_comm.to_string(),
            process_count: self.processes.len(),
            running_count: self.running_count,
            exited_count: self.processes.len() - self.running_count,
            file_count: self.file_count,
            net_count: self.net_count,
            unix_count: self.unix_count,
            exec_count: self.exec_count,
            deny_count: self.deny_count,
            audit_count: self.audit_count,
            fs_mod_count: self.fs_mod_count,
            bind_count: self.bind_count,
            ptrace_count: self.ptrace_count,
            has_sensitive_files: self.has_sensitive_files,
            has_sensitive_writes: self.has_sensitive_writes,
            has_sensitive_delete: self.has_sensitive_delete,
            has_external_net: self.has_external_net,
            has_listener: self.has_listener,
            has_ptrace: self.has_ptrace,
            events_dropped: self.events_dropped,
        }
    }

    fn process_list(&self) -> Vec<ProcessInfo> {
        let mut processes: Vec<ProcessInfo> = self
            .processes
            .iter()
            .map(|(&pid, entry)| ProcessInfo {
                pid,
                comm: entry.comm.to_string(),
                parent_pid: entry.parent_pid,
                running: entry.running,
                file_count: entry.file_count,
                net_count: entry.net_count,
                unix_count: entry.unix_count,
                exec_count: entry.exec_count,
                first_seen_ms: entry.first_seen_ms,
                last_seen_ms: entry.last_seen_ms,
            })
            .collect();
        processes.sort_by_key(|p| p.pid);
        processes
    }

    fn running(&self) -> bool {
        self.running_count > 0
    }

    fn detail(&self) -> AgentDetail {
        let mut files: Vec<FileAccess> = self
            .files
            .iter()
            .map(|(path, agg)| FileAccess {
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
        files.sort_by(|a, b| {
            b.denied
                .cmp(&a.denied)
                .then(b.deleted.cmp(&a.deleted))
                .then(b.sensitive.cmp(&a.sensitive))
                .then(b.modified.cmp(&a.modified))
                .then(b.access.count.cmp(&a.access.count))
                .then(a.path.cmp(&b.path))
        });

        let mut unix_sockets: Vec<UnixSocketAccess> = self
            .unix_sockets
            .iter()
            .map(|(path, acc)| UnixSocketAccess {
                path: path.clone(),
                access: acc.view(),
            })
            .collect();
        unix_sockets.sort_by(|a, b| {
            b.access
                .count
                .cmp(&a.access.count)
                .then(a.path.cmp(&b.path))
        });

        AgentDetail {
            root_pid: self.root_pid,
            root_comm: self.root_comm.to_string(),
            version: self.version,
            processes: self.process_list(),
            files,
            connections: connection_list(&self.conns),
            binds: connection_list(&self.binds),
            unix_sockets,
            summary: self.summary(),
        }
    }
}

fn connection_list(peers: &PeerMap) -> Vec<ConnectionAccess> {
    let mut out: Vec<ConnectionAccess> = peers
        .iter()
        .flat_map(|(addr, ports)| {
            ports.iter().map(move |(port, acc)| ConnectionAccess {
                addr: addr.clone(),
                port: *port,
                access: acc.view(),
                external: is_external_addr(addr),
                enrich: EnrichedAddr::default(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.external
            .cmp(&a.external)
            .then(b.access.count.cmp(&a.access.count))
            .then(a.addr.cmp(&b.addr))
            .then(a.port.cmp(&b.port))
    });
    out
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct EventStore {
    agents: HashMap<u32, AgentTree>,
    max_events_per_agent: usize,
    /// Budget across all trees; when exceeded the largest tree gives way.
    max_total_events: usize,
    total_events: usize,
}

impl EventStore {
    pub fn new(max_events_per_agent: usize, max_total_events: usize) -> Self {
        Self {
            agents: HashMap::new(),
            max_events_per_agent,
            max_total_events,
            total_events: 0,
        }
    }

    /// Pre-populate a process entry from the /proc scan at startup, so
    /// processes that existed before k11 started have correct parent linkage.
    pub fn seed_process(&mut self, root_pid: u32, pid: u32, parent_pid: Option<u32>, comm: &str) {
        let comm: Arc<str> = Arc::from(comm);
        let agent = self
            .agents
            .entry(root_pid)
            .or_insert_with(|| AgentTree::new(root_pid, Arc::clone(&comm)));
        if !agent.processes.contains_key(&pid) {
            agent.insert_process(pid, comm, parent_pid);
        }
    }

    pub fn push(&mut self, event: Arc<Event>) {
        let root_pid = event.meta.root_pid;
        let is_new = !self.agents.contains_key(&root_pid);
        let agent = self
            .agents
            .entry(root_pid)
            .or_insert_with(|| AgentTree::new(root_pid, Arc::clone(&event.meta.comm)));
        // New trees legitimately start with exec (comm discovery) or fork
        // (lineage); anything else means the root was never seen.
        if is_new && !matches!(event.payload, Payload::Execve { .. } | Payload::Fork { .. }) {
            warn!(root_pid, comm = %event.meta.comm, "agent tree created from non-exec event (possible orphan)");
        }
        let before = agent.events.len();
        agent.ingest(event, self.max_events_per_agent);
        self.total_events += agent.events.len() - before;

        if self.total_events > self.max_total_events {
            if let Some(largest) = self.agents.values_mut().max_by_key(|a| a.events.len()) {
                largest.drop_oldest();
                self.total_events -= 1;
            }
        }
    }

    /// Drop trees whose processes have all exited and whose last event is
    /// older than `ttl_ms`. Returns how many trees were evicted.
    pub fn evict_exited(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.agents.len();
        let mut freed = 0;
        self.agents.retain(|_, agent| {
            let keep = agent.running() || now_ms.saturating_sub(agent.last_event_ms) < ttl_ms;
            if !keep {
                freed += agent.events.len();
            }
            keep
        });
        self.total_events -= freed;
        before - self.agents.len()
    }

    pub fn agents_summary(&self) -> Vec<AgentSummary> {
        self.agents.values().map(|a| a.summary()).collect()
    }

    pub fn agent_events(&self, root_pid: u32) -> Option<&VecDeque<Arc<Event>>> {
        self.agents.get(&root_pid).map(|a| &a.events)
    }

    pub fn agent_version(&self, root_pid: u32) -> Option<u64> {
        self.agents.get(&root_pid).map(|a| a.version)
    }

    pub fn agent_detail(&self, root_pid: u32) -> Option<AgentDetail> {
        self.agents.get(&root_pid).map(|a| a.detail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u32 = 100;
    const TS: u64 = 1_000_000_000; // 1 second in ns

    fn ev(pid: u32, root_pid: u32, comm: &str, ts: u64, payload: Payload) -> Arc<Event> {
        Arc::new(Event {
            meta: EventMeta {
                pid,
                root_pid,
                uid: 1000,
                comm: comm.into(),
                timestamp_ns: ts,
            },
            payload,
        })
    }

    fn root_ev(ts: u64, payload: Payload) -> Arc<Event> {
        ev(ROOT, ROOT, "claude", ts, payload)
    }

    fn open(filename: &str, flags: i32, ret: i32) -> Payload {
        Payload::Openat {
            filename: filename.into(),
            flags,
            ret,
            policy: Policy::Allowed,
        }
    }

    fn new_store() -> EventStore {
        EventStore::new(10_000, 100_000)
    }

    fn new_store_with_root() -> EventStore {
        let mut store = new_store();
        store.push(root_ev(
            TS,
            Payload::Execve {
                filename: "/usr/bin/claude".into(),
            },
        ));
        store
    }

    #[test]
    fn sensitive_file_write_detection() {
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, open("/home/user/.ssh/id_rsa", 0x1, 3)));
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(summary.has_sensitive_writes);

        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, open("/home/user/.ssh/id_rsa", 0x0, 3)));
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);

        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, open("/tmp/scratch.txt", 0x1, 3)));
        let summary = &store.agents_summary()[0];
        assert!(!summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);
    }

    #[test]
    fn policy_outcomes_are_counted_separately() {
        let mut store = new_store_with_root();
        store.push(root_ev(
            TS + 1,
            Payload::Openat {
                filename: "/home/u/.ssh/id_rsa".into(),
                flags: 0,
                ret: -1,
                policy: Policy::Denied,
            },
        ));
        store.push(root_ev(
            TS + 2,
            Payload::Openat {
                filename: "/home/u/.gnupg/x".into(),
                flags: 0,
                ret: 3,
                policy: Policy::Audited,
            },
        ));
        let summary = &store.agents_summary()[0];
        assert_eq!(summary.deny_count, 1);
        assert_eq!(summary.audit_count, 1);
        let detail = store.agent_detail(ROOT).unwrap();
        let denied = detail
            .files
            .iter()
            .find(|f| f.path.ends_with("id_rsa"))
            .unwrap();
        assert!(denied.denied && !denied.audited);
        let audited = detail
            .files
            .iter()
            .find(|f| f.path.ends_with("/x"))
            .unwrap();
        assert!(audited.audited && !audited.denied);
    }

    #[test]
    fn external_network_detection() {
        let mut store = new_store_with_root();
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 1,
            Payload::Connect {
                addr: "8.8.8.8".into(),
                port: 443,
                ret: 0,
            },
        ));
        assert!(store.agents_summary()[0].has_external_net);

        let mut store = new_store_with_root();
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 1,
            Payload::Connect {
                addr: "127.0.0.1".into(),
                port: 8080,
                ret: 0,
            },
        ));
        assert!(!store.agents_summary()[0].has_external_net);

        let mut store = new_store_with_root();
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 1,
            Payload::Connect {
                addr: "192.168.1.10".into(),
                port: 8080,
                ret: 0,
            },
        ));
        assert!(!store.agents_summary()[0].has_external_net);
    }

    #[test]
    fn process_tree_lifecycle() {
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, Payload::Fork { child_pid: 200 }));

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail
            .processes
            .iter()
            .find(|p| p.pid == 200)
            .expect("child should exist");
        assert_eq!(child.parent_pid, Some(ROOT));
        assert!(child.running);
        assert_eq!(child.comm, "claude");
        assert_eq!(detail.summary.running_count, 2);

        store.push(ev(
            200,
            ROOT,
            "curl",
            TS + 2,
            Payload::Execve {
                filename: "/usr/bin/curl".into(),
            },
        ));
        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert_eq!(child.comm, "curl");
        assert_eq!(child.exec_count, 1);

        store.push(ev(200, ROOT, "curl", TS + 3, Payload::Exit));
        // A second exit for the same pid must not underflow the running count.
        store.push(ev(200, ROOT, "curl", TS + 4, Payload::Exit));
        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert!(!child.running);
        assert_eq!(detail.summary.running_count, 1);
        assert_eq!(detail.summary.exited_count, 1);
        assert_eq!(detail.summary.process_count, 2);
    }

    #[test]
    fn multiple_agents_isolated() {
        let mut store = new_store();
        let (root_a, root_b) = (100, 200);
        store.push(ev(
            root_a,
            root_a,
            "agent_a",
            TS,
            Payload::Execve {
                filename: "/bin/a".into(),
            },
        ));
        store.push(ev(
            root_b,
            root_b,
            "agent_b",
            TS,
            Payload::Execve {
                filename: "/bin/b".into(),
            },
        ));
        store.push(ev(
            root_a,
            root_a,
            "agent_a",
            TS + 1,
            open("/tmp/a.txt", 0, 3),
        ));

        let summaries = store.agents_summary();
        let a = summaries.iter().find(|s| s.root_pid == root_a).unwrap();
        let b = summaries.iter().find(|s| s.root_pid == root_b).unwrap();
        assert_eq!(a.file_count, 1);
        assert_eq!(b.file_count, 0);
        assert_eq!(a.root_comm, "agent_a");
        assert_eq!(b.root_comm, "agent_b");
    }

    #[test]
    fn detail_aggregates_repeated_accesses() {
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, open("/etc/config", 0, 3)));
        store.push(root_ev(TS + 2, open("/etc/config", 0, 4)));
        store.push(ev(ROOT, ROOT, "cat", TS + 3, open("/etc/config", 0, -2)));

        let detail = store.agent_detail(ROOT).unwrap();
        let file = detail
            .files
            .iter()
            .find(|f| f.path == "/etc/config")
            .expect("aggregated");
        assert_eq!(file.access.count, 3);
        assert_eq!(file.access.errors.get("ENOENT"), Some(&1));
        assert!(file.access.comms.contains(&"claude".to_string()));
        assert!(file.access.comms.contains(&"cat".to_string()));
        assert_eq!(file.access.first_seen_ms, (TS + 1) / 1_000_000);
        assert_eq!(file.access.last_seen_ms, (TS + 3) / 1_000_000);
    }

    #[test]
    fn peers_group_ports_under_one_address() {
        let mut store = new_store_with_root();
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 1,
            Payload::Connect {
                addr: "1.1.1.1".into(),
                port: 80,
                ret: 0,
            },
        ));
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 2,
            Payload::Connect {
                addr: "1.1.1.1".into(),
                port: 443,
                ret: 0,
            },
        ));
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 3,
            Payload::Connect {
                addr: "1.1.1.1".into(),
                port: 443,
                ret: -111,
            },
        ));
        let detail = store.agent_detail(ROOT).unwrap();
        assert_eq!(detail.connections.len(), 2);
        let https = detail.connections.iter().find(|c| c.port == 443).unwrap();
        assert_eq!(https.access.count, 2);
        assert_eq!(https.access.errors.get("ECONNREFUSED"), Some(&1));
    }

    #[test]
    fn detail_sort_order() {
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, open("/tmp/harmless.txt", 0, 3)));
        store.push(root_ev(
            TS + 2,
            open("/home/user/.ssh/authorized_keys", 0, 3),
        ));
        let detail = store.agent_detail(ROOT).unwrap();
        assert!(
            detail.files[0].sensitive,
            "sensitive files should sort first"
        );
        assert!(!detail.files[1].sensitive);

        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 3,
            Payload::Connect {
                addr: "127.0.0.1".into(),
                port: 8080,
                ret: 0,
            },
        ));
        store.push(ev(
            ROOT,
            ROOT,
            "curl",
            TS + 4,
            Payload::Connect {
                addr: "93.184.216.34".into(),
                port: 443,
                ret: 0,
            },
        ));
        let detail = store.agent_detail(ROOT).unwrap();
        assert!(
            detail.connections[0].external,
            "external connections should sort first"
        );
        assert!(!detail.connections[1].external);
    }

    #[test]
    fn event_ring_caps_and_counts_drops() {
        let mut store = EventStore::new(3, 100);
        store.push(root_ev(
            TS,
            Payload::Execve {
                filename: "/usr/bin/claude".into(),
            },
        ));
        for i in 0..4u64 {
            store.push(root_ev(TS + i, open(&format!("/tmp/f{i}"), 0, 3)));
        }
        assert_eq!(store.agent_events(ROOT).unwrap().len(), 3);
        let summary = &store.agents_summary()[0];
        assert_eq!(summary.events_dropped, 2);
        // Aggregates survive the ring: all 4 paths are still tracked.
        assert_eq!(store.agent_detail(ROOT).unwrap().files.len(), 4);
        assert_eq!(summary.file_count, 4);
    }

    #[test]
    fn global_budget_trims_largest_tree() {
        let mut store = EventStore::new(100, 5);
        for i in 0..4u64 {
            store.push(ev(100, 100, "a", TS + i, open("/a", 0, 3)));
        }
        store.push(ev(
            200,
            200,
            "b",
            TS,
            Payload::Execve {
                filename: "/b".into(),
            },
        ));
        store.push(ev(200, 200, "b", TS + 1, open("/b", 0, 3)));
        assert_eq!(store.total_events, 5);
        assert_eq!(store.agent_events(100).unwrap().len(), 3);
        assert_eq!(store.agent_events(200).unwrap().len(), 2);
        assert_eq!(
            store
                .agents_summary()
                .iter()
                .find(|s| s.root_pid == 100)
                .unwrap()
                .events_dropped,
            1
        );
    }

    #[test]
    fn evict_exited_trees() {
        let mut store = new_store_with_root();
        let ts_ms = TS / 1_000_000;
        assert_eq!(store.evict_exited(ts_ms + 1_000_000, 1), 0);

        store.push(root_ev(TS + 1, Payload::Exit));
        assert_eq!(store.evict_exited(ts_ms + 10, 60_000), 0);
        assert_eq!(store.agents_summary().len(), 1);

        assert_eq!(store.evict_exited(ts_ms + 61_000, 60_000), 1);
        assert!(store.agents_summary().is_empty());
        assert_eq!(store.total_events, 0);
    }

    #[test]
    fn version_advances_per_event() {
        let mut store = new_store_with_root();
        let v1 = store.agent_version(ROOT).unwrap();
        store.push(root_ev(TS + 1, open("/x", 0, 3)));
        assert_eq!(store.agent_version(ROOT).unwrap(), v1 + 1);
        assert_eq!(store.agent_detail(ROOT).unwrap().version, v1 + 1);
    }

    #[test]
    fn listener_flag_only_on_successful_listen() {
        let mut store = new_store_with_root();
        store.push(root_ev(
            TS + 1,
            Payload::Listen {
                backlog: 128,
                ret: -13,
            },
        ));
        assert!(!store.agents_summary()[0].has_listener);
        store.push(root_ev(
            TS + 2,
            Payload::Listen {
                backlog: 128,
                ret: 0,
            },
        ));
        assert!(store.agents_summary()[0].has_listener);
        assert_eq!(store.agents_summary()[0].bind_count, 0);
    }
}
