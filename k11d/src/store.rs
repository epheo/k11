use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;

use tracing::warn;

use crate::dns_cache::DnsCache;

/// Canonical list of sensitive paths — shared with the dashboard via GetConfig.
pub const SENSITIVE_PATHS: &[&str] = &[
    ".ssh/", ".gnupg/", ".aws/", ".kube/", ".docker/",
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/etc/ssl/private", "/etc/pki/tls/private",
    "/root/",
];

/// Default cap for the per-agent raw event ring (config: store.max_events_per_agent).
pub const DEFAULT_MAX_EVENTS_PER_AGENT: usize = 10_000;

/// Cap on unique keys per aggregate map (files, connections, unix sockets):
/// a runaway crawler must not OOM the daemon. Existing keys keep updating.
const MAX_AGGREGATE_KEYS: usize = 20_000;

pub fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.iter().any(|p| path.contains(p))
}

/// External = routable beyond this machine and its private networks.
/// Loopback, RFC1918, link-local, unspecified, and IPv6 unique-local are not
/// external. Unparseable addresses (e.g. "af=5") count as external.
pub fn is_external_addr(addr: &str) -> bool {
    match DnsCache::parse_ip(addr) {
        Some(IpAddr::V4(ip)) => {
            !(ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified())
        }
        Some(IpAddr::V6(ip)) => {
            let seg0 = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00   // unique local fc00::/7
                || (seg0 & 0xffc0) == 0xfe80)  // link local fe80::/10
        }
        None => true,
    }
}

/// Map a negative syscall return value to its errno name.
pub fn errno_name(ret: i32) -> Cow<'static, str> {
    match -ret {
        1 => Cow::Borrowed("EPERM"),
        2 => Cow::Borrowed("ENOENT"),
        3 => Cow::Borrowed("ESRCH"),
        4 => Cow::Borrowed("EINTR"),
        5 => Cow::Borrowed("EIO"),
        9 => Cow::Borrowed("EBADF"),
        11 => Cow::Borrowed("EAGAIN"),
        12 => Cow::Borrowed("ENOMEM"),
        13 => Cow::Borrowed("EACCES"),
        14 => Cow::Borrowed("EFAULT"),
        17 => Cow::Borrowed("EEXIST"),
        19 => Cow::Borrowed("ENODEV"),
        20 => Cow::Borrowed("ENOTDIR"),
        21 => Cow::Borrowed("EISDIR"),
        22 => Cow::Borrowed("EINVAL"),
        23 => Cow::Borrowed("ENFILE"),
        24 => Cow::Borrowed("EMFILE"),
        26 => Cow::Borrowed("ETXTBSY"),
        28 => Cow::Borrowed("ENOSPC"),
        30 => Cow::Borrowed("EROFS"),
        36 => Cow::Borrowed("ENAMETOOLONG"),
        40 => Cow::Borrowed("ELOOP"),
        61 => Cow::Borrowed("ENODATA"),
        98 => Cow::Borrowed("EADDRINUSE"),
        99 => Cow::Borrowed("EADDRNOTAVAIL"),
        100 => Cow::Borrowed("ENETDOWN"),
        101 => Cow::Borrowed("ENETUNREACH"),
        103 => Cow::Borrowed("ECONNABORTED"),
        104 => Cow::Borrowed("ECONNRESET"),
        110 => Cow::Borrowed("ETIMEDOUT"),
        111 => Cow::Borrowed("ECONNREFUSED"),
        113 => Cow::Borrowed("EHOSTUNREACH"),
        114 => Cow::Borrowed("EALREADY"),
        115 => Cow::Borrowed("EINPROGRESS"),
        n => Cow::Owned(format!("E?{n}")),
    }
}

fn status(ret: i32) -> Cow<'static, str> {
    if ret >= 0 {
        Cow::Borrowed("ok")
    } else {
        errno_name(ret)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Fields shared by every event, mirroring the BPF `EventHeader`.
/// `root_pid` makes each event attributable to its agent tree on its own.
#[derive(Clone)]
pub struct EventMeta {
    /// Acting process (for fork: the parent).
    pub pid: u32,
    pub root_pid: u32,
    pub uid: u32,
    pub comm: String,
    pub timestamp_ns: u64,
}

#[derive(Clone)]
pub struct Event {
    pub meta: EventMeta,
    pub payload: Payload,
}

#[derive(Clone)]
pub enum Payload {
    Execve { filename: String },
    Openat { filename: String, flags: i32, ret: i32, denied: bool },
    Connect { addr: String, port: u16, ret: i32 },
    UnixConnect { path: String, ret: i32 },
    Fork { child_pid: u32 },
    Exit,
    Bind { addr: String, port: u16, ret: i32 },
    Listen { backlog: i32, ret: i32 },
    Unlink { filename: String, flags: i32, ret: i32 },
    Rename { old_path: String, new_path: String, ret: i32 },
    Chmod { filename: String, mode: u32, ret: i32 },
    Chown { filename: String, owner_uid: u32, owner_gid: u32, ret: i32 },
    Symlink { target: String, linkpath: String, ret: i32 },
    Ptrace { request: u32, target_pid: u32, ret: i32 },
}

impl Event {
    /// Shift boot-relative `timestamp_ns` to wall-clock epoch nanoseconds.
    pub fn adjust_timestamp(&mut self, boot_offset_ns: u64) {
        self.meta.timestamp_ns = self.meta.timestamp_ns.saturating_add(boot_offset_ns);
    }

    /// True if this event was actively denied by k11 policy.
    pub fn is_denied(&self) -> bool {
        matches!(self.payload, Payload::Openat { denied: true, .. })
    }

    fn ret(&self) -> Option<i32> {
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

    /// True if the syscall returned an error (ret < 0) but was NOT a policy deny.
    pub fn is_error(&self) -> bool {
        !self.is_denied() && self.ret().is_some_and(|r| r < 0)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.meta;
        match &self.payload {
            Payload::Execve { filename } => {
                write!(f, "execve pid={} root={} uid={} comm={} filename={filename}",
                    m.pid, m.root_pid, m.uid, m.comm)
            }
            Payload::Openat { filename, flags, ret, .. } => {
                write!(f, "openat pid={} comm={} filename={filename} flags=0x{flags:x} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Connect { addr, port, ret } => {
                write!(f, "connect pid={} comm={} addr={addr} port={port} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::UnixConnect { path, ret } => {
                write!(f, "unix_connect pid={} comm={} path={path} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Fork { child_pid } => {
                write!(f, "fork parent_pid={} child_pid={child_pid} comm={}", m.pid, m.comm)
            }
            Payload::Exit => {
                write!(f, "exit pid={} comm={}", m.pid, m.comm)
            }
            Payload::Bind { addr, port, ret } => {
                write!(f, "bind pid={} comm={} addr={addr} port={port} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Listen { backlog, ret } => {
                write!(f, "listen pid={} comm={} backlog={backlog} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Unlink { filename, ret, .. } => {
                write!(f, "unlink pid={} comm={} filename={filename} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Rename { old_path, new_path, ret } => {
                write!(f, "rename pid={} comm={} old={old_path} new={new_path} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Chmod { filename, mode, ret } => {
                write!(f, "chmod pid={} comm={} filename={filename} mode=0o{mode:o} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Chown { filename, owner_uid, owner_gid, ret } => {
                write!(f, "chown pid={} comm={} filename={filename} uid={owner_uid} gid={owner_gid} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Symlink { target, linkpath, ret } => {
                write!(f, "symlink pid={} comm={} target={target} linkpath={linkpath} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
            }
            Payload::Ptrace { request, target_pid, ret } => {
                write!(f, "ptrace pid={} comm={} request={request} target={target_pid} ret={ret} [{}]",
                    m.pid, m.comm, status(*ret))
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

#[derive(Clone)]
pub struct FileAccess {
    pub path: String,
    pub count: usize,
    /// Per-errno failure counts, e.g. {"ENOENT": 3, "EACCES": 1}.
    pub errors: BTreeMap<String, usize>,
    pub comms: Vec<String>,
    pub sensitive: bool,
    pub modified: bool,
    pub deleted: bool,
    pub renamed: bool,
    pub perm_changed: bool,
    pub owner_changed: bool,
    pub is_symlink: bool,
    /// True if any access to this path was denied by k11 policy.
    pub denied: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct ConnectionAccess {
    pub addr: String,
    pub port: u16,
    pub count: usize,
    /// Per-errno failure counts.
    pub errors: BTreeMap<String, usize>,
    pub comms: Vec<String>,
    pub external: bool,
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct UnixSocketAccess {
    pub path: String,
    pub count: usize,
    /// Per-errno failure counts.
    pub errors: BTreeMap<String, usize>,
    pub comms: Vec<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone)]
pub struct AgentDetail {
    pub root_pid: u32,
    pub root_comm: String,
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

/// Per-process state maintained incrementally from BPF events.
struct ProcessEntry {
    comm: String,
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
    fn new(comm: String, parent_pid: Option<u32>) -> Self {
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

/// Shared accumulator for aggregating access events (files, connections, unix sockets).
struct AccessAccumulator {
    count: usize,
    errors: BTreeMap<String, usize>,
    comms: HashSet<String>,
    denied: bool,
    first_ns: u64,
    last_ns: u64,
}

impl Default for AccessAccumulator {
    fn default() -> Self {
        Self {
            count: 0,
            errors: BTreeMap::new(),
            comms: HashSet::new(),
            denied: false,
            first_ns: u64::MAX,
            last_ns: 0,
        }
    }
}

impl AccessAccumulator {
    fn record(&mut self, comm: &str, ret: i32, denied: bool, timestamp_ns: u64) {
        self.count += 1;
        if ret < 0 {
            *self.errors.entry(errno_name(ret).to_string()).or_insert(0) += 1;
        }
        self.denied |= denied;
        self.comms.insert(comm.to_owned());
        self.first_ns = self.first_ns.min(timestamp_ns);
        self.last_ns = self.last_ns.max(timestamp_ns);
    }

    /// `(count, errors, comms, denied, first_seen_ms, last_seen_ms)` for API views.
    fn snapshot(&self) -> (usize, BTreeMap<String, usize>, Vec<String>, bool, u64, u64) {
        (
            self.count,
            self.errors.clone(),
            self.comms.iter().cloned().collect(),
            self.denied,
            self.first_ns / 1_000_000,
            self.last_ns / 1_000_000,
        )
    }
}

#[derive(Default)]
struct FileAgg {
    acc: AccessAccumulator,
    modified: bool,
    deleted: bool,
    renamed: bool,
    perm_changed: bool,
    owner_changed: bool,
    is_symlink: bool,
}

/// Aggregate-map insert guard: existing keys always update, new keys are
/// rejected past the cap. Sets `overflowed` so the caller can log once.
fn agg_entry<'a, K: Ord, V: Default>(
    map: &'a mut BTreeMap<K, V>,
    key: K,
    overflowed: &mut bool,
) -> Option<&'a mut V> {
    if map.len() >= MAX_AGGREGATE_KEYS && !map.contains_key(&key) {
        *overflowed = true;
        return None;
    }
    Some(map.entry(key).or_default())
}

/// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
const WRITE_FLAGS: i32 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400;

pub struct AgentTree {
    pub root_pid: u32,
    pub root_comm: String,
    pub events: VecDeque<Event>,
    /// Event-driven process table — single source of truth for the process tree.
    processes: HashMap<u32, ProcessEntry>,
    // Aggregates maintained in ingest(), served by agent_detail() without
    // rescanning events. The events deque exists only for the raw log.
    files: BTreeMap<String, FileAgg>,
    conns: BTreeMap<(String, u16), AccessAccumulator>,
    binds: BTreeMap<(String, u16), AccessAccumulator>,
    unix_sockets: BTreeMap<String, AccessAccumulator>,
    aggregates_overflowed: bool,
    events_dropped: u64,
    last_event_ms: u64,
    file_count: usize,
    net_count: usize,
    unix_count: usize,
    exec_count: usize,
    deny_count: usize,
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
    fn new(root_pid: u32, comm: String) -> Self {
        let mut processes = HashMap::new();
        processes.insert(root_pid, ProcessEntry::new(comm.clone(), None));
        Self {
            root_pid,
            root_comm: comm,
            events: VecDeque::new(),
            processes,
            files: BTreeMap::new(),
            conns: BTreeMap::new(),
            binds: BTreeMap::new(),
            unix_sockets: BTreeMap::new(),
            aggregates_overflowed: false,
            events_dropped: 0,
            last_event_ms: 0,
            file_count: 0,
            net_count: 0,
            unix_count: 0,
            exec_count: 0,
            deny_count: 0,
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

    fn proc_entry(&mut self, pid: u32, comm: &str) -> &mut ProcessEntry {
        self.processes
            .entry(pid)
            .or_insert_with(|| ProcessEntry::new(comm.to_owned(), None))
    }

    fn ingest(&mut self, event: Event, max_events: usize) {
        let meta = &event.meta;
        let ts = meta.timestamp_ns;
        self.last_event_ms = self.last_event_ms.max(ts / 1_000_000);
        let was_overflowed = self.aggregates_overflowed;

        match &event.payload {
            Payload::Fork { child_pid } => {
                // In sched_process_fork comm is the parent's; the child
                // inherits it until its first exec.
                self.proc_entry(meta.pid, &meta.comm).touch(ts);
                let child = self
                    .processes
                    .entry(*child_pid)
                    .or_insert_with(|| ProcessEntry::new(meta.comm.clone(), Some(meta.pid)));
                child.parent_pid = Some(meta.pid);
                child.touch(ts);
            }
            Payload::Execve { .. } => {
                self.exec_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.comm = meta.comm.clone();
                entry.exec_count += 1;
                entry.touch(ts);
            }
            Payload::Openat { filename, flags, ret, denied } => {
                self.file_count += 1;
                if *denied {
                    self.deny_count += 1;
                }
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(filename) {
                    self.has_sensitive_files = true;
                    if (flags & WRITE_FLAGS) != 0 {
                        self.has_sensitive_writes = true;
                    }
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, filename.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, *denied, ts);
                    agg.modified |= (flags & WRITE_FLAGS) != 0;
                }
            }
            Payload::Connect { addr, port, ret } => {
                self.net_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
                if is_external_addr(addr) {
                    self.has_external_net = true;
                }
                if let Some(acc) = agg_entry(
                    &mut self.conns,
                    (addr.clone(), *port),
                    &mut self.aggregates_overflowed,
                ) {
                    acc.record(&meta.comm, *ret, false, ts);
                }
            }
            Payload::UnixConnect { path, ret } => {
                self.unix_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.unix_count += 1;
                entry.touch(ts);
                if let Some(acc) = agg_entry(
                    &mut self.unix_sockets,
                    path.clone(),
                    &mut self.aggregates_overflowed,
                ) {
                    acc.record(&meta.comm, *ret, false, ts);
                }
            }
            Payload::Exit => {
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.running = false;
                entry.touch(ts);
            }
            Payload::Bind { addr, port, ret } => {
                self.bind_count += 1;
                self.net_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
                if let Some(acc) = agg_entry(
                    &mut self.binds,
                    (addr.clone(), *port),
                    &mut self.aggregates_overflowed,
                ) {
                    acc.record(&meta.comm, *ret, false, ts);
                }
            }
            Payload::Listen { ret, .. } => {
                if *ret == 0 {
                    self.has_listener = true;
                }
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.net_count += 1;
                entry.touch(ts);
            }
            Payload::Unlink { filename, ret, .. } => {
                self.file_count += 1;
                self.fs_mod_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(filename) {
                    self.has_sensitive_files = true;
                    self.has_sensitive_delete = true;
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, filename.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, false, ts);
                    agg.deleted = true;
                }
            }
            Payload::Rename { old_path, new_path, ret } => {
                self.file_count += 1;
                self.fs_mod_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(old_path) || is_sensitive_path(new_path) {
                    self.has_sensitive_files = true;
                }
                for path in [old_path, new_path] {
                    if let Some(agg) =
                        agg_entry(&mut self.files, path.clone(), &mut self.aggregates_overflowed)
                    {
                        agg.acc.record(&meta.comm, *ret, false, ts);
                        agg.renamed = true;
                    }
                }
            }
            Payload::Chmod { filename, ret, .. } => {
                self.file_count += 1;
                self.fs_mod_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(filename) {
                    self.has_sensitive_files = true;
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, filename.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, false, ts);
                    agg.perm_changed = true;
                }
            }
            Payload::Chown { filename, ret, .. } => {
                self.file_count += 1;
                self.fs_mod_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(filename) {
                    self.has_sensitive_files = true;
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, filename.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, false, ts);
                    agg.owner_changed = true;
                }
            }
            Payload::Symlink { target, linkpath, ret } => {
                self.file_count += 1;
                self.fs_mod_count += 1;
                let entry = self.proc_entry(meta.pid, &meta.comm);
                entry.file_count += 1;
                entry.touch(ts);
                if is_sensitive_path(target) || is_sensitive_path(linkpath) {
                    self.has_sensitive_files = true;
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, target.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, false, ts);
                }
                if let Some(agg) =
                    agg_entry(&mut self.files, linkpath.clone(), &mut self.aggregates_overflowed)
                {
                    agg.acc.record(&meta.comm, *ret, false, ts);
                    agg.is_symlink = true;
                }
            }
            Payload::Ptrace { .. } => {
                self.ptrace_count += 1;
                self.has_ptrace = true;
                self.proc_entry(meta.pid, &meta.comm).touch(ts);
            }
        }

        if self.aggregates_overflowed && !was_overflowed {
            warn!(
                root_pid = self.root_pid,
                cap = MAX_AGGREGATE_KEYS,
                "aggregate cap reached — new paths/addresses no longer tracked in detail view"
            );
        }

        if self.events.len() >= max_events {
            self.events.pop_front();
            self.events_dropped += 1;
        }
        self.events.push_back(event);
    }

    fn summary(&self) -> AgentSummary {
        let running_count = self.processes.values().filter(|e| e.running).count();
        AgentSummary {
            root_pid: self.root_pid,
            root_comm: self.root_comm.clone(),
            process_count: self.processes.len(),
            running_count,
            exited_count: self.processes.len() - running_count,
            file_count: self.file_count,
            net_count: self.net_count,
            unix_count: self.unix_count,
            exec_count: self.exec_count,
            deny_count: self.deny_count,
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
        let mut processes: Vec<ProcessInfo> = self.processes.iter()
            .map(|(&pid, entry)| ProcessInfo {
                pid,
                comm: entry.comm.clone(),
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
        self.processes.values().any(|e| e.running)
    }
}

fn connection_list(map: &BTreeMap<(String, u16), AccessAccumulator>) -> Vec<ConnectionAccess> {
    let mut out: Vec<ConnectionAccess> = map
        .iter()
        .map(|((addr, port), acc)| {
            let (count, errors, comms, _denied, first_seen_ms, last_seen_ms) = acc.snapshot();
            ConnectionAccess {
                addr: addr.clone(),
                port: *port,
                count,
                errors,
                comms,
                external: is_external_addr(addr),
                hostname: None,
                country: None,
                city: None,
                asn: None,
                first_seen_ms,
                last_seen_ms,
            }
        })
        .collect();
    out.sort_by(|a, b| b.external.cmp(&a.external).then(b.count.cmp(&a.count)));
    out
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct EventStore {
    agents: HashMap<u32, AgentTree>,
    max_events_per_agent: usize,
}

impl EventStore {
    pub fn new(max_events_per_agent: usize) -> Self {
        Self {
            agents: HashMap::new(),
            max_events_per_agent,
        }
    }

    /// Pre-populate a process entry from the /proc scan at startup, so
    /// processes that existed before k11 started have correct parent linkage.
    pub fn seed_process(&mut self, root_pid: u32, pid: u32, parent_pid: Option<u32>, comm: String) {
        let agent = self.agents.entry(root_pid).or_insert_with(|| {
            AgentTree::new(root_pid, comm.clone())
        });
        // Don't overwrite an existing entry (e.g. the root created by AgentTree::new)
        agent.processes.entry(pid).or_insert(ProcessEntry::new(comm, parent_pid));
    }

    pub fn push(&mut self, event: Event) {
        let root_pid = event.meta.root_pid;
        let is_new = !self.agents.contains_key(&root_pid);
        let agent = self.agents.entry(root_pid).or_insert_with(|| {
            AgentTree::new(root_pid, event.meta.comm.clone())
        });
        // New trees legitimately start with exec (comm discovery) or fork
        // (lineage); anything else means the root was never seen — likely a
        // lookup_root fallback in the probe.
        if is_new && !matches!(event.payload, Payload::Execve { .. } | Payload::Fork { .. }) {
            warn!(
                root_pid,
                comm = %event.meta.comm,
                "agent tree created from non-exec event (possible orphan)"
            );
        }
        agent.ingest(event, self.max_events_per_agent);
    }

    /// Drop trees whose processes have all exited and whose last event is
    /// older than `ttl_ms`. Returns how many trees were evicted.
    pub fn evict_exited(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.agents.len();
        self.agents.retain(|_, agent| {
            agent.running() || now_ms.saturating_sub(agent.last_event_ms) < ttl_ms
        });
        before - self.agents.len()
    }

    pub fn agents_summary(&self) -> Vec<AgentSummary> {
        self.agents.values().map(|a| a.summary()).collect()
    }

    pub fn agent_events(&self, root_pid: u32) -> Vec<&Event> {
        self.agents
            .get(&root_pid)
            .map(|a| a.events.iter().collect())
            .unwrap_or_default()
    }

    pub fn agent_detail(&self, root_pid: u32) -> Option<AgentDetail> {
        let agent = self.agents.get(&root_pid)?;

        let mut files: Vec<FileAccess> = agent
            .files
            .iter()
            .map(|(path, agg)| {
                let (count, errors, comms, denied, first_seen_ms, last_seen_ms) =
                    agg.acc.snapshot();
                FileAccess {
                    path: path.clone(),
                    count,
                    errors,
                    comms,
                    sensitive: is_sensitive_path(path),
                    modified: agg.modified,
                    deleted: agg.deleted,
                    renamed: agg.renamed,
                    perm_changed: agg.perm_changed,
                    owner_changed: agg.owner_changed,
                    is_symlink: agg.is_symlink,
                    denied,
                    first_seen_ms,
                    last_seen_ms,
                }
            })
            .collect();
        files.sort_by(|a, b| {
            b.denied.cmp(&a.denied)
                .then(b.deleted.cmp(&a.deleted))
                .then(b.sensitive.cmp(&a.sensitive))
                .then(b.modified.cmp(&a.modified))
                .then(b.count.cmp(&a.count))
        });

        let mut unix_sockets: Vec<UnixSocketAccess> = agent
            .unix_sockets
            .iter()
            .map(|(path, acc)| {
                let (count, errors, comms, _denied, first_seen_ms, last_seen_ms) = acc.snapshot();
                UnixSocketAccess {
                    path: path.clone(),
                    count,
                    errors,
                    comms,
                    first_seen_ms,
                    last_seen_ms,
                }
            })
            .collect();
        unix_sockets.sort_by_key(|s| std::cmp::Reverse(s.count));

        Some(AgentDetail {
            root_pid: agent.root_pid,
            root_comm: agent.root_comm.clone(),
            processes: agent.process_list(),
            files,
            connections: connection_list(&agent.conns),
            binds: connection_list(&agent.binds),
            unix_sockets,
            summary: agent.summary(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u32 = 100;
    const TS: u64 = 1_000_000_000; // 1 second in ns

    fn ev(pid: u32, root_pid: u32, comm: &str, ts: u64, payload: Payload) -> Event {
        Event {
            meta: EventMeta {
                pid,
                root_pid,
                uid: 1000,
                comm: comm.into(),
                timestamp_ns: ts,
            },
            payload,
        }
    }

    fn root_ev(ts: u64, payload: Payload) -> Event {
        ev(ROOT, ROOT, "claude", ts, payload)
    }

    fn new_store_with_root() -> EventStore {
        let mut store = EventStore::new(DEFAULT_MAX_EVENTS_PER_AGENT);
        store.push(root_ev(TS, Payload::Execve { filename: "/usr/bin/claude".into() }));
        store
    }

    #[test]
    fn external_addr_classification() {
        assert!(is_external_addr("8.8.8.8"));
        assert!(is_external_addr("[2606:4700::1111]"));
        assert!(!is_external_addr("127.0.0.1"));
        assert!(!is_external_addr("127.1.2.3"));
        assert!(!is_external_addr("10.0.0.5"));
        assert!(!is_external_addr("192.168.1.1"));
        assert!(!is_external_addr("172.16.0.1"));
        assert!(!is_external_addr("172.31.255.1"));
        assert!(is_external_addr("172.32.0.1"));
        assert!(!is_external_addr("169.254.1.1"));
        assert!(!is_external_addr("0.0.0.0"));
        assert!(!is_external_addr("[::1]"));
        assert!(!is_external_addr("[fd00::1]"));
        assert!(!is_external_addr("[fe80::1]"));
        // Unparseable (unknown address family) counts as external.
        assert!(is_external_addr("af=5"));
    }

    #[test]
    fn sensitive_file_write_detection() {
        let mut store = new_store_with_root();

        // Write to sensitive path → both flags
        store.push(root_ev(TS + 1, Payload::Openat {
            filename: "/home/user/.ssh/id_rsa".into(),
            flags: 0x1, // O_WRONLY
            ret: 3,
            denied: false,
        }));
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(summary.has_sensitive_writes);

        // Fresh store: read-only access to sensitive path → sensitive but not write
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, Payload::Openat {
            filename: "/home/user/.ssh/id_rsa".into(),
            flags: 0x0, // O_RDONLY
            ret: 3,
            denied: false,
        }));
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);

        // Fresh store: write to non-sensitive path → neither flag
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, Payload::Openat {
            filename: "/tmp/scratch.txt".into(),
            flags: 0x1, // O_WRONLY
            ret: 3,
            denied: false,
        }));
        let summary = &store.agents_summary()[0];
        assert!(!summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);
    }

    #[test]
    fn external_network_detection() {
        // External address → flagged
        let mut store = new_store_with_root();
        store.push(ev(ROOT, ROOT, "curl", TS + 1, Payload::Connect {
            addr: "8.8.8.8".into(), port: 443, ret: 0,
        }));
        assert!(store.agents_summary()[0].has_external_net);

        // Loopback only → not flagged
        let mut store = new_store_with_root();
        store.push(ev(ROOT, ROOT, "curl", TS + 1, Payload::Connect {
            addr: "127.0.0.1".into(), port: 8080, ret: 0,
        }));
        assert!(!store.agents_summary()[0].has_external_net);

        // LAN address → not flagged
        let mut store = new_store_with_root();
        store.push(ev(ROOT, ROOT, "curl", TS + 1, Payload::Connect {
            addr: "192.168.1.10".into(), port: 8080, ret: 0,
        }));
        assert!(!store.agents_summary()[0].has_external_net);
    }

    #[test]
    fn process_tree_lifecycle() {
        let mut store = new_store_with_root();

        // Fork child
        store.push(root_ev(TS + 1, Payload::Fork { child_pid: 200 }));

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).expect("child should exist");
        assert_eq!(child.parent_pid, Some(ROOT));
        assert!(child.running);
        assert_eq!(child.comm, "claude");

        // Exec replaces child image
        store.push(ev(200, ROOT, "curl", TS + 2, Payload::Execve {
            filename: "/usr/bin/curl".into(),
        }));

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert_eq!(child.comm, "curl");
        assert_eq!(child.exec_count, 1);

        // Child exits
        store.push(ev(200, ROOT, "curl", TS + 3, Payload::Exit));

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert!(!child.running);

        // Root is still running, child exited
        assert_eq!(detail.summary.running_count, 1);
        assert_eq!(detail.summary.exited_count, 1);
        assert_eq!(detail.summary.process_count, 2);
    }

    #[test]
    fn multiple_agents_isolated() {
        let mut store = EventStore::new(DEFAULT_MAX_EVENTS_PER_AGENT);
        let root_a: u32 = 100;
        let root_b: u32 = 200;

        store.push(ev(root_a, root_a, "agent_a", TS, Payload::Execve { filename: "/bin/a".into() }));
        store.push(ev(root_b, root_b, "agent_b", TS, Payload::Execve { filename: "/bin/b".into() }));

        // File access under agent A only
        store.push(ev(root_a, root_a, "agent_a", TS + 1, Payload::Openat {
            filename: "/tmp/a.txt".into(), flags: 0, ret: 3, denied: false,
        }));

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

        // 3 opens to same file: 2 success from "claude", 1 ENOENT from "cat"
        store.push(root_ev(TS + 1, Payload::Openat {
            filename: "/etc/config".into(), flags: 0, ret: 3, denied: false,
        }));
        store.push(root_ev(TS + 2, Payload::Openat {
            filename: "/etc/config".into(), flags: 0, ret: 4, denied: false,
        }));
        store.push(ev(ROOT, ROOT, "cat", TS + 3, Payload::Openat {
            filename: "/etc/config".into(), flags: 0, ret: -2, denied: false, // ENOENT
        }));

        let detail = store.agent_detail(ROOT).unwrap();
        let file = detail.files.iter()
            .find(|f| f.path == "/etc/config")
            .expect("file should be aggregated");

        assert_eq!(file.count, 3);
        assert_eq!(file.errors.get("ENOENT"), Some(&1));
        assert!(file.comms.contains(&"claude".to_string()));
        assert!(file.comms.contains(&"cat".to_string()));
        assert_eq!(file.first_seen_ms, (TS + 1) / 1_000_000);
        assert_eq!(file.last_seen_ms, (TS + 3) / 1_000_000);
    }

    #[test]
    fn detail_sort_order() {
        let mut store = new_store_with_root();

        // Non-sensitive file first, then sensitive
        store.push(root_ev(TS + 1, Payload::Openat {
            filename: "/tmp/harmless.txt".into(), flags: 0, ret: 3, denied: false,
        }));
        store.push(root_ev(TS + 2, Payload::Openat {
            filename: "/home/user/.ssh/authorized_keys".into(), flags: 0, ret: 3, denied: false,
        }));

        let detail = store.agent_detail(ROOT).unwrap();
        assert!(detail.files[0].sensitive, "sensitive files should sort first");
        assert!(!detail.files[1].sensitive);

        // External connection + loopback
        store.push(ev(ROOT, ROOT, "curl", TS + 3, Payload::Connect {
            addr: "127.0.0.1".into(), port: 8080, ret: 0,
        }));
        store.push(ev(ROOT, ROOT, "curl", TS + 4, Payload::Connect {
            addr: "93.184.216.34".into(), port: 443, ret: 0,
        }));

        let detail = store.agent_detail(ROOT).unwrap();
        assert!(detail.connections[0].external, "external connections should sort first");
        assert!(!detail.connections[1].external);
    }

    #[test]
    fn event_ring_caps_and_counts_drops() {
        let mut store = EventStore::new(3);
        store.push(root_ev(TS, Payload::Execve { filename: "/usr/bin/claude".into() }));
        for i in 0..4u64 {
            store.push(root_ev(TS + i, Payload::Openat {
                filename: format!("/tmp/f{i}"), flags: 0, ret: 3, denied: false,
            }));
        }

        assert_eq!(store.agent_events(ROOT).len(), 3);
        let summary = &store.agents_summary()[0];
        assert_eq!(summary.events_dropped, 2);
        // Aggregates survive the ring: all 4 paths are still tracked.
        assert_eq!(store.agent_detail(ROOT).unwrap().files.len(), 4);
        assert_eq!(summary.file_count, 4);
    }

    #[test]
    fn evict_exited_trees() {
        let mut store = new_store_with_root();
        let ts_ms = TS / 1_000_000;

        // Still running → never evicted
        assert_eq!(store.evict_exited(ts_ms + 1_000_000, 1), 0);

        store.push(root_ev(TS + 1, Payload::Exit));

        // Exited but fresh → kept
        assert_eq!(store.evict_exited(ts_ms + 10, 60_000), 0);
        assert_eq!(store.agents_summary().len(), 1);

        // Exited and stale → evicted
        assert_eq!(store.evict_exited(ts_ms + 61_000, 60_000), 1);
        assert!(store.agents_summary().is_empty());
    }

    #[test]
    fn listener_flag_only_on_successful_listen() {
        let mut store = new_store_with_root();
        store.push(root_ev(TS + 1, Payload::Listen { backlog: 128, ret: -13 }));
        assert!(!store.agents_summary()[0].has_listener);

        store.push(root_ev(TS + 2, Payload::Listen { backlog: 128, ret: 0 }));
        assert!(store.agents_summary()[0].has_listener);
        // Listen is not a bind: bind_count untouched.
        assert_eq!(store.agents_summary()[0].bind_count, 0);
    }
}
