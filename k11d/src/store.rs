use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

use serde::Serialize;
use tracing::warn;

/// Canonical list of sensitive paths — shared with the dashboard via /api/config.
pub const SENSITIVE_PATHS: &[&str] = &[
    ".ssh/", ".gnupg/", ".aws/", ".kube/", ".docker/",
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/etc/ssl/private", "/etc/pki/tls/private",
    "/root/",
];

pub fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.iter().any(|p| path.contains(p))
}

pub fn is_external_addr(addr: &str) -> bool {
    !addr.starts_with("127.") && !addr.starts_with("[::1]") && !addr.starts_with("0.0.0.0")
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

#[derive(Clone, Serialize)]
#[serde(tag = "type")]
pub enum Event {
    Execve {
        pid: u32,
        root_pid: u32,
        uid: u32,
        comm: String,
        filename: String,
        timestamp_ns: u64,
    },
    Openat {
        pid: u32,
        comm: String,
        filename: String,
        flags: i32,
        ret: i32,
        timestamp_ns: u64,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        denied: bool,
    },
    Connect {
        pid: u32,
        comm: String,
        addr: String,
        port: u16,
        ret: i32,
        timestamp_ns: u64,
    },
    Fork {
        /// parent_pid is header.pid — the current task in sched_process_fork.
        parent_pid: u32,
        child_pid: u32,
        comm: String,
        timestamp_ns: u64,
    },
    UnixConnect {
        pid: u32,
        comm: String,
        path: String,
        ret: i32,
        timestamp_ns: u64,
    },
    Exit {
        pid: u32,
        comm: String,
        timestamp_ns: u64,
    },
    Bind {
        pid: u32,
        comm: String,
        addr: String,
        port: u16,
        ret: i32,
        timestamp_ns: u64,
    },
    Listen {
        pid: u32,
        comm: String,
        backlog: i32,
        ret: i32,
        timestamp_ns: u64,
    },
    Unlink {
        pid: u32,
        comm: String,
        filename: String,
        flags: i32,
        ret: i32,
        timestamp_ns: u64,
    },
    Rename {
        pid: u32,
        comm: String,
        old_path: String,
        new_path: String,
        ret: i32,
        timestamp_ns: u64,
    },
    Chmod {
        pid: u32,
        comm: String,
        filename: String,
        mode: u32,
        ret: i32,
        timestamp_ns: u64,
    },
    Chown {
        pid: u32,
        comm: String,
        filename: String,
        owner_uid: u32,
        owner_gid: u32,
        ret: i32,
        timestamp_ns: u64,
    },
    Symlink {
        pid: u32,
        comm: String,
        target: String,
        linkpath: String,
        ret: i32,
        timestamp_ns: u64,
    },
    Ptrace {
        pid: u32,
        comm: String,
        request: u32,
        target_pid: u32,
        ret: i32,
        timestamp_ns: u64,
    },
}

impl Event {
    pub fn comm(&self) -> &str {
        match self {
            Event::Execve { comm, .. }
            | Event::Openat { comm, .. }
            | Event::Connect { comm, .. }
            | Event::UnixConnect { comm, .. }
            | Event::Fork { comm, .. }
            | Event::Exit { comm, .. }
            | Event::Bind { comm, .. }
            | Event::Listen { comm, .. }
            | Event::Unlink { comm, .. }
            | Event::Rename { comm, .. }
            | Event::Chmod { comm, .. }
            | Event::Chown { comm, .. }
            | Event::Symlink { comm, .. }
            | Event::Ptrace { comm, .. } => comm,
        }
    }

    fn timestamp_ns_mut(&mut self) -> &mut u64 {
        match self {
            Event::Execve { timestamp_ns, .. }
            | Event::Openat { timestamp_ns, .. }
            | Event::Connect { timestamp_ns, .. }
            | Event::UnixConnect { timestamp_ns, .. }
            | Event::Fork { timestamp_ns, .. }
            | Event::Exit { timestamp_ns, .. }
            | Event::Bind { timestamp_ns, .. }
            | Event::Listen { timestamp_ns, .. }
            | Event::Unlink { timestamp_ns, .. }
            | Event::Rename { timestamp_ns, .. }
            | Event::Chmod { timestamp_ns, .. }
            | Event::Chown { timestamp_ns, .. }
            | Event::Symlink { timestamp_ns, .. }
            | Event::Ptrace { timestamp_ns, .. } => timestamp_ns,
        }
    }

    /// Shift boot-relative `timestamp_ns` to wall-clock epoch nanoseconds.
    pub fn adjust_timestamp(&mut self, boot_offset_ns: u64) {
        let ts = self.timestamp_ns_mut();
        *ts = ts.saturating_add(boot_offset_ns);
    }

    /// True if this event was actively denied by k11 policy.
    pub fn is_denied(&self) -> bool {
        matches!(self, Event::Openat { denied: true, .. })
    }

    /// True if the syscall returned an error (ret < 0) but was NOT a policy deny.
    pub fn is_error(&self) -> bool {
        if self.is_denied() {
            return false;
        }
        match self {
            Event::Openat { ret, .. }
            | Event::Connect { ret, .. }
            | Event::UnixConnect { ret, .. }
            | Event::Bind { ret, .. }
            | Event::Listen { ret, .. }
            | Event::Unlink { ret, .. }
            | Event::Rename { ret, .. }
            | Event::Chmod { ret, .. }
            | Event::Chown { ret, .. }
            | Event::Symlink { ret, .. }
            | Event::Ptrace { ret, .. } => *ret < 0,
            _ => false,
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Execve { pid, root_pid, uid, comm, filename, .. } => {
                write!(f, "execve pid={pid} root={root_pid} uid={uid} comm={comm} filename={filename}")
            }
            Event::Openat { pid, comm, filename, flags, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "openat pid={pid} comm={comm} filename={filename} flags=0x{flags:x} ret={ret} [{status}]")
            }
            Event::Connect { pid, comm, addr, port, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "connect pid={pid} comm={comm} addr={addr} port={port} ret={ret} [{status}]")
            }
            Event::UnixConnect { pid, comm, path, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "unix_connect pid={pid} comm={comm} path={path} ret={ret} [{status}]")
            }
            Event::Fork { parent_pid, child_pid, comm, .. } => {
                write!(f, "fork parent_pid={parent_pid} child_pid={child_pid} comm={comm}")
            }
            Event::Exit { pid, comm, .. } => {
                write!(f, "exit pid={pid} comm={comm}")
            }
            Event::Bind { pid, comm, addr, port, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "bind pid={pid} comm={comm} addr={addr} port={port} ret={ret} [{status}]")
            }
            Event::Listen { pid, comm, backlog, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "listen pid={pid} comm={comm} backlog={backlog} ret={ret} [{status}]")
            }
            Event::Unlink { pid, comm, filename, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "unlink pid={pid} comm={comm} filename={filename} ret={ret} [{status}]")
            }
            Event::Rename { pid, comm, old_path, new_path, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "rename pid={pid} comm={comm} old={old_path} new={new_path} ret={ret} [{status}]")
            }
            Event::Chmod { pid, comm, filename, mode, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "chmod pid={pid} comm={comm} filename={filename} mode=0o{mode:o} ret={ret} [{status}]")
            }
            Event::Chown { pid, comm, filename, owner_uid, owner_gid, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "chown pid={pid} comm={comm} filename={filename} uid={owner_uid} gid={owner_gid} ret={ret} [{status}]")
            }
            Event::Symlink { pid, comm, target, linkpath, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "symlink pid={pid} comm={comm} target={target} linkpath={linkpath} ret={ret} [{status}]")
            }
            Event::Ptrace { pid, comm, request, target_pid, ret, .. } => {
                let status = if *ret >= 0 { "ok".into() } else { errno_name(*ret) };
                write!(f, "ptrace pid={pid} comm={comm} request={request} target={target_pid} ret={ret} [{status}]")
            }
        }
    }
}

#[derive(Clone, Serialize)]
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
}

#[derive(Clone, Serialize)]
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

#[derive(Clone, Serialize)]
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

#[derive(Clone, Serialize)]
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

#[derive(Clone, Serialize)]
pub struct UnixSocketAccess {
    pub path: String,
    pub count: usize,
    /// Per-errno failure counts.
    pub errors: BTreeMap<String, usize>,
    pub comms: Vec<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Clone, Serialize)]
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

    /// Update first/last seen timestamps from a boot-relative nanosecond value.
    fn touch(&mut self, timestamp_ns: u64) {
        let ts_ms = timestamp_ns / 1_000_000;
        if self.first_seen_ms == 0 {
            self.first_seen_ms = ts_ms;
        }
        self.last_seen_ms = self.last_seen_ms.max(ts_ms);
    }
}

pub struct AgentTree {
    pub root_pid: u32,
    pub root_comm: String,
    pub pids: HashSet<u32>,
    pub events: VecDeque<Event>,
    /// Event-driven process table — single source of truth for the process tree.
    processes: HashMap<u32, ProcessEntry>,
    // Incremental counters — updated in push(), queried in summary().
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

/// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
const WRITE_FLAGS: i32 = 0x1 | 0x2 | 0x40 | 0x200 | 0x400;

impl AgentTree {
    fn new(root_pid: u32, comm: String) -> Self {
        let mut pids = HashSet::new();
        pids.insert(root_pid);
        let mut processes = HashMap::new();
        processes.insert(root_pid, ProcessEntry::new(comm.clone(), None));
        Self {
            root_pid,
            root_comm: comm,
            pids,
            events: VecDeque::new(),
            processes,
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

    fn summary(&self) -> AgentSummary {
        let running_count = self.processes.values().filter(|e| e.running).count();
        AgentSummary {
            root_pid: self.root_pid,
            root_comm: self.root_comm.clone(),
            process_count: self.pids.len(),
            running_count,
            exited_count: self.pids.len() - running_count,
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

impl AccessAccumulator {
    fn new() -> Self {
        Self {
            count: 0,
            errors: BTreeMap::new(),
            comms: HashSet::new(),
            denied: false,
            first_ns: u64::MAX,
            last_ns: 0,
        }
    }

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

    /// Consume the accumulator, returning `(count, errors, comms, denied, first_seen_ms, last_seen_ms)`.
    fn into_parts(self) -> (usize, BTreeMap<String, usize>, Vec<String>, bool, u64, u64) {
        (
            self.count,
            self.errors,
            self.comms.into_iter().collect(),
            self.denied,
            self.first_ns / 1_000_000,
            self.last_ns / 1_000_000,
        )
    }
}

pub struct EventStore {
    agents: HashMap<u32, AgentTree>,
}

impl EventStore {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// Pre-populate a process entry from /proc scan at startup.
    /// This ensures processes that existed before k11 started have correct parent linkage.
    pub fn seed_process(&mut self, root_pid: u32, pid: u32, parent_pid: Option<u32>, comm: String) {
        let agent = self.agents.entry(root_pid).or_insert_with(|| {
            AgentTree::new(root_pid, comm.clone())
        });
        agent.pids.insert(pid);
        // Don't overwrite an existing entry (e.g. the root created by AgentTree::new)
        agent.processes.entry(pid).or_insert(ProcessEntry::new(comm, parent_pid));
    }

    /// Push an event into the agent tree identified by root_pid.
    /// root_pid comes directly from the BPF event header.
    pub fn push(&mut self, root_pid: u32, event: Event) {
        let is_new = !self.agents.contains_key(&root_pid);
        let agent = self.agents.entry(root_pid).or_insert_with(|| {
            AgentTree::new(root_pid, event.comm().to_owned())
        });
        if is_new {
            warn!(
                root_pid,
                comm = %event.comm(),
                "new agent tree created from BPF event (possible lookup_root fallback)"
            );
        }

        // Update incremental counters, PID set, and process table from this event.
        match &event {
            Event::Fork { child_pid, parent_pid, comm, timestamp_ns, .. } => {
                agent.pids.insert(*child_pid);
                agent.pids.insert(*parent_pid);
                let mut child = ProcessEntry::new(comm.clone(), Some(*parent_pid));
                child.touch(*timestamp_ns);
                agent.processes.insert(*child_pid, child);
                if let Some(parent) = agent.processes.get_mut(parent_pid) {
                    parent.touch(*timestamp_ns);
                }
            }
            Event::Execve { pid, comm, timestamp_ns, .. } => {
                agent.pids.insert(*pid);
                agent.exec_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.comm = comm.clone();
                    entry.exec_count += 1;
                    entry.touch(*timestamp_ns);
                } else {
                    let mut entry = ProcessEntry::new(comm.clone(), None);
                    entry.exec_count = 1;
                    entry.touch(*timestamp_ns);
                    agent.processes.insert(*pid, entry);
                }
            }
            Event::Openat { pid, filename, flags, denied, timestamp_ns, .. } => {
                agent.file_count += 1;
                if *denied { agent.deny_count += 1; }
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(filename) {
                    agent.has_sensitive_files = true;
                    if (flags & WRITE_FLAGS) != 0 {
                        agent.has_sensitive_writes = true;
                    }
                }
            }
            Event::Connect { pid, addr, timestamp_ns, .. } => {
                agent.net_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.net_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_external_addr(addr) {
                    agent.has_external_net = true;
                }
            }
            Event::UnixConnect { pid, timestamp_ns, .. } => {
                agent.unix_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.unix_count += 1;
                    entry.touch(*timestamp_ns);
                }
            }
            Event::Exit { pid, timestamp_ns, .. } => {
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.running = false;
                    entry.touch(*timestamp_ns);
                }
            }
            Event::Bind { pid, addr, ret, timestamp_ns, .. } => {
                agent.bind_count += 1;
                agent.net_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.net_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if *ret >= 0 && is_external_addr(addr) {
                    agent.has_listener = true;
                }
            }
            Event::Listen { pid, timestamp_ns, .. } => {
                agent.bind_count += 1;
                agent.has_listener = true;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.net_count += 1;
                    entry.touch(*timestamp_ns);
                }
            }
            Event::Unlink { pid, filename, timestamp_ns, .. } => {
                agent.file_count += 1;
                agent.fs_mod_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(filename) {
                    agent.has_sensitive_files = true;
                    agent.has_sensitive_delete = true;
                }
            }
            Event::Rename { pid, old_path, new_path, timestamp_ns, .. } => {
                agent.file_count += 1;
                agent.fs_mod_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(old_path) || is_sensitive_path(new_path) {
                    agent.has_sensitive_files = true;
                }
            }
            Event::Chmod { pid, filename, timestamp_ns, .. } => {
                agent.file_count += 1;
                agent.fs_mod_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(filename) {
                    agent.has_sensitive_files = true;
                }
            }
            Event::Chown { pid, filename, timestamp_ns, .. } => {
                agent.file_count += 1;
                agent.fs_mod_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(filename) {
                    agent.has_sensitive_files = true;
                }
            }
            Event::Symlink { pid, target, linkpath, timestamp_ns, .. } => {
                agent.file_count += 1;
                agent.fs_mod_count += 1;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.file_count += 1;
                    entry.touch(*timestamp_ns);
                }
                if is_sensitive_path(target) || is_sensitive_path(linkpath) {
                    agent.has_sensitive_files = true;
                }
            }
            Event::Ptrace { pid, timestamp_ns, .. } => {
                agent.ptrace_count += 1;
                agent.has_ptrace = true;
                if let Some(entry) = agent.processes.get_mut(pid) {
                    entry.exec_count += 1;
                    entry.touch(*timestamp_ns);
                }
            }
        }

        agent.events.push_back(event);
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
        let processes = agent.process_list();

        // Aggregate files by path — includes openat, unlink, rename, chmod, chown, symlink
        struct FileFlags {
            acc: AccessAccumulator,
            modified: bool,
            deleted: bool,
            renamed: bool,
            perm_changed: bool,
            owner_changed: bool,
            is_symlink: bool,
        }
        impl FileFlags {
            fn new() -> Self {
                Self {
                    acc: AccessAccumulator::new(),
                    modified: false, deleted: false, renamed: false,
                    perm_changed: false, owner_changed: false, is_symlink: false,
                }
            }
        }
        let mut file_map: BTreeMap<String, FileFlags> = BTreeMap::new();
        for event in &agent.events {
            match event {
                Event::Openat { filename, comm, flags, ret, denied, timestamp_ns, .. } => {
                    let ff = file_map.entry(filename.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, *denied, *timestamp_ns);
                    ff.modified |= (flags & WRITE_FLAGS) != 0;
                }
                Event::Unlink { filename, comm, ret, timestamp_ns, .. } => {
                    let ff = file_map.entry(filename.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.deleted = true;
                }
                Event::Rename { old_path, new_path, comm, ret, timestamp_ns, .. } => {
                    let ff = file_map.entry(old_path.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.renamed = true;
                    let ff = file_map.entry(new_path.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.renamed = true;
                }
                Event::Chmod { filename, comm, ret, timestamp_ns, .. } => {
                    let ff = file_map.entry(filename.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.perm_changed = true;
                }
                Event::Chown { filename, comm, ret, timestamp_ns, .. } => {
                    let ff = file_map.entry(filename.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.owner_changed = true;
                }
                Event::Symlink { target, linkpath, comm, ret, timestamp_ns, .. } => {
                    // Record target path as a reference
                    let ff = file_map.entry(target.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    // Record linkpath with symlink flag
                    let ff = file_map.entry(linkpath.clone()).or_insert_with(FileFlags::new);
                    ff.acc.record(comm, *ret, false, *timestamp_ns);
                    ff.is_symlink = true;
                }
                _ => {}
            }
        }
        let mut files: Vec<FileAccess> = file_map
            .into_iter()
            .map(|(path, ff)| {
                let sensitive = is_sensitive_path(&path);
                let (count, errors, comms, denied, first_seen_ms, last_seen_ms) = ff.acc.into_parts();
                FileAccess {
                    path, count, errors, comms, sensitive,
                    modified: ff.modified, deleted: ff.deleted, renamed: ff.renamed,
                    perm_changed: ff.perm_changed, owner_changed: ff.owner_changed,
                    is_symlink: ff.is_symlink, denied,
                    first_seen_ms, last_seen_ms,
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

        // Aggregate connections by addr:port
        let mut conn_map: HashMap<(String, u16), AccessAccumulator> = HashMap::new();
        for event in &agent.events {
            if let Event::Connect { addr, port, comm, ret, timestamp_ns, .. } = event {
                conn_map.entry((addr.clone(), *port))
                    .or_insert_with(AccessAccumulator::new)
                    .record(comm, *ret, false, *timestamp_ns);
            }
        }
        let mut connections: Vec<ConnectionAccess> = conn_map
            .into_iter()
            .map(|((addr, port), acc)| {
                let external = is_external_addr(&addr);
                let (count, errors, comms, _denied, first_seen_ms, last_seen_ms) = acc.into_parts();
                ConnectionAccess {
                    addr, port, count, errors, comms, external,
                    hostname: None, country: None, city: None, asn: None,
                    first_seen_ms, last_seen_ms,
                }
            })
            .collect();
        connections.sort_by(|a, b| b.external.cmp(&a.external).then(b.count.cmp(&a.count)));

        // Aggregate Unix socket connections by path
        let mut unix_map: BTreeMap<String, AccessAccumulator> = BTreeMap::new();
        for event in &agent.events {
            if let Event::UnixConnect { path, comm, ret, timestamp_ns, .. } = event {
                unix_map.entry(path.clone())
                    .or_insert_with(AccessAccumulator::new)
                    .record(comm, *ret, false, *timestamp_ns);
            }
        }
        let mut unix_sockets: Vec<UnixSocketAccess> = unix_map
            .into_iter()
            .map(|(path, acc)| {
                let (count, errors, comms, _denied, first_seen_ms, last_seen_ms) = acc.into_parts();
                UnixSocketAccess {
                    path, count, errors, comms, first_seen_ms, last_seen_ms,
                }
            })
            .collect();
        unix_sockets.sort_by_key(|s| std::cmp::Reverse(s.count));

        // Aggregate bind events by addr:port (reuse ConnectionAccess)
        let mut bind_map: HashMap<(String, u16), AccessAccumulator> = HashMap::new();
        for event in &agent.events {
            if let Event::Bind { addr, port, comm, ret, timestamp_ns, .. } = event {
                bind_map.entry((addr.clone(), *port))
                    .or_insert_with(AccessAccumulator::new)
                    .record(comm, *ret, false, *timestamp_ns);
            }
        }
        let mut binds: Vec<ConnectionAccess> = bind_map
            .into_iter()
            .map(|((addr, port), acc)| {
                let external = is_external_addr(&addr);
                let (count, errors, comms, _denied, first_seen_ms, last_seen_ms) = acc.into_parts();
                ConnectionAccess {
                    addr, port, count, errors, comms, external,
                    hostname: None, country: None, city: None, asn: None,
                    first_seen_ms, last_seen_ms,
                }
            })
            .collect();
        binds.sort_by(|a, b| b.external.cmp(&a.external).then(b.count.cmp(&a.count)));

        let summary = agent.summary();

        Some(AgentDetail {
            root_pid: agent.root_pid,
            root_comm: agent.root_comm.clone(),
            processes,
            files,
            connections,
            binds,
            unix_sockets,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u32 = 100;
    const TS: u64 = 1_000_000_000; // 1 second in ns

    fn new_store_with_root() -> EventStore {
        let mut store = EventStore::new();
        store.push(ROOT, Event::Execve {
            pid: ROOT,
            root_pid: ROOT,
            uid: 1000,
            comm: "claude".into(),
            filename: "/usr/bin/claude".into(),
            timestamp_ns: TS,
        });
        store
    }

    #[test]
    fn sensitive_file_write_detection() {
        let mut store = new_store_with_root();

        // Write to sensitive path → both flags
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/home/user/.ssh/id_rsa".into(),
            flags: 0x1, // O_WRONLY
            ret: 3, timestamp_ns: TS + 1, denied: false,
        });
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(summary.has_sensitive_writes);

        // Fresh store: read-only access to sensitive path → sensitive but not write
        let mut store = new_store_with_root();
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/home/user/.ssh/id_rsa".into(),
            flags: 0x0, // O_RDONLY
            ret: 3, timestamp_ns: TS + 1, denied: false,
        });
        let summary = &store.agents_summary()[0];
        assert!(summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);

        // Fresh store: write to non-sensitive path → neither flag
        let mut store = new_store_with_root();
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/tmp/scratch.txt".into(),
            flags: 0x1, // O_WRONLY
            ret: 3, timestamp_ns: TS + 1, denied: false,
        });
        let summary = &store.agents_summary()[0];
        assert!(!summary.has_sensitive_files);
        assert!(!summary.has_sensitive_writes);
    }

    #[test]
    fn external_network_detection() {
        // External address → flagged
        let mut store = new_store_with_root();
        store.push(ROOT, Event::Connect {
            pid: ROOT, comm: "curl".into(),
            addr: "8.8.8.8".into(), port: 443, ret: 0, timestamp_ns: TS + 1,
        });
        assert!(store.agents_summary()[0].has_external_net);

        // Loopback only → not flagged
        let mut store = new_store_with_root();
        store.push(ROOT, Event::Connect {
            pid: ROOT, comm: "curl".into(),
            addr: "127.0.0.1".into(), port: 8080, ret: 0, timestamp_ns: TS + 1,
        });
        assert!(!store.agents_summary()[0].has_external_net);
    }

    #[test]
    fn process_tree_lifecycle() {
        let mut store = new_store_with_root();

        // Fork child
        store.push(ROOT, Event::Fork {
            parent_pid: ROOT, child_pid: 200,
            comm: "claude".into(), timestamp_ns: TS + 1,
        });

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).expect("child should exist");
        assert_eq!(child.parent_pid, Some(ROOT));
        assert!(child.running);
        assert_eq!(child.comm, "claude");

        // Exec replaces child image
        store.push(ROOT, Event::Execve {
            pid: 200, root_pid: ROOT, uid: 1000,
            comm: "curl".into(), filename: "/usr/bin/curl".into(),
            timestamp_ns: TS + 2,
        });

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert_eq!(child.comm, "curl");
        assert_eq!(child.exec_count, 1);

        // Child exits
        store.push(ROOT, Event::Exit {
            pid: 200, comm: "curl".into(), timestamp_ns: TS + 3,
        });

        let detail = store.agent_detail(ROOT).unwrap();
        let child = detail.processes.iter().find(|p| p.pid == 200).unwrap();
        assert!(!child.running);

        // Root is still running, child exited
        assert_eq!(detail.summary.running_count, 1);
        assert_eq!(detail.summary.exited_count, 1);
    }

    #[test]
    fn multiple_agents_isolated() {
        let mut store = EventStore::new();
        let root_a: u32 = 100;
        let root_b: u32 = 200;

        store.push(root_a, Event::Execve {
            pid: root_a, root_pid: root_a, uid: 1000,
            comm: "agent_a".into(), filename: "/bin/a".into(),
            timestamp_ns: TS,
        });
        store.push(root_b, Event::Execve {
            pid: root_b, root_pid: root_b, uid: 1000,
            comm: "agent_b".into(), filename: "/bin/b".into(),
            timestamp_ns: TS,
        });

        // File access under agent A only
        store.push(root_a, Event::Openat {
            pid: root_a, comm: "agent_a".into(),
            filename: "/tmp/a.txt".into(),
            flags: 0, ret: 3, timestamp_ns: TS + 1, denied: false,
        });

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
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/etc/config".into(),
            flags: 0, ret: 3, timestamp_ns: TS + 1, denied: false,
        });
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/etc/config".into(),
            flags: 0, ret: 4, timestamp_ns: TS + 2, denied: false,
        });
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "cat".into(),
            filename: "/etc/config".into(),
            flags: 0, ret: -2, timestamp_ns: TS + 3, denied: false, // ENOENT
        });

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
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/tmp/harmless.txt".into(),
            flags: 0, ret: 3, timestamp_ns: TS + 1, denied: false,
        });
        store.push(ROOT, Event::Openat {
            pid: ROOT, comm: "claude".into(),
            filename: "/home/user/.ssh/authorized_keys".into(),
            flags: 0, ret: 3, timestamp_ns: TS + 2, denied: false,
        });

        let detail = store.agent_detail(ROOT).unwrap();
        assert!(detail.files[0].sensitive, "sensitive files should sort first");
        assert!(!detail.files[1].sensitive);

        // External connection + loopback
        store.push(ROOT, Event::Connect {
            pid: ROOT, comm: "curl".into(),
            addr: "127.0.0.1".into(), port: 8080, ret: 0, timestamp_ns: TS + 3,
        });
        store.push(ROOT, Event::Connect {
            pid: ROOT, comm: "curl".into(),
            addr: "93.184.216.34".into(), port: 443, ret: 0, timestamp_ns: TS + 4,
        });

        let detail = store.agent_detail(ROOT).unwrap();
        assert!(detail.connections[0].external, "external connections should sort first");
        assert!(!detail.connections[1].external);
    }
}
