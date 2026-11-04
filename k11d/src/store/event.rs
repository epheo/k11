//! What the probe saw, decoded: one event, and how it reads to people.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::classify::{error, failed, is_exposed, is_external, is_sensitive_path, ptrace_request};
use crate::cmdline::CommandLine;
use crate::container::Container;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Fields shared by every event, mirroring the probe's `EventHeader`.
/// `root_pid` makes each event attributable to its agent tree on its own.
#[derive(Clone)]
pub struct EventMeta {
    /// Decode order, from 1; unique per daemon run.
    pub seq: u64,
    /// Acting process (for fork: the parent).
    pub pid: u32,
    pub root_pid: u32,
    pub uid: u32,
    /// Interned by the decoder: one allocation per distinct name, not per event.
    pub comm: Arc<str>,
    /// Wall-clock epoch nanoseconds.
    pub timestamp_ns: u64,
    /// Syscall result: fd or 0 on success, negative errno on failure. Zero
    /// for fork, exit and a successful exec.
    pub ret: i32,
    /// None on the host or in a VM.
    pub container: Option<Arc<Container>>,
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
        /// None for a failed exec, and where BTF lacks what it needs.
        cmd_line: Option<Arc<CommandLine>>,
    },
    Open {
        filename: String,
        flags: i32,
        policy: Policy,
    },
    Connect {
        addr: SocketAddr,
    },
    /// A connect libc made while resolving a name: kept in the record, but
    /// the resolver at work, not a connection the program asked for.
    ResolverConnect {
        addr: SocketAddr,
    },
    UnixConnect {
        path: String,
    },
    Fork {
        child_pid: u32,
    },
    Exit,
    Bind {
        addr: SocketAddr,
    },
    Listen {
        backlog: i32,
    },
    Unlink {
        filename: String,
        flags: i32,
    },
    Rename {
        old_path: String,
        new_path: String,
    },
    Chmod {
        filename: String,
        mode: u32,
    },
    Chown {
        filename: String,
        owner_uid: u32,
        owner_gid: u32,
    },
    Symlink {
        target: String,
        linkpath: String,
    },
    Ptrace {
        request: u32,
        target_pid: u32,
    },
    /// A name looked up through libc; no addresses when it failed.
    Resolve {
        name: String,
        addrs: Vec<IpAddr>,
    },
}

impl Event {
    pub fn policy(&self) -> Policy {
        match self.payload {
            Payload::Open { policy, .. } => policy,
            _ => Policy::Allowed,
        }
    }

    pub fn is_denied(&self) -> bool {
        self.policy() == Policy::Denied
    }

    /// The syscall failed on its own, not because k11 denied it.
    pub fn is_error(&self) -> bool {
        !self.is_denied() && failed(self.meta.ret)
    }

    /// Filesystem paths this event names.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        let (a, b): (Option<&str>, Option<&str>) = match &self.payload {
            Payload::Execve { filename, .. }
            | Payload::Open { filename, .. }
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

    /// A connect leaving this machine's networks, or a bind other hosts can reach.
    pub fn is_external(&self) -> bool {
        match self.payload {
            Payload::Connect { addr } => is_external(addr.ip()),
            Payload::Bind { addr } => is_exposed(addr.ip(), addr.port()),
            _ => false,
        }
    }

    /// One line for people: what the process did, then how it ended when
    /// that is not plain success. Shared by logs, OCSF and the dashboard.
    pub fn describe(&self) -> String {
        let comm = &self.meta.comm;
        let mut s = match &self.payload {
            Payload::Execve { filename, cmd_line } => {
                match cmd_line.as_ref().map(|c| c.arguments()) {
                    Some(args) if !args.is_empty() => format!("{comm} exec {filename} {args}"),
                    _ => format!("{comm} exec {filename}"),
                }
            }
            Payload::Open { filename, .. } => format!("{comm} open {filename}"),
            Payload::Connect { addr } => format!("{comm} connect {addr}"),
            Payload::ResolverConnect { addr } => format!("{comm} connect {addr} (resolving)"),
            Payload::UnixConnect { path } => format!("{comm} connect unix:{path}"),
            Payload::Fork { child_pid } => format!("{comm} fork {child_pid}"),
            Payload::Exit => format!("{comm} exit"),
            Payload::Bind { addr } => format!("{comm} bind {addr}"),
            Payload::Listen { backlog } => format!("{comm} listen (backlog {backlog})"),
            Payload::Unlink { filename, .. } => format!("{comm} unlink {filename}"),
            Payload::Rename { old_path, new_path } => {
                format!("{comm} rename {old_path} to {new_path}")
            }
            Payload::Chmod { filename, mode } => format!("{comm} chmod {mode:o} {filename}"),
            Payload::Chown {
                filename,
                owner_uid,
                owner_gid,
            } => format!("{comm} chown {owner_uid}:{owner_gid} {filename}"),
            Payload::Symlink { target, linkpath } => {
                format!("{comm} symlink {linkpath} to {target}")
            }
            Payload::Ptrace {
                request,
                target_pid,
            } => format!("{comm} ptrace {} {target_pid}", ptrace_request(*request)),
            Payload::Resolve { name, addrs } if addrs.is_empty() => {
                format!("{comm} resolve {name}: not found")
            }
            Payload::Resolve { name, addrs } => {
                let addrs: Vec<String> = addrs.iter().map(IpAddr::to_string).collect();
                format!("{comm} resolve {name}: {}", addrs.join(", "))
            }
        };
        match self.policy() {
            Policy::Denied => s.push_str(": denied by k11"),
            Policy::Audited => s.push_str(": deny rule matched (audit)"),
            Policy::Allowed => {
                if let Some(errno) = error(self.meta.ret) {
                    s.push_str(": ");
                    s.push_str(&errno);
                }
            }
        }
        s
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.meta;
        write!(f, "pid={} root={} {}", m.pid, m.root_pid, self.describe())
    }
}
