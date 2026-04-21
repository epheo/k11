use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use aya::maps::RingBuf;
use k11_common::{
    ChownEvent, ConnectEvent, ExecveEvent, ExitEvent, ForkEvent, ListenEvent, OpenatEvent,
    PtraceEvent, RenameEvent, UnixConnectEvent,
    EVENT_BIND, EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT,
    EVENT_DENY_OPENAT, EVENT_EXECVE, EVENT_EXIT,
    EVENT_FORK, EVENT_LISTEN, EVENT_OPENAT, EVENT_PTRACE, EVENT_RENAME, EVENT_SYMLINK,
    EVENT_UNLINK, EVENT_UNIX_CONNECT,
};
use tracing::{debug, trace, warn};

use crate::store::{self, EventStore};

fn bytes_to_str(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).unwrap_or("<invalid utf8>")
}

// ---------------------------------------------------------------------------
// Ring buffer drain + dispatch
// ---------------------------------------------------------------------------

pub fn drain_events(
    ring_buf: &mut RingBuf<&mut aya::maps::MapData>,
    store: &Arc<Mutex<EventStore>>,
    event_tx: &tokio::sync::broadcast::Sender<store::Event>,
    boot_offset_ns: u64,
) {
    while let Some(item) = ring_buf.next() {
        let bytes: &[u8] = &item;
        if bytes.len() < 4 {
            continue;
        }

        let event_type = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        match event_type {
            EVENT_EXECVE => dispatch::<ExecveEvent>(bytes, store, event_tx, boot_offset_ns, decode_execve),
            EVENT_OPENAT => dispatch::<OpenatEvent>(bytes, store, event_tx, boot_offset_ns, decode_openat),
            EVENT_CONNECT => dispatch::<ConnectEvent>(bytes, store, event_tx, boot_offset_ns, decode_connect),
            EVENT_UNIX_CONNECT => dispatch::<UnixConnectEvent>(bytes, store, event_tx, boot_offset_ns, decode_unix_connect),
            EVENT_FORK => dispatch::<ForkEvent>(bytes, store, event_tx, boot_offset_ns, decode_fork),
            EVENT_EXIT => dispatch::<ExitEvent>(bytes, store, event_tx, boot_offset_ns, decode_exit),
            EVENT_DENY_OPENAT => dispatch::<OpenatEvent>(bytes, store, event_tx, boot_offset_ns, decode_deny_openat),
            EVENT_BIND => dispatch::<ConnectEvent>(bytes, store, event_tx, boot_offset_ns, decode_bind),
            EVENT_LISTEN => dispatch::<ListenEvent>(bytes, store, event_tx, boot_offset_ns, decode_listen),
            EVENT_UNLINK => dispatch::<OpenatEvent>(bytes, store, event_tx, boot_offset_ns, decode_unlink),
            EVENT_RENAME => dispatch::<RenameEvent>(bytes, store, event_tx, boot_offset_ns, decode_rename),
            EVENT_CHMOD => dispatch::<OpenatEvent>(bytes, store, event_tx, boot_offset_ns, decode_chmod),
            EVENT_CHOWN => dispatch::<ChownEvent>(bytes, store, event_tx, boot_offset_ns, decode_chown),
            EVENT_SYMLINK => dispatch::<RenameEvent>(bytes, store, event_tx, boot_offset_ns, decode_symlink),
            EVENT_PTRACE => dispatch::<PtraceEvent>(bytes, store, event_tx, boot_offset_ns, decode_ptrace),
            _ => warn!(event_type, "unknown event type"),
        }
    }
}

/// Decoded result from an eBPF event: the data needed for storage.
struct Decoded {
    root_pid: u32,
    event: store::Event,
}

/// Validates size, reads the raw struct, decodes it via `f`,
/// logs the result, and pushes it to the store + event broadcast.
fn dispatch<T: Copy>(
    bytes: &[u8],
    store: &Arc<Mutex<EventStore>>,
    event_tx: &tokio::sync::broadcast::Sender<store::Event>,
    boot_offset_ns: u64,
    f: fn(&T) -> Decoded,
) {
    if bytes.len() < size_of::<T>() {
        return;
    }
    let raw: T = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
    let mut decoded = f(&raw);

    decoded.event.adjust_timestamp(boot_offset_ns);

    if decoded.event.is_denied() {
        warn!("{}", decoded.event);
    } else if decoded.event.is_error() {
        debug!("{}", decoded.event);
    } else {
        trace!("{}", decoded.event);
    }

    let _ = event_tx.send(decoded.event.clone());
    store.lock().unwrap().push(decoded.root_pid, decoded.event);
}

// ---------------------------------------------------------------------------
// Per-event decoders — pure functions, no I/O
// ---------------------------------------------------------------------------

fn decode_execve(raw: &ExecveEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Execve {
            pid: raw.header.pid,
            root_pid: raw.header.root_pid,
            uid: raw.header.uid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            filename: bytes_to_str(&raw.filename).to_string(),
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

/// Resolve relative paths by reading /proc/<pid>/cwd.
/// Falls back to the root agent process CWD if the child already exited.
fn resolve_path(pid: u32, root_pid: u32, filename: &str) -> String {
    if filename.starts_with('/') || filename.is_empty() {
        return filename.to_string();
    }
    for try_pid in [pid, root_pid] {
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", try_pid)) {
            return format!("{}/{}", cwd.display(), filename);
        }
    }
    filename.to_string()
}

fn decode_openat(raw: &OpenatEvent) -> Decoded {
    decode_openat_inner(raw, false)
}

fn decode_deny_openat(raw: &OpenatEvent) -> Decoded {
    decode_openat_inner(raw, true)
}

fn decode_openat_inner(raw: &OpenatEvent, denied: bool) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Openat {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            filename: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.filename)),
            flags: raw.flags,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
            denied,
        },
    }
}

fn decode_connect(raw: &ConnectEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Connect {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            addr: format_addr(raw),
            port: raw.port,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_unix_connect(raw: &UnixConnectEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::UnixConnect {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            path: bytes_to_str(&raw.path).to_string(),
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_fork(raw: &ForkEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Fork {
            parent_pid: raw.header.pid,
            child_pid: raw.child_pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_exit(raw: &ExitEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Exit {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

// ---------------------------------------------------------------------------
// Tier 1+2 decoders
// ---------------------------------------------------------------------------

fn decode_bind(raw: &ConnectEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Bind {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            addr: format_addr(raw),
            port: raw.port,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_listen(raw: &ListenEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Listen {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            backlog: raw.backlog,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_unlink(raw: &OpenatEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Unlink {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            filename: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.filename)),
            flags: raw.flags,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_rename(raw: &RenameEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Rename {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            old_path: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.old_path)),
            new_path: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.new_path)),
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_chmod(raw: &OpenatEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Chmod {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            filename: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.filename)),
            mode: raw.flags as u32, // mode stored in flags field
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_chown(raw: &ChownEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Chown {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            filename: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.filename)),
            owner_uid: raw.owner_uid,
            owner_gid: raw.owner_gid,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_symlink(raw: &RenameEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Symlink {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            target: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.old_path)),
            linkpath: resolve_path(raw.header.pid, raw.header.root_pid, bytes_to_str(&raw.new_path)),
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn decode_ptrace(raw: &PtraceEvent) -> Decoded {
    Decoded {
        root_pid: raw.header.root_pid,
        event: store::Event::Ptrace {
            pid: raw.header.pid,
            comm: bytes_to_str(&raw.header.comm).to_string(),
            request: raw.request,
            target_pid: raw.target_pid,
            ret: raw.ret,
            timestamp_ns: raw.header.timestamp_ns,
        },
    }
}

fn format_addr(event: &ConnectEvent) -> String {
    match event.af {
        k11_common::AF_INET => {
            let ip = Ipv4Addr::from(event.addr_v4.to_be());
            format!("{ip}")
        }
        k11_common::AF_INET6 => {
            let ip = Ipv6Addr::from(event.addr_v6);
            format!("[{ip}]")
        }
        af => format!("af={af}"),
    }
}
