use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use aya::maps::RingBuf;
use k11_common::{
    ChownEvent, ConnectEvent, EventHeader, ExecveEvent, ExitEvent, ForkEvent, ListenEvent,
    OpenatEvent, PtraceEvent, RenameEvent, UnixConnectEvent,
    EVENT_BIND, EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT,
    EVENT_DENY_OPENAT, EVENT_EXECVE, EVENT_EXIT,
    EVENT_FORK, EVENT_LISTEN, EVENT_OPENAT, EVENT_PTRACE, EVENT_RENAME, EVENT_SYMLINK,
    EVENT_UNLINK, EVENT_UNIX_CONNECT,
};
use tracing::{debug, trace, warn};

use crate::store::{Event, EventMeta, EventStore, Payload};

fn bytes_to_str(bytes: &[u8]) -> &str {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).unwrap_or("<invalid utf8>")
}

fn meta_from(header: &EventHeader) -> EventMeta {
    EventMeta {
        pid: header.pid,
        root_pid: header.root_pid,
        uid: header.uid,
        comm: bytes_to_str(&header.comm).to_string(),
        timestamp_ns: header.timestamp_ns,
    }
}

// ---------------------------------------------------------------------------
// Ring buffer drain + dispatch
// ---------------------------------------------------------------------------

pub fn drain_events(
    ring_buf: &mut RingBuf<&mut aya::maps::MapData>,
    store: &Arc<Mutex<EventStore>>,
    event_tx: &tokio::sync::broadcast::Sender<Event>,
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

/// Validates size, reads the raw struct, decodes it via `f`,
/// logs the result, and pushes it to the store + event broadcast.
fn dispatch<T: Copy>(
    bytes: &[u8],
    store: &Arc<Mutex<EventStore>>,
    event_tx: &tokio::sync::broadcast::Sender<Event>,
    boot_offset_ns: u64,
    f: fn(&T) -> Event,
) {
    if bytes.len() < size_of::<T>() {
        return;
    }
    let raw: T = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
    let mut event = f(&raw);

    event.adjust_timestamp(boot_offset_ns);

    if event.is_denied() {
        warn!("{event}");
    } else if event.is_error() {
        debug!("{event}");
    } else {
        trace!("{event}");
    }

    let _ = event_tx.send(event.clone());
    store.lock().unwrap().push(event);
}

// ---------------------------------------------------------------------------
// Per-event decoders — pure functions, no I/O (except resolve_path)
// ---------------------------------------------------------------------------

fn decode_execve(raw: &ExecveEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Execve {
            filename: bytes_to_str(&raw.filename).to_string(),
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

fn decode_openat(raw: &OpenatEvent) -> Event {
    decode_openat_inner(raw, false)
}

fn decode_deny_openat(raw: &OpenatEvent) -> Event {
    decode_openat_inner(raw, true)
}

fn decode_openat_inner(raw: &OpenatEvent, denied: bool) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Openat {
            filename: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.filename)),
            flags: raw.flags,
            ret: raw.ret,
            denied,
        },
        meta,
    }
}

fn decode_connect(raw: &ConnectEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Connect {
            addr: format_addr(raw),
            port: raw.port,
            ret: raw.ret,
        },
    }
}

fn decode_unix_connect(raw: &UnixConnectEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::UnixConnect {
            path: bytes_to_str(&raw.path).to_string(),
            ret: raw.ret,
        },
    }
}

fn decode_fork(raw: &ForkEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Fork {
            child_pid: raw.child_pid,
        },
    }
}

fn decode_exit(raw: &ExitEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Exit,
    }
}

fn decode_bind(raw: &ConnectEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Bind {
            addr: format_addr(raw),
            port: raw.port,
            ret: raw.ret,
        },
    }
}

fn decode_listen(raw: &ListenEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Listen {
            backlog: raw.backlog,
            ret: raw.ret,
        },
    }
}

fn decode_unlink(raw: &OpenatEvent) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Unlink {
            filename: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.filename)),
            flags: raw.flags,
            ret: raw.ret,
        },
        meta,
    }
}

fn decode_rename(raw: &RenameEvent) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Rename {
            old_path: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.old_path)),
            new_path: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.new_path)),
            ret: raw.ret,
        },
        meta,
    }
}

fn decode_chmod(raw: &OpenatEvent) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Chmod {
            filename: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.filename)),
            mode: raw.flags as u32, // mode stored in flags field
            ret: raw.ret,
        },
        meta,
    }
}

fn decode_chown(raw: &ChownEvent) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Chown {
            filename: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.filename)),
            owner_uid: raw.owner_uid,
            owner_gid: raw.owner_gid,
            ret: raw.ret,
        },
        meta,
    }
}

fn decode_symlink(raw: &RenameEvent) -> Event {
    let meta = meta_from(&raw.header);
    Event {
        payload: Payload::Symlink {
            target: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.old_path)),
            linkpath: resolve_path(meta.pid, meta.root_pid, bytes_to_str(&raw.new_path)),
            ret: raw.ret,
        },
        meta,
    }
}

fn decode_ptrace(raw: &PtraceEvent) -> Event {
    Event {
        meta: meta_from(&raw.header),
        payload: Payload::Ptrace {
            request: raw.request,
            target_pid: raw.target_pid,
            ret: raw.ret,
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
