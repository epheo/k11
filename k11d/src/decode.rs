//! Ring buffer records to `store::Event`.
//!
//! A record is a prefix of one `RawEvent` variant (strings are trimmed after
//! the NUL). Decoding copies it into a zeroed `RawEvent`, so every string is
//! terminated and every untouched field reads as zero.

use std::collections::HashMap;
use std::mem::{offset_of, size_of, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use aya::maps::{MapData, RingBuf};
use k11_common::{
    ChownEvent, ConnectEvent, EventHeader, ExitEvent, ForkEvent, ListenEvent, PathEvent,
    PathPairEvent, PtraceEvent, RawEvent, UnixConnectEvent, AF_INET, AF_INET6, AT_FDCWD, COMM_LEN,
    EVENT_BIND, EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT, EVENT_EXECVE, EVENT_EXIT, EVENT_FORK,
    EVENT_LISTEN, EVENT_OPEN, EVENT_OPEN_AUDITED, EVENT_OPEN_DENIED, EVENT_PTRACE, EVENT_RENAME,
    EVENT_SYMLINK, EVENT_UNIX_CONNECT, EVENT_UNLINK, MAX_EVENT_SIZE,
};
use tracing::{debug, trace, warn};

use crate::store::{Event, EventMeta, Payload, Policy};

/// Distinct comms seen before the intern table is reset. Comm churn is
/// bounded by binaries on the host, so this is a safety net, not a policy.
const MAX_INTERNED_COMMS: usize = 4096;

pub struct Decoder {
    boot_offset_ns: u64,
    comms: HashMap<[u8; COMM_LEN], Arc<str>>,
    seq: u64,
}

impl Decoder {
    /// Wall-clock nanoseconds at boot, so probe timestamps (CLOCK_BOOTTIME)
    /// become epoch time. Computed once from two clock reads.
    pub fn new() -> Self {
        Self {
            boot_offset_ns: wall_at_boot_ns(),
            comms: HashMap::new(),
            seq: 0,
        }
    }

    #[cfg(test)]
    pub fn with_boot_offset(boot_offset_ns: u64) -> Self {
        Self {
            boot_offset_ns,
            comms: HashMap::new(),
            seq: 0,
        }
    }

    /// Decode every record currently in the ring into `out`.
    pub fn drain(&mut self, ring: &mut RingBuf<MapData>, out: &mut Vec<Arc<Event>>) {
        while let Some(item) = ring.next() {
            if let Some(event) = self.decode(&item) {
                if event.is_denied() {
                    warn!("{event}");
                } else if event.is_error() {
                    debug!("{event}");
                } else {
                    trace!("{event}");
                }
                out.push(Arc::new(event));
            }
        }
    }

    pub fn decode(&mut self, bytes: &[u8]) -> Option<Event> {
        if bytes.len() < size_of::<EventHeader>() || bytes.len() > MAX_EVENT_SIZE {
            warn!(len = bytes.len(), "malformed ring record");
            return None;
        }
        // Zero-filled so a trimmed record still has terminated strings.
        let raw = unsafe {
            let mut raw = MaybeUninit::<RawEvent>::zeroed();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw.as_mut_ptr() as *mut u8, bytes.len());
            raw.assume_init()
        };
        let header = unsafe { raw.header };
        let min_len = min_len(header.event_type)?;
        if bytes.len() < min_len {
            warn!(
                event_type = header.event_type,
                len = bytes.len(),
                min_len,
                "truncated ring record"
            );
            return None;
        }

        self.seq += 1;
        let meta = EventMeta {
            seq: self.seq,
            pid: header.pid,
            root_pid: header.root_pid,
            uid: header.uid,
            comm: self.intern(&header.comm),
            timestamp_ns: header.timestamp_ns.saturating_add(self.boot_offset_ns),
            ret: header.ret,
        };
        let pid = meta.pid;
        let path = || {
            let p = unsafe { &raw.path };
            (resolve_path(pid, p.dfd, cstr(&p.path)), p.flags)
        };

        let payload = match header.event_type {
            EVENT_EXECVE => Payload::Execve { filename: path().0 },
            EVENT_OPEN | EVENT_OPEN_DENIED | EVENT_OPEN_AUDITED => {
                let (filename, flags) = path();
                Payload::Open {
                    filename,
                    flags,
                    policy: match header.event_type {
                        EVENT_OPEN_DENIED => Policy::Denied,
                        EVENT_OPEN_AUDITED => Policy::Audited,
                        _ => Policy::Allowed,
                    },
                }
            }
            EVENT_UNLINK => {
                let (filename, flags) = path();
                Payload::Unlink { filename, flags }
            }
            EVENT_CHMOD => {
                let (filename, mode) = path();
                Payload::Chmod {
                    filename,
                    mode: mode as u32,
                }
            }
            EVENT_RENAME => {
                let p = unsafe { &raw.pair };
                let (old, new) = pair(&p.paths);
                Payload::Rename {
                    old_path: resolve_path(pid, p.dfd, old),
                    new_path: resolve_path(pid, p.dfd2, new),
                }
            }
            EVENT_SYMLINK => {
                // The target is stored verbatim in the link; only the link
                // path is resolved.
                let p = unsafe { &raw.pair };
                let (target, link) = pair(&p.paths);
                Payload::Symlink {
                    target,
                    linkpath: resolve_path(pid, p.dfd2, link),
                }
            }
            EVENT_CHOWN => {
                let p = unsafe { &raw.chown };
                Payload::Chown {
                    filename: resolve_path(pid, p.dfd, cstr(&p.path)),
                    owner_uid: p.owner_uid,
                    owner_gid: p.owner_gid,
                }
            }
            EVENT_CONNECT => Payload::Connect {
                addr: socket_addr(unsafe { &raw.connect })?,
            },
            EVENT_BIND => Payload::Bind {
                addr: socket_addr(unsafe { &raw.connect })?,
            },
            EVENT_UNIX_CONNECT => Payload::UnixConnect {
                path: cstr(unsafe { &raw.unix.path }),
            },
            EVENT_FORK => Payload::Fork {
                child_pid: unsafe { raw.fork.child_pid },
            },
            EVENT_EXIT => Payload::Exit,
            EVENT_LISTEN => Payload::Listen {
                backlog: unsafe { raw.listen.backlog },
            },
            EVENT_PTRACE => {
                let p = unsafe { &raw.ptrace };
                Payload::Ptrace {
                    request: p.request,
                    target_pid: p.target_pid,
                }
            }
            _ => unreachable!("min_len rejected unknown event types"),
        };

        Some(Event { meta, payload })
    }

    fn intern(&mut self, comm: &[u8; COMM_LEN]) -> Arc<str> {
        if let Some(c) = self.comms.get(comm) {
            return Arc::clone(c);
        }
        if self.comms.len() >= MAX_INTERNED_COMMS {
            self.comms.clear();
        }
        let c: Arc<str> = Arc::from(cstr(comm));
        self.comms.insert(*comm, Arc::clone(&c));
        c
    }
}

/// Smallest valid record per type: fixed structs whole, string-bearing
/// structs up to and including one byte of string.
fn min_len(event_type: u32) -> Option<usize> {
    Some(match event_type {
        EVENT_EXECVE | EVENT_OPEN | EVENT_OPEN_DENIED | EVENT_OPEN_AUDITED | EVENT_UNLINK
        | EVENT_CHMOD => offset_of!(PathEvent, path) + 1,
        EVENT_RENAME | EVENT_SYMLINK => offset_of!(PathPairEvent, paths) + 2,
        EVENT_CHOWN => offset_of!(ChownEvent, path) + 1,
        EVENT_CONNECT | EVENT_BIND => size_of::<ConnectEvent>(),
        EVENT_UNIX_CONNECT => offset_of!(UnixConnectEvent, path) + 1,
        EVENT_FORK => size_of::<ForkEvent>(),
        EVENT_EXIT => size_of::<ExitEvent>(),
        EVENT_LISTEN => size_of::<ListenEvent>(),
        EVENT_PTRACE => size_of::<PtraceEvent>(),
        other => {
            warn!(event_type = other, "unknown event type");
            return None;
        }
    })
}

/// Bytes up to the first NUL, lossily decoded: Linux paths are bytes and a
/// non-UTF-8 name must survive into the record.
fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Two NUL-terminated strings packed back to back.
fn pair(bytes: &[u8]) -> (String, String) {
    let first_end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let rest = bytes.get(first_end + 1..).unwrap_or(&[]);
    (cstr(&bytes[..first_end]), cstr(rest))
}

/// Make a relative path absolute against the directory it was relative to;
/// an empty path names the directory fd itself (`AT_EMPTY_PATH`). Successful
/// opens never get here: the LSM hook records the kernel-resolved path. This
/// read races the process, so a failure leaves the path as requested.
fn resolve_path(pid: u32, dfd: i32, path: String) -> String {
    if path.starts_with('/') || (path.is_empty() && dfd == AT_FDCWD) {
        return path;
    }
    let base = if dfd == AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dfd}")
    };
    match std::fs::read_link(&base) {
        Ok(dir) if path.is_empty() => dir.to_string_lossy().into_owned(),
        Ok(dir) => dir.join(&path).to_string_lossy().into_owned(),
        Err(_) => path,
    }
}

fn socket_addr(c: &ConnectEvent) -> Option<SocketAddr> {
    let ip = match c.af {
        AF_INET => IpAddr::V4(Ipv4Addr::from([c.addr[0], c.addr[1], c.addr[2], c.addr[3]])),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(c.addr)),
        af => {
            warn!(af, "connect record with an unexpected address family");
            return None;
        }
    };
    Some(SocketAddr::new(ip, c.port))
}

/// Epoch nanoseconds at the instant CLOCK_BOOTTIME was zero. Both clocks are
/// read back to back; the gap between the reads is the only error.
fn wall_at_boot_ns() -> u64 {
    fn clock_ns(id: libc::clockid_t) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: ts is a valid out-pointer; both clock ids exist on every Linux.
        unsafe { libc::clock_gettime(id, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    let boot = clock_ns(libc::CLOCK_BOOTTIME);
    let real = clock_ns(libc::CLOCK_REALTIME);
    real.saturating_sub(boot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k11_common::{PATH_LEN, UNIX_PATH_LEN};

    fn header(event_type: u32, ret: i32, len: usize) -> EventHeader {
        let mut comm = [0u8; COMM_LEN];
        comm[..5].copy_from_slice(b"claud");
        EventHeader {
            event_type,
            pid: 42,
            root_pid: 7,
            uid: 1000,
            timestamp_ns: 5,
            comm,
            ret,
            len: len as u32,
        }
    }

    fn bytes_of<T>(v: &T, len: usize) -> Vec<u8> {
        let all = unsafe { std::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>()) };
        all[..len].to_vec()
    }

    fn decoder() -> Decoder {
        Decoder::with_boot_offset(1_000)
    }

    #[test]
    fn decodes_trimmed_path_record() {
        let mut ev = PathEvent {
            header: header(EVENT_OPEN, 3, 0),
            flags: 0x241,
            dfd: AT_FDCWD,
            path: [0; PATH_LEN],
        };
        ev.path[..8].copy_from_slice(b"/etc/hos");
        let len = offset_of!(PathEvent, path) + 9;
        ev.header.len = len as u32;
        let event = decoder().decode(&bytes_of(&ev, len)).unwrap();
        assert_eq!(event.meta.pid, 42);
        assert_eq!(event.meta.root_pid, 7);
        assert_eq!(&*event.meta.comm, "claud");
        assert_eq!(event.meta.timestamp_ns, 1_005);
        assert_eq!(event.meta.ret, 3);
        assert_eq!(event.meta.seq, 1);
        match event.payload {
            Payload::Open {
                filename,
                flags,
                policy,
            } => {
                assert_eq!(filename, "/etc/hos");
                assert_eq!(flags, 0x241);
                assert_eq!(policy, Policy::Allowed);
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn policy_comes_from_event_type() {
        let mut ev = PathEvent {
            header: header(EVENT_OPEN_DENIED, -1, 0),
            flags: 0,
            dfd: AT_FDCWD,
            path: [0; PATH_LEN],
        };
        ev.path[..2].copy_from_slice(b"/x");
        let len = offset_of!(PathEvent, path) + 3;
        let event = decoder().decode(&bytes_of(&ev, len)).unwrap();
        assert_eq!(event.policy(), Policy::Denied);
        assert!(event.is_denied());
        assert!(!event.is_error());

        ev.header.event_type = EVENT_OPEN_AUDITED;
        ev.header.ret = 0;
        let event = decoder().decode(&bytes_of(&ev, len)).unwrap();
        assert_eq!(event.policy(), Policy::Audited);
        assert!(!event.is_denied());
    }

    #[test]
    fn decodes_packed_path_pair() {
        let mut ev = PathPairEvent {
            header: header(EVENT_RENAME, 0, 0),
            dfd: AT_FDCWD,
            dfd2: AT_FDCWD,
            paths: [0; 2 * PATH_LEN],
        };
        ev.paths[..2].copy_from_slice(b"/a");
        ev.paths[3..5].copy_from_slice(b"/b");
        let len = offset_of!(PathPairEvent, paths) + 6;
        let event = decoder().decode(&bytes_of(&ev, len)).unwrap();
        match event.payload {
            Payload::Rename {
                old_path, new_path, ..
            } => {
                assert_eq!(old_path, "/a");
                assert_eq!(new_path, "/b");
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn decodes_addresses_in_network_order() {
        let mut ev = ConnectEvent {
            header: header(EVENT_CONNECT, 0, size_of::<ConnectEvent>()),
            addr: [0; 16],
            port: 443,
            af: AF_INET,
            _pad: 0,
        };
        ev.addr[..4].copy_from_slice(&[93, 184, 216, 34]);
        let event = decoder()
            .decode(&bytes_of(&ev, size_of::<ConnectEvent>()))
            .unwrap();
        assert!(
            matches!(event.payload, Payload::Connect { addr } if addr.to_string() == "93.184.216.34:443")
        );

        ev.af = AF_INET6;
        ev.addr = [
            0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ];
        let event = decoder()
            .decode(&bytes_of(&ev, size_of::<ConnectEvent>()))
            .unwrap();
        assert!(
            matches!(event.payload, Payload::Connect { addr } if addr.to_string() == "[2606:4700::1111]:443")
        );
    }

    #[test]
    fn keeps_non_utf8_paths() {
        let mut ev = UnixConnectEvent {
            header: header(EVENT_UNIX_CONNECT, 0, 0),
            path: [0; UNIX_PATH_LEN],
        };
        ev.path[..3].copy_from_slice(&[b'/', 0xff, b'x']);
        let len = offset_of!(UnixConnectEvent, path) + 4;
        let event = decoder().decode(&bytes_of(&ev, len)).unwrap();
        assert!(
            matches!(event.payload, Payload::UnixConnect { ref path, .. } if path == "/\u{fffd}x")
        );
    }

    #[test]
    fn rejects_short_and_unknown_records() {
        let mut d = decoder();
        assert!(d.decode(&[0u8; 8]).is_none());
        let h = header(999, 0, size_of::<EventHeader>());
        assert!(d.decode(&bytes_of(&h, size_of::<EventHeader>())).is_none());
        // A path record with no string byte at all.
        let ev = PathEvent {
            header: header(EVENT_OPEN, 0, 0),
            flags: 0,
            dfd: 0,
            path: [0; PATH_LEN],
        };
        assert!(d
            .decode(&bytes_of(&ev, offset_of!(PathEvent, path)))
            .is_none());
    }

    #[test]
    fn interns_comms() {
        let mut d = decoder();
        let h = header(EVENT_EXIT, 0, size_of::<ExitEvent>());
        let a = d.decode(&bytes_of(&h, size_of::<ExitEvent>())).unwrap();
        let b = d.decode(&bytes_of(&h, size_of::<ExitEvent>())).unwrap();
        assert!(Arc::ptr_eq(&a.meta.comm, &b.meta.comm));
    }
}
