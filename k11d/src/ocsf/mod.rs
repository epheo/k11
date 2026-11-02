//! `store::Event` to OCSF 1.1.0 records, one per event, for JSON Lines.
//!
//! Process Activity (1007) for exec, fork, exit and ptrace; File System
//! Activity (1001) for open, unlink, rename, chmod, chown and symlink;
//! Network Activity (4001) for connect, unix connect, bind and listen.

mod schema;

pub use schema::{Host, LossRecord, Record};

use schema::*;

use crate::classify::{failed, ptrace_request};
use crate::enrich::EnrichedEvent;
use crate::store::{Event, Payload};

// 1007 activities.
const LAUNCH: u32 = 1;
const TERMINATE: u32 = 2;
const INJECT: u32 = 4;
// 1001 activities. An open is a request for a handle: what it is for is
// in `access_mask`.
const CREATE: u32 = 1;
const DELETE: u32 = 4;
const RENAME: u32 = 5;
const SET_SECURITY: u32 = 7;
const OPEN: u32 = 14;
// 4001 activities. Binding and listening have no activity of their own.
const NET_OPEN: u32 = 1;
const NET_FAIL: u32 = 4;
const NET_REFUSE: u32 = 5;
const NET_OTHER: u32 = 99;

const INBOUND: u32 = 1;
const OUTBOUND: u32 = 2;

const AT_REMOVEDIR: i32 = 0x200;
const ECONNREFUSED: i32 = -111;

pub fn record<'a>(event: &'a Event, enriched: &'a EnrichedEvent, host: &'a Host) -> Record<'a> {
    let m = &event.meta;
    let new = |class, activity| Record::new(class, activity, event, enriched, host);
    let local = || Endpoint {
        hostname: Some(&host.hostname),
        ..Endpoint::default()
    };
    match &event.payload {
        Payload::Execve { filename } => {
            let mut r = new(CLASS_PROCESS, LAUNCH);
            let file = r.file("process.file.name", filename, FILE_REGULAR);
            r.process = Some(Process {
                file: Some(file),
                ..r.actor.process.clone()
            });
            r
        }
        Payload::Fork { child_pid } => {
            let mut r = new(CLASS_PROCESS, LAUNCH);
            r.process = Some(Process {
                pid: *child_pid,
                parent_process: Some(ProcessRef { pid: m.pid }),
                ..r.actor.process.clone()
            });
            r
        }
        Payload::Exit => {
            let mut r = new(CLASS_PROCESS, TERMINATE);
            r.process = Some(r.actor.process.clone());
            r
        }
        Payload::Ptrace {
            request,
            target_pid,
        } => {
            let mut r = new(CLASS_PROCESS, INJECT);
            r.process = Some(Process {
                pid: *target_pid,
                ..Process::default()
            });
            r.injection_type_id = Some(99);
            r.injection_type = Some(ptrace_request(*request));
            r.unmapped.ptrace_request = Some(*request);
            r
        }
        Payload::Open {
            filename, flags, ..
        } => {
            let mut r = new(CLASS_FILE_SYSTEM, OPEN);
            r.file = Some(r.file("file.name", filename, FILE_UNKNOWN));
            r.access_mask = Some(*flags);
            r
        }
        Payload::Unlink { filename, flags } => {
            let kind = if flags & AT_REMOVEDIR != 0 {
                FILE_FOLDER
            } else {
                FILE_UNKNOWN
            };
            let mut r = new(CLASS_FILE_SYSTEM, DELETE);
            r.file = Some(r.file("file.name", filename, kind));
            r
        }
        Payload::Rename { old_path, new_path } => {
            let mut r = new(CLASS_FILE_SYSTEM, RENAME);
            r.file = Some(r.file("file.name", old_path, FILE_UNKNOWN));
            r.file_result = Some(r.file("file_result.name", new_path, FILE_UNKNOWN));
            r
        }
        Payload::Chmod { filename, mode } => {
            let mut r = new(CLASS_FILE_SYSTEM, SET_SECURITY);
            r.file = Some(r.file("file.name", filename, FILE_UNKNOWN));
            r.unmapped.mode = Some(*mode);
            r
        }
        Payload::Chown {
            filename,
            owner_uid,
            owner_gid,
        } => {
            let mut r = new(CLASS_FILE_SYSTEM, SET_SECURITY);
            let mut file = r.file("file.name", filename, FILE_UNKNOWN);
            file.owner = Some(User {
                uid: owner_uid.to_string(),
                name: None,
            });
            r.file = Some(file);
            r.unmapped.owner_gid = Some(*owner_gid);
            r
        }
        Payload::Symlink { target, linkpath } => {
            let mut r = new(CLASS_FILE_SYSTEM, CREATE);
            r.file = Some(r.file("file.name", linkpath, FILE_SYMLINK));
            r.unmapped.symlink_target = Some(target);
            r
        }
        Payload::Connect { addr } => {
            let mut r = new(CLASS_NETWORK, connect_activity(m.ret));
            r.src_endpoint = Some(local());
            r.dst_endpoint = Some(r.remote(*addr, enriched.addr.as_ref()));
            r.connection_info = Some(ConnectionInfo {
                direction_id: OUTBOUND,
                protocol_ver_id: Some(if addr.is_ipv4() { 4 } else { 6 }),
            });
            r
        }
        Payload::UnixConnect { path } => {
            let mut r = new(CLASS_NETWORK, connect_activity(m.ret));
            r.src_endpoint = Some(local());
            r.dst_endpoint = Some(Endpoint {
                name: Some(path),
                ..Endpoint::default()
            });
            r.connection_info = Some(ConnectionInfo {
                direction_id: OUTBOUND,
                protocol_ver_id: None,
            });
            r
        }
        // Inbound: the local address is where connections will arrive.
        Payload::Bind { addr } => {
            let mut r = new(CLASS_NETWORK, NET_OTHER);
            r.activity_name = Some("Bind");
            r.src_endpoint = Some(local());
            r.dst_endpoint = Some(Endpoint {
                ip: Some(addr.ip()),
                port: Some(addr.port()),
                hostname: Some(&host.hostname),
                ..Endpoint::default()
            });
            r.connection_info = Some(ConnectionInfo {
                direction_id: INBOUND,
                protocol_ver_id: Some(if addr.is_ipv4() { 4 } else { 6 }),
            });
            r
        }
        Payload::Listen { backlog } => {
            let mut r = new(CLASS_NETWORK, NET_OTHER);
            r.activity_name = Some("Listen");
            r.src_endpoint = Some(local());
            r.dst_endpoint = Some(local());
            r.connection_info = Some(ConnectionInfo {
                direction_id: INBOUND,
                protocol_ver_id: None,
            });
            r.unmapped.backlog = Some(*backlog);
            r
        }
    }
}

fn connect_activity(ret: i32) -> u32 {
    match ret {
        ECONNREFUSED => NET_REFUSE,
        ret if failed(ret) => NET_FAIL,
        _ => NET_OPEN,
    }
}

#[cfg(test)]
mod tests;
