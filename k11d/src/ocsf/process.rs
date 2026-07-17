//! OCSF Process Activity (1007) mappings: Execve, Fork, Exit, Ptrace.

use serde_json::{json, Value};

use crate::enrich::EnrichedEvent;
use crate::store::{errno_name, Event, Payload};

use super::envelope::{
    envelope, push_observable, user_object, CATEGORY_SYSTEM, CLASS_PROCESS_ACTIVITY,
    OBS_FILE_PATH,
};

pub(super) fn execve(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Payload::Execve { filename } = &event.payload else {
        unreachable!()
    };
    let meta = &event.meta;

    let message = format!("{} exec'd {filename}", meta.comm);

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        1, // Launch
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": meta.pid,
        "name": meta.comm,
        "cmd_line": filename,
        "file": super::envelope::file_object(filename),
        "user": user_object(meta.uid, enriched.username.as_deref()),
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    v
}

pub(super) fn fork(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Payload::Fork { child_pid } = &event.payload else {
        unreachable!()
    };
    let meta = &event.meta;

    let message = format!("{} forked (parent={}, child={child_pid})", meta.comm, meta.pid);

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        1, // Launch — OCSF 1007 has no dedicated "fork"; Launch is the closest semantic
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": child_pid,
        "name": meta.comm,
    }));
    v
}

pub(super) fn exit(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let meta = &event.meta;
    let message = format!("{} exited (pid={})", meta.comm, meta.pid);

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        2, // Terminate
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": meta.pid,
        "name": meta.comm,
    }));
    v
}

pub(super) fn ptrace(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Payload::Ptrace { request, target_pid, ret } = &event.payload else {
        unreachable!()
    };
    let meta = &event.meta;

    let status = if *ret >= 0 { "ok".to_string() } else { errno_name(*ret).to_string() };
    let message = format!(
        "{} ptrace(request={request}, target={target_pid}) [{status}]", meta.comm
    );

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        4, // Inject — ptrace attach/syscall is canonical process injection
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": target_pid,
    }));
    m.insert("injection_type_id".into(), json!(99)); // Other (OCSF doesn't define ptrace specifically)
    m.insert("injection_type".into(), json!(format!("ptrace(request={request})")));
    v
}
