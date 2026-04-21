//! OCSF Process Activity (1007) mappings: Execve, Fork, Exit, Ptrace.

use serde_json::{json, Value};

use crate::enrich::EnrichedEvent;
use crate::store::{errno_name, Event};

use super::envelope::{
    envelope, push_observable, user_object, CATEGORY_SYSTEM, CLASS_PROCESS_ACTIVITY,
    OBS_FILE_PATH, OBS_PROCESS_NAME, OBS_USER_NAME,
};

pub(super) fn execve(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Execve { pid, root_pid, uid, comm, filename, timestamp_ns } = event else {
        unreachable!()
    };

    let message = format!("{comm} exec'd {filename}");

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        1, // Launch
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": pid,
        "name": comm,
        "cmd_line": filename,
        "file": super::envelope::file_object(filename),
        "user": user_object(*uid, enriched.username.as_deref()),
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": root_pid }
    }));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    if let Some(name) = enriched.username.as_deref() {
        push_observable(&mut v, "user.name", OBS_USER_NAME, name);
    }

    v
}

pub(super) fn fork(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Fork { parent_pid, child_pid, comm, timestamp_ns } = event else {
        unreachable!()
    };

    let message = format!("{comm} forked (parent={parent_pid}, child={child_pid})");

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        1, // Launch — OCSF 1007 has no dedicated "fork"; Launch is the closest semantic
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": child_pid,
        "name": comm,
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": parent_pid, "name": comm }
    }));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn exit(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Exit { pid, comm, timestamp_ns } = event else {
        unreachable!()
    };

    let message = format!("{comm} exited (pid={pid})");

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        2, // Terminate
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": pid,
        "name": comm,
    }));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn ptrace(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Ptrace { pid, comm, request, target_pid, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let status = if *ret >= 0 { "ok".to_string() } else { errno_name(*ret).to_string() };
    let message = format!(
        "{comm} ptrace(request={request}, target={target_pid}) [{status}]"
    );

    let mut v = envelope(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        4, // Inject — ptrace attach/syscall is canonical process injection
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("process".into(), json!({
        "pid": target_pid,
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));
    m.insert("injection_type_id".into(), json!(99)); // Other (OCSF doesn't define ptrace specifically)
    m.insert("injection_type".into(), json!(format!("ptrace(request={request})")));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}
