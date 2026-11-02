//! OCSF Process Activity (1007): Execve, Fork, Exit, Ptrace.

use crate::classify::status;
use crate::enrich::EnrichedEvent;
use crate::store::{Event, Payload};

use super::envelope::{
    File, Process, Record, User, CATEGORY_SYSTEM, CLASS_PROCESS_ACTIVITY, OBS_FILE_PATH,
};

// OCSF 1007 activity ids.
const LAUNCH: u32 = 1;
const TERMINATE: u32 = 2;
const INJECT: u32 = 4;

fn record<'a>(
    activity_id: u32,
    hostname: &'a str,
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    message: String,
) -> Record<'a> {
    Record::new(
        CLASS_PROCESS_ACTIVITY,
        CATEGORY_SYSTEM,
        activity_id,
        hostname,
        event,
        enriched,
        message,
    )
}

pub(super) fn execve<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Execve { filename } = &event.payload else {
        unreachable!()
    };
    let meta = &event.meta;
    let mut r = record(
        LAUNCH,
        hostname,
        event,
        enriched,
        format!("{} exec'd {filename}", meta.comm),
    );
    let mut process = Process::new(meta.pid, &meta.comm);
    process.cmd_line = Some(filename);
    process.file = Some(File::new(filename));
    process.user = Some(User::new(meta.uid, enriched.username.as_deref()));
    r.process = Some(process);
    r.observe("file.path", OBS_FILE_PATH, filename);
    r
}

pub(super) fn fork<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Fork { child_pid } = &event.payload else {
        unreachable!()
    };
    let meta = &event.meta;
    let message = format!(
        "{} forked (parent={}, child={child_pid})",
        meta.comm, meta.pid
    );
    // OCSF 1007 has no fork; Launch is the closest.
    let mut r = record(LAUNCH, hostname, event, enriched, message);
    r.process = Some(Process::new(*child_pid, &meta.comm));
    r
}

pub(super) fn exit<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let meta = &event.meta;
    let message = format!("{} exited (pid={})", meta.comm, meta.pid);
    let mut r = record(TERMINATE, hostname, event, enriched, message);
    r.process = Some(Process::new(meta.pid, &meta.comm));
    r
}

pub(super) fn ptrace<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Ptrace {
        request,
        target_pid,
        ret,
    } = &event.payload
    else {
        unreachable!()
    };
    let meta = &event.meta;
    let message = format!(
        "{} ptrace(request={request}, target={target_pid}) [{}]",
        meta.comm,
        status(*ret)
    );
    // ptrace attach/syscall is canonical process injection.
    let mut r = record(INJECT, hostname, event, enriched, message);
    r.process = Some(Process {
        pid: *target_pid,
        name: None,
        cmd_line: None,
        file: None,
        user: None,
    });
    r.injection_type_id = Some(99); // Other: OCSF does not define ptrace
    r.injection_type = Some(format!("ptrace(request={request})"));
    r
}
