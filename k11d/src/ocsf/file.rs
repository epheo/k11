//! OCSF File System Activity (1001) mappings:
//! Openat, Unlink, Rename, Chmod, Chown, Symlink.

use serde_json::{json, Value};

use crate::enrich::EnrichedEvent;
use crate::store::{errno_name, Event};

use super::envelope::{
    envelope, file_object, push_observable, CATEGORY_SYSTEM, CLASS_FILE_SYSTEM_ACTIVITY,
    MODIFY_FLAGS, OBS_FILE_PATH, OBS_PROCESS_NAME, O_CREAT,
};

pub(super) fn openat(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Openat { pid, comm, filename, flags, ret, timestamp_ns, denied } = event else {
        unreachable!()
    };

    // OCSF file activities: 1=Create, 2=Read, 3=Update.
    // Any modify flag wins (writes data), else O_CREAT-only means Create,
    // else Read.
    let activity_id = if *flags & MODIFY_FLAGS != 0 {
        3
    } else if *flags & O_CREAT != 0 {
        1
    } else {
        2
    };

    let message = if *denied {
        format!("k11 blocked file access: {comm} attempted to open {filename}")
    } else if *ret < 0 {
        format!("{comm} open({filename}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} opened {filename} (fd={ret})")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        activity_id,
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("file".into(), file_object(filename));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn unlink(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Unlink { pid, comm, filename, flags: _, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} unlink({filename}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} unlinked {filename}")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        4, // Delete
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("file".into(), file_object(filename));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn rename(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Rename { pid, comm, old_path, new_path, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} rename({old_path} → {new_path}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} renamed {old_path} → {new_path}")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        5, // Rename
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("file".into(), file_object(old_path));
    m.insert("file_result".into(), file_object(new_path));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, old_path);
    push_observable(&mut v, "file_result.path", OBS_FILE_PATH, new_path);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn chmod(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Chmod { pid, comm, filename, mode, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} chmod({filename}, 0o{mode:o}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} chmod {filename} → 0o{mode:o}")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        6, // SetAttributes
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    let mut file = file_object(filename);
    file.as_object_mut().unwrap().insert("attributes".into(), json!(format!("{mode:o}")));
    file.as_object_mut().unwrap().insert("mode".into(), json!(*mode));
    m.insert("file".into(), file);
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn chown(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Chown { pid, comm, filename, owner_uid, owner_gid, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} chown({filename}, {owner_uid}:{owner_gid}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} chown {filename} → {owner_uid}:{owner_gid}")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        7, // Set Security
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    let mut file = file_object(filename);
    // OCSF 1.1.0 `file.owner` is a User object; there's no native `file.group`,
    // so the POSIX group lands in `unmapped` (legitimate use — OCSF has no field).
    file.as_object_mut().unwrap().insert("owner".into(), json!({
        "uid": owner_uid.to_string(),
    }));
    m.insert("file".into(), file);
    m.insert("unmapped".into(), json!({ "owner_gid": owner_gid }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, filename);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn symlink(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Symlink { pid, comm, target, linkpath, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} symlink({linkpath} → {target}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} symlinked {linkpath} → {target}")
    };

    let mut v = envelope(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        1, // Create
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    let mut file = file_object(linkpath);
    file.as_object_mut().unwrap().insert("type_id".into(), json!(5)); // Symbolic Link
    file.as_object_mut().unwrap().insert("target".into(), json!(target));
    m.insert("file".into(), file);
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "file.path", OBS_FILE_PATH, linkpath);
    push_observable(&mut v, "file.target", OBS_FILE_PATH, target);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}
