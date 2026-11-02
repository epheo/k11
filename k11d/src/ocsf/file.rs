//! OCSF File System Activity (1001): Openat, Unlink, Rename, Chmod, Chown,
//! Symlink.

use crate::classify::errno_name;
use crate::enrich::EnrichedEvent;
use crate::store::{Event, Payload, Policy};

use super::envelope::{
    File, Record, Unmapped, User, CATEGORY_SYSTEM, CLASS_FILE_SYSTEM_ACTIVITY, MODIFY_FLAGS,
    OBS_FILE_PATH, O_CREAT,
};

// OCSF 1001 activity ids.
const CREATE: u32 = 1;
const READ: u32 = 2;
const UPDATE: u32 = 3;
const DELETE: u32 = 4;
const RENAME: u32 = 5;
const SET_ATTRIBUTES: u32 = 6;
const SET_SECURITY: u32 = 7;

fn record<'a>(
    activity_id: u32,
    hostname: &'a str,
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    message: String,
) -> Record<'a> {
    Record::new(
        CLASS_FILE_SYSTEM_ACTIVITY,
        CATEGORY_SYSTEM,
        activity_id,
        hostname,
        event,
        enriched,
        message,
    )
}

pub(super) fn openat<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Openat {
        filename,
        flags,
        ret,
        policy,
    } = &event.payload
    else {
        unreachable!()
    };
    let comm = &event.meta.comm;

    // Any modify flag wins (writes data), else O_CREAT alone means Create.
    let activity_id = if *flags & MODIFY_FLAGS != 0 {
        UPDATE
    } else if *flags & O_CREAT != 0 {
        CREATE
    } else {
        READ
    };

    let message = match policy {
        Policy::Denied => format!("k11 blocked file access: {comm} attempted to open {filename}"),
        Policy::Audited => format!("k11 deny rule matched in audit mode: {comm} opened {filename}"),
        Policy::Allowed if *ret < 0 => {
            format!("{comm} open({filename}) failed [{}]", errno_name(*ret))
        }
        Policy::Allowed => format!("{comm} opened {filename}"),
    };

    let mut r = record(activity_id, hostname, event, enriched, message);
    r.file = Some(File::new(filename));
    if *policy == Policy::Audited {
        r.unmapped = Some(Unmapped {
            policy: Some("audited"),
            ..Default::default()
        });
    }
    r.observe("file.path", OBS_FILE_PATH, filename);
    r
}

pub(super) fn unlink<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Unlink { filename, ret, .. } = &event.payload else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!("{comm} unlink({filename}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} unlinked {filename}")
    };
    let mut r = record(DELETE, hostname, event, enriched, message);
    r.file = Some(File::new(filename));
    r.observe("file.path", OBS_FILE_PATH, filename);
    r
}

pub(super) fn rename<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Rename {
        old_path,
        new_path,
        ret,
    } = &event.payload
    else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!(
            "{comm} rename({old_path} -> {new_path}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        format!("{comm} renamed {old_path} -> {new_path}")
    };
    let mut r = record(RENAME, hostname, event, enriched, message);
    r.file = Some(File::new(old_path));
    r.file_result = Some(File::new(new_path));
    r.observe("file.path", OBS_FILE_PATH, old_path);
    r.observe("file_result.path", OBS_FILE_PATH, new_path);
    r
}

pub(super) fn chmod<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Chmod {
        filename,
        mode,
        ret,
    } = &event.payload
    else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!(
            "{comm} chmod({filename}, 0o{mode:o}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        format!("{comm} chmod {filename} -> 0o{mode:o}")
    };
    let mut r = record(SET_ATTRIBUTES, hostname, event, enriched, message);
    let mut file = File::new(filename);
    file.attributes = Some(format!("{mode:o}"));
    file.mode = Some(*mode);
    r.file = Some(file);
    r.observe("file.path", OBS_FILE_PATH, filename);
    r
}

pub(super) fn chown<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Chown {
        filename,
        owner_uid,
        owner_gid,
        ret,
    } = &event.payload
    else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!(
            "{comm} chown({filename}, {owner_uid}:{owner_gid}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        format!("{comm} chown {filename} -> {owner_uid}:{owner_gid}")
    };
    let mut r = record(SET_SECURITY, hostname, event, enriched, message);
    let mut file = File::new(filename);
    // OCSF `file.owner` is a User object; there is no native `file.group`.
    file.owner = Some(User::new(*owner_uid, None));
    r.file = Some(file);
    r.unmapped = Some(Unmapped {
        owner_gid: Some(*owner_gid),
        ..Default::default()
    });
    r.observe("file.path", OBS_FILE_PATH, filename);
    r
}

pub(super) fn symlink<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Symlink {
        target,
        linkpath,
        ret,
    } = &event.payload
    else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!(
            "{comm} symlink({linkpath} -> {target}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        format!("{comm} symlinked {linkpath} -> {target}")
    };
    let mut r = record(CREATE, hostname, event, enriched, message);
    let mut file = File::new(linkpath);
    file.type_id = Some(5); // Symbolic Link
    file.target = Some(target);
    r.file = Some(file);
    r.observe("file.path", OBS_FILE_PATH, linkpath);
    r.observe("file.target", OBS_FILE_PATH, target);
    r
}
