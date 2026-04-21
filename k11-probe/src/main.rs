#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, gen},
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use k11_common::{
    ChownEvent, ConnectEvent, EventHeader, ExecveEvent, ExitEvent, ForkEvent, ListenEvent,
    OpenatEvent, PtraceEvent, RenameEvent, UnixConnectEvent,
    AF_INET, AF_INET6, AF_UNIX, CONFIG_ENFORCE, CONFIG_WATCH_ALL,
    EVENT_BIND, EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT,
    EVENT_DENY_OPENAT, EVENT_EXECVE, EVENT_EXIT, EVENT_FORK,
    EVENT_LISTEN, EVENT_OPENAT, EVENT_PTRACE, EVENT_RENAME, EVENT_SYMLINK,
    EVENT_UNLINK, EVENT_UNIX_CONNECT, MAX_DENY_PATHS, OFFSETS_LEN, OFF_BIND_ADDR, OFF_BIND_RET,
    OFF_CHMOD_FILENAME, OFF_CHMOD_MODE, OFF_CHMOD_RET,
    OFF_CHOWN_FILENAME, OFF_CHOWN_GID, OFF_CHOWN_RET, OFF_CHOWN_UID,
    OFF_CONNECT_ADDR, OFF_CONNECT_RET, OFF_EXEC_FILENAME, OFF_FORK_CHILD_PID,
    OFF_LISTEN_BACKLOG, OFF_LISTEN_RET,
    OFF_OPENAT_FILENAME, OFF_OPENAT_FLAGS, OFF_OPENAT_RET,
    OFF_PTRACE_PID, OFF_PTRACE_REQUEST, OFF_PTRACE_RET,
    OFF_RENAME_NEWNAME, OFF_RENAME_OLDNAME, OFF_RENAME_RET,
    OFF_SYMLINK_NEWNAME, OFF_SYMLINK_OLDNAME, OFF_SYMLINK_RET,
    OFF_UNLINK_FLAGS, OFF_UNLINK_PATHNAME, OFF_UNLINK_RET,
    DUAL_PATH_LEN, PATH_LEN, POLICY_PATH_LEN, UNIX_PATH_LEN,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Tracked PIDs: key=tgid (process ID), value=root_agent_tgid
#[map]
static WATCHED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

/// Pending openat syscalls: key=pid_tgid, value=partial OpenatEvent (ret not yet known)
#[map]
static PENDING_OPENAT: HashMap<u64, OpenatEvent> = HashMap::with_max_entries(10240, 0);

/// Pending connect syscalls: key=pid_tgid, value=partial ConnectEvent (ret not yet known)
#[map]
static PENDING_CONNECT: HashMap<u64, ConnectEvent> = HashMap::with_max_entries(10240, 0);

/// Pending Unix socket connect syscalls: key=pid_tgid, value=partial UnixConnectEvent
#[map]
static PENDING_UNIX_CONNECT: HashMap<u64, UnixConnectEvent> = HashMap::with_max_entries(10240, 0);

// --- Tier 1+2 pending maps ---

#[map]
static PENDING_BIND: HashMap<u64, ConnectEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_LISTEN: HashMap<u64, ListenEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_UNLINK: HashMap<u64, OpenatEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_RENAME: HashMap<u64, RenameEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_CHMOD: HashMap<u64, OpenatEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_CHOWN: HashMap<u64, ChownEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_SYMLINK: HashMap<u64, RenameEvent> = HashMap::with_max_entries(10240, 0);
#[map]
static PENDING_PTRACE: HashMap<u64, PtraceEvent> = HashMap::with_max_entries(10240, 0);

/// Comm names to watch: key=comm (16 bytes), value=1
#[map]
static WATCH_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(64, 0);

/// Config flags: index 0 = bitflags (bit0 = watch_all)
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

/// Tracepoint field offsets discovered from tracefs at daemon startup.
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(OFFSETS_LEN, 0);

/// Offset of f_path within struct file — set via .rodata global from userspace
/// before BPF load. Must be a constant for the verifier to resolve
/// trusted_ptr_file + offset → struct path * through BTF.
#[no_mangle]
static FILE_F_PATH_OFF: u32 = 0;

// --- Policy maps for LSM enforcement ---

/// Deny-list path prefixes for file access. Array for bounded BPF iteration.
#[map]
static DENY_FILE_PATHS: Array<[u8; POLICY_PATH_LEN]> = Array::with_max_entries(MAX_DENY_PATHS, 0);
#[map]
static DENY_FILE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
fn tp_offset(index: u32) -> usize {
    unsafe { OFFSETS.get_ptr(index).map(|p| *p as usize).unwrap_or(0) }
}

// --- Filtering ---

#[inline(always)]
fn is_watch_all() -> bool {
    unsafe {
        CONFIG
            .get_ptr(0)
            .map(|p| *p & CONFIG_WATCH_ALL != 0)
            .unwrap_or(false)
    }
}

#[inline(always)]
fn is_watched(tgid: u32) -> bool {
    WATCHED_PIDS.get_ptr(&tgid).is_some()
}

#[inline(always)]
fn is_enforce() -> bool {
    unsafe {
        CONFIG
            .get_ptr(0)
            .map(|p| *p & CONFIG_ENFORCE != 0)
            .unwrap_or(false)
    }
}

/// Check if `path` starts with any prefix in `paths_map[0..count_map[0]]`.
/// Both loops are bounded by compile-time constants for the BPF verifier.
#[inline(always)]
fn matches_deny_paths(
    path: &[u8; POLICY_PATH_LEN],
    paths_map: &Array<[u8; POLICY_PATH_LEN]>,
    count_map: &Array<u32>,
) -> bool {
    let count = unsafe { count_map.get_ptr(0).map(|p| *p).unwrap_or(0) };
    let mut i: u32 = 0;
    while i < MAX_DENY_PATHS {
        if i >= count {
            break;
        }
        if let Some(prefix_ptr) = paths_map.get_ptr(i) {
            let prefix = unsafe { &*prefix_ptr };
            let mut matched = true;
            let mut j: usize = 0;
            while j < POLICY_PATH_LEN {
                if prefix[j] == 0 {
                    break; // end of prefix — all bytes matched so far
                }
                if path[j] != prefix[j] {
                    matched = false;
                    break;
                }
                j += 1;
            }
            if matched {
                return true;
            }
        }
        i += 1;
    }
    false
}

// --- sched_process_fork ---

#[tracepoint]
pub fn k11_fork(ctx: TracePointContext) -> u32 {
    match handle_fork(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // In sched_process_fork the current task is always the parent.
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let child_pid: i32 = unsafe { ctx.read_at(tp_offset(OFF_FORK_CHILD_PID))? };
    let child_pid = child_pid as u32;

    // Propagate lineage in BPF map
    if let Some(root_ptr) = WATCHED_PIDS.get_ptr(&parent_tgid) {
        let root = unsafe { *root_ptr };
        let _ = WATCHED_PIDS.insert(&child_pid, &root, 0);
    }

    // Emit event if parent is watched
    if !is_watch_all() && !is_watched(parent_tgid) {
        return Ok(0);
    }

    let mut entry = match EVENTS.reserve::<ForkEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    fill_header_with_root(&mut event.header, EVENT_FORK, lookup_root(parent_tgid));
    event.child_pid = child_pid;
    event._padding = 0;
    entry.submit(0);

    Ok(0)
}

// --- sched_process_exit ---

#[tracepoint]
pub fn k11_exit(ctx: TracePointContext) -> u32 {
    match handle_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_exit(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Single map read: combines the watched-check and root lookup into one
    // operation to eliminate a TOCTOU race. Without this, a worker thread
    // could pass is_watched() just before the leader's exit removes the
    // WATCHED_PIDS entry, then hit the lookup_root() fallback (unwrap_or)
    // and emit an Exit event with root_pid = self — creating an orphan
    // AgentTree. This reliably affected multi-threaded processes like Go
    // binaries (gh, host-spawn).
    let root = if is_watch_all() {
        tgid
    } else {
        match WATCHED_PIDS.get_ptr(&tgid) {
            Some(ptr) => unsafe { *ptr },
            None => return Ok(0),
        }
    };

    if let Some(mut entry) = EVENTS.reserve::<ExitEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        fill_header_with_root(&mut event.header, EVENT_EXIT, root);
        entry.submit(0);
    }

    // Only remove from WATCHED_PIDS when the thread-group leader exits
    // (tid == tgid), not on individual thread exits. This is a stable,
    // portable check — no dependency on tracepoint field offsets.
    if tid == tgid {
        let _ = WATCHED_PIDS.remove(&tgid);
    }
    Ok(0)
}

// --- sched_process_exec ---
// Fires AFTER execve completes — comm reflects the new binary.

#[tracepoint]
pub fn k11_exec(ctx: TracePointContext) -> u32 {
    match handle_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if !is_watch_all() && !is_watched(tgid) {
        // Not watched yet — check if this is a new agent by comm name.
        // Because we hook sched_process_exec (post-exec), comm is the NEW
        // binary's name, so discovery works for processes launched from
        // non-watched parents (e.g. bash → claude).
        let comm = match bpf_get_current_comm() {
            Ok(c) => c,
            Err(_) => return Ok(0),
        };
        if WATCH_COMMS.get_ptr(&comm).is_none() {
            return Ok(0);
        }
        // New agent discovered — register as root of its own lineage
        let _ = WATCHED_PIDS.insert(&tgid, &tgid, 0);
    }

    let mut entry = match EVENTS.reserve::<ExecveEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    fill_header(&mut event.header, EVENT_EXECVE);

    // Read filename from __data_loc field (kernel memory, not user pointer).
    // __data_loc is a u32: lower 16 bits = offset, upper 16 bits = length.
    let filename_ptr = core::ptr::addr_of_mut!(event.filename) as *mut _;
    match unsafe { ctx.read_at::<u32>(tp_offset(OFF_EXEC_FILENAME)) } {
        Ok(data_loc) => {
            let str_offset = (data_loc & 0xFFFF) as usize;
            let src = unsafe { (ctx.as_ptr() as *const u8).add(str_offset) };
            unsafe {
                gen::bpf_probe_read_kernel_str(
                    filename_ptr,
                    PATH_LEN as u32,
                    src as *const _,
                );
            }
        }
        _ => event.filename[0] = 0,
    }

    entry.submit(0);
    Ok(0)
}

// --- sys_enter_openat ---

#[tracepoint]
pub fn k11_openat(ctx: TracePointContext) -> u32 {
    match handle_openat(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_openat(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: OpenatEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_OPENAT);

    let filename_ptr = core::ptr::addr_of_mut!(event.filename) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_OPENAT_FILENAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(filename_ptr, PATH_LEN as u32, addr as *const _);
        },
        _ => event.filename[0] = 0,
    }

    event.flags = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_OPENAT_FLAGS)) } {
        Ok(f) => f as i32,
        Err(_) => 0,
    };

    let _ = PENDING_OPENAT.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_openat ---

#[tracepoint]
pub fn k11_openat_exit(ctx: TracePointContext) -> u32 {
    match handle_openat_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_openat_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_OPENAT.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };

    let _ = PENDING_OPENAT.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<OpenatEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;

    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_OPENAT_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };

    entry.submit(0);
    Ok(0)
}

// --- sys_enter_connect ---

#[tracepoint]
pub fn k11_connect(ctx: TracePointContext) -> u32 {
    match handle_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_connect(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: ConnectEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_CONNECT);
    event._padding = 0;

    let sockaddr_ptr = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CONNECT_ADDR)) } {
        Ok(addr) if addr != 0 => addr,
        _ => return Ok(0), // No sockaddr (null) — no useful info, skip.
    };

    let mut sa_family: u16 = 0;
    unsafe {
        gen::bpf_probe_read_user(
            &mut sa_family as *mut u16 as *mut _,
            2,
            sockaddr_ptr as *const _,
        );
    }
    // AF_UNSPEC (0) = UDP disconnect / null sockaddr — no security signal, skip.
    if sa_family == 0 {
        return Ok(0);
    }

    // AF_UNIX → separate event type with sun_path
    if sa_family == AF_UNIX {
        let mut unix_event: UnixConnectEvent = unsafe { core::mem::zeroed() };
        fill_header(&mut unix_event.header, EVENT_UNIX_CONNECT);
        // sun_path starts at offset 2 in sockaddr_un
        let path_ptr = core::ptr::addr_of_mut!(unix_event.path) as *mut _;
        unsafe {
            gen::bpf_probe_read_user_str(
                path_ptr,
                UNIX_PATH_LEN as u32,
                (sockaddr_ptr + 2) as *const _,
            );
        }
        let _ = PENDING_UNIX_CONNECT.insert(&pid_tgid, &unix_event, 0);
        return Ok(0);
    }

    event.af = sa_family;

    // Port sits at offset 2 in both sockaddr_in and sockaddr_in6.
    let mut port_be: u16 = 0;
    unsafe {
        gen::bpf_probe_read_user(
            &mut port_be as *mut u16 as *mut _,
            2,
            (sockaddr_ptr + 2) as *const _,
        );
    }
    event.port = u16::from_be(port_be);

    if sa_family == AF_INET {
        unsafe {
            gen::bpf_probe_read_user(
                &mut event.addr_v4 as *mut u32 as *mut _,
                4,
                (sockaddr_ptr + 4) as *const _,
            );
        }
    } else if sa_family == AF_INET6 {
        unsafe {
            gen::bpf_probe_read_user(
                core::ptr::addr_of_mut!(event.addr_v6) as *mut _,
                16,
                (sockaddr_ptr + 8) as *const _,
            );
        }
    }

    let _ = PENDING_CONNECT.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_connect ---

#[tracepoint]
pub fn k11_connect_exit(ctx: TracePointContext) -> u32 {
    match handle_connect_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_connect_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let ret_val = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_CONNECT_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };

    // Try IP connect first (most common path)
    if let Some(ptr) = PENDING_CONNECT.get_ptr(&pid_tgid) {
        let pending = unsafe { *ptr };
        let _ = PENDING_CONNECT.remove(&pid_tgid);

        if let Some(mut entry) = EVENTS.reserve::<ConnectEvent>(0) {
            let event = unsafe { &mut *entry.as_mut_ptr() };
            *event = pending;
            event.ret = ret_val;
            entry.submit(0);
        }
        return Ok(0);
    }

    // Try Unix connect
    if let Some(ptr) = PENDING_UNIX_CONNECT.get_ptr(&pid_tgid) {
        let pending = unsafe { *ptr };
        let _ = PENDING_UNIX_CONNECT.remove(&pid_tgid);

        if let Some(mut entry) = EVENTS.reserve::<UnixConnectEvent>(0) {
            let event = unsafe { &mut *entry.as_mut_ptr() };
            *event = pending;
            event.ret = ret_val;
            entry.submit(0);
        }
    }

    Ok(0)
}

// =======================================================================
// Tier 1+2 syscall tracepoints
// =======================================================================

// --- sys_enter_bind ---

#[tracepoint]
pub fn k11_bind(ctx: TracePointContext) -> u32 {
    match handle_bind(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_bind(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: ConnectEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_BIND);
    event._padding = 0;

    let sockaddr_ptr = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_BIND_ADDR)) } {
        Ok(addr) if addr != 0 => addr,
        _ => return Ok(0),
    };

    let mut sa_family: u16 = 0;
    unsafe {
        gen::bpf_probe_read_user(
            &mut sa_family as *mut u16 as *mut _,
            2,
            sockaddr_ptr as *const _,
        );
    }
    // Only trace AF_INET/AF_INET6 binds — AF_UNIX bind is low signal for agents.
    if sa_family != AF_INET && sa_family != AF_INET6 {
        return Ok(0);
    }

    event.af = sa_family;

    let mut port_be: u16 = 0;
    unsafe {
        gen::bpf_probe_read_user(
            &mut port_be as *mut u16 as *mut _,
            2,
            (sockaddr_ptr + 2) as *const _,
        );
    }
    event.port = u16::from_be(port_be);

    if sa_family == AF_INET {
        unsafe {
            gen::bpf_probe_read_user(
                &mut event.addr_v4 as *mut u32 as *mut _,
                4,
                (sockaddr_ptr + 4) as *const _,
            );
        }
    } else if sa_family == AF_INET6 {
        unsafe {
            gen::bpf_probe_read_user(
                core::ptr::addr_of_mut!(event.addr_v6) as *mut _,
                16,
                (sockaddr_ptr + 8) as *const _,
            );
        }
    }

    let _ = PENDING_BIND.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_bind ---

#[tracepoint]
pub fn k11_bind_exit(ctx: TracePointContext) -> u32 {
    match handle_bind_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_bind_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_BIND.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_BIND.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_BIND_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_listen ---

#[tracepoint]
pub fn k11_listen(ctx: TracePointContext) -> u32 {
    match handle_listen(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_listen(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: ListenEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_LISTEN);
    event.backlog = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_LISTEN_BACKLOG)) } {
        Ok(b) => b as i32,
        Err(_) => 0,
    };

    let _ = PENDING_LISTEN.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_listen ---

#[tracepoint]
pub fn k11_listen_exit(ctx: TracePointContext) -> u32 {
    match handle_listen_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_listen_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_LISTEN.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_LISTEN.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<ListenEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_LISTEN_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_unlinkat ---

#[tracepoint]
pub fn k11_unlink(ctx: TracePointContext) -> u32 {
    match handle_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_unlink(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: OpenatEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_UNLINK);

    let filename_ptr = core::ptr::addr_of_mut!(event.filename) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_UNLINK_PATHNAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(filename_ptr, PATH_LEN as u32, addr as *const _);
        },
        _ => event.filename[0] = 0,
    }

    event.flags = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_UNLINK_FLAGS)) } {
        Ok(f) => f as i32,
        Err(_) => 0,
    };

    let _ = PENDING_UNLINK.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_unlinkat ---

#[tracepoint]
pub fn k11_unlink_exit(ctx: TracePointContext) -> u32 {
    match handle_unlink_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_unlink_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_UNLINK.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_UNLINK.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<OpenatEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_UNLINK_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_renameat2 ---

#[tracepoint]
pub fn k11_rename(ctx: TracePointContext) -> u32 {
    match handle_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_rename(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: RenameEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_RENAME);

    let old_ptr = core::ptr::addr_of_mut!(event.old_path) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_RENAME_OLDNAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(old_ptr, DUAL_PATH_LEN as u32, addr as *const _);
        },
        _ => event.old_path[0] = 0,
    }

    let new_ptr = core::ptr::addr_of_mut!(event.new_path) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_RENAME_NEWNAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(new_ptr, DUAL_PATH_LEN as u32, addr as *const _);
        },
        _ => event.new_path[0] = 0,
    }

    event._padding = 0;
    let _ = PENDING_RENAME.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_renameat2 ---

#[tracepoint]
pub fn k11_rename_exit(ctx: TracePointContext) -> u32 {
    match handle_rename_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_rename_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_RENAME.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_RENAME.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<RenameEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_RENAME_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_fchmodat ---

#[tracepoint]
pub fn k11_chmod(ctx: TracePointContext) -> u32 {
    match handle_chmod(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_chmod(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: OpenatEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_CHMOD);

    let filename_ptr = core::ptr::addr_of_mut!(event.filename) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CHMOD_FILENAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(filename_ptr, PATH_LEN as u32, addr as *const _);
        },
        _ => event.filename[0] = 0,
    }

    // Store mode in the flags field (same i32 layout)
    event.flags = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CHMOD_MODE)) } {
        Ok(m) => m as i32,
        Err(_) => 0,
    };

    let _ = PENDING_CHMOD.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_fchmodat ---

#[tracepoint]
pub fn k11_chmod_exit(ctx: TracePointContext) -> u32 {
    match handle_chmod_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_chmod_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_CHMOD.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_CHMOD.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<OpenatEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_CHMOD_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_fchownat ---

#[tracepoint]
pub fn k11_chown(ctx: TracePointContext) -> u32 {
    match handle_chown(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_chown(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: ChownEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_CHOWN);

    let filename_ptr = core::ptr::addr_of_mut!(event.filename) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CHOWN_FILENAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(filename_ptr, PATH_LEN as u32, addr as *const _);
        },
        _ => event.filename[0] = 0,
    }

    event.owner_uid = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CHOWN_UID)) } {
        Ok(u) => u as u32,
        Err(_) => 0,
    };
    event.owner_gid = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_CHOWN_GID)) } {
        Ok(g) => g as u32,
        Err(_) => 0,
    };
    event._padding = 0;

    let _ = PENDING_CHOWN.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_fchownat ---

#[tracepoint]
pub fn k11_chown_exit(ctx: TracePointContext) -> u32 {
    match handle_chown_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_chown_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_CHOWN.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_CHOWN.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<ChownEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_CHOWN_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_symlinkat ---

#[tracepoint]
pub fn k11_symlink(ctx: TracePointContext) -> u32 {
    match handle_symlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_symlink(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: RenameEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_SYMLINK);

    // oldname = target path, newname = link path
    let old_ptr = core::ptr::addr_of_mut!(event.old_path) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_SYMLINK_OLDNAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(old_ptr, DUAL_PATH_LEN as u32, addr as *const _);
        },
        _ => event.old_path[0] = 0,
    }

    let new_ptr = core::ptr::addr_of_mut!(event.new_path) as *mut _;
    match unsafe { ctx.read_at::<u64>(tp_offset(OFF_SYMLINK_NEWNAME)) } {
        Ok(addr) if addr != 0 => unsafe {
            gen::bpf_probe_read_user_str(new_ptr, DUAL_PATH_LEN as u32, addr as *const _);
        },
        _ => event.new_path[0] = 0,
    }

    event._padding = 0;
    let _ = PENDING_SYMLINK.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_symlinkat ---

#[tracepoint]
pub fn k11_symlink_exit(ctx: TracePointContext) -> u32 {
    match handle_symlink_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_symlink_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_SYMLINK.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_SYMLINK.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<RenameEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_SYMLINK_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- sys_enter_ptrace ---

#[tracepoint]
pub fn k11_ptrace(ctx: TracePointContext) -> u32 {
    match handle_ptrace(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_ptrace(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if !is_watch_all() && !is_watched(tgid) {
        return Ok(0);
    }

    let mut event: PtraceEvent = unsafe { core::mem::zeroed() };
    fill_header(&mut event.header, EVENT_PTRACE);

    event.request = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_PTRACE_REQUEST)) } {
        Ok(r) => r as u32,
        Err(_) => 0,
    };
    event.target_pid = match unsafe { ctx.read_at::<u64>(tp_offset(OFF_PTRACE_PID)) } {
        Ok(p) => p as u32,
        Err(_) => 0,
    };
    event._padding = 0;

    let _ = PENDING_PTRACE.insert(&pid_tgid, &event, 0);
    Ok(0)
}

// --- sys_exit_ptrace ---

#[tracepoint]
pub fn k11_ptrace_exit(ctx: TracePointContext) -> u32 {
    match handle_ptrace_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn handle_ptrace_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();

    let pending = match PENDING_PTRACE.get_ptr(&pid_tgid) {
        Some(ptr) => unsafe { *ptr },
        None => return Ok(0),
    };
    let _ = PENDING_PTRACE.remove(&pid_tgid);

    let mut entry = match EVENTS.reserve::<PtraceEvent>(0) {
        Some(entry) => entry,
        None => return Ok(0),
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    *event = pending;
    event.ret = match unsafe { ctx.read_at::<i64>(tp_offset(OFF_PTRACE_RET)) } {
        Ok(r) => r as i32,
        Err(_) => -1,
    };
    entry.submit(0);
    Ok(0)
}

// --- LSM: file_open — deny file access by path prefix ---
//
// Uses bpf_d_path to resolve the full path from struct file's f_path field
// (offset discovered from kernel BTF at startup), then matches against
// path prefix deny rules.
//
// NOTE: All LSM programs avoid slice operations (copy_from_slice, [0u8; N])
// because aya 0.13's linker fails to append .text subprograms to LSM sections.

#[lsm(hook = "file_open", sleepable)]
pub fn k11_lsm_file_open(ctx: LsmContext) -> i32 {
    match handle_lsm_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn handle_lsm_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    // file_open(struct file *file) + retval
    let retval: i32 = unsafe { ctx.arg(1) };
    if retval != 0 {
        return Ok(retval);
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_watched(tgid) {
        return Ok(0);
    }

    let file_ptr: *const u8 = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return Ok(0);
    }

    // Resolve full path via bpf_d_path on file->f_path.
    // FILE_F_PATH_OFF is a .rodata global (constant to the verifier), so
    // file_ptr + const resolves to struct path * through BTF.
    let mut buf = core::mem::MaybeUninit::<[u8; POLICY_PATH_LEN]>::uninit();
    let off = unsafe { core::ptr::read_volatile(&FILE_F_PATH_OFF) } as usize;
    let path_ptr = unsafe { file_ptr.add(off) };
    let len = unsafe {
        gen::bpf_d_path(
            path_ptr as *mut _,
            buf.as_mut_ptr() as *mut _,
            POLICY_PATH_LEN as u32,
        )
    };
    if len <= 0 {
        return Ok(0);
    }

    let buf_ref = unsafe { buf.assume_init_ref() };
    if !matches_deny_paths(buf_ref, &DENY_FILE_PATHS, &DENY_FILE_COUNT) {
        return Ok(0);
    }

    // Emit deny event with resolved path.
    if let Some(mut entry) = EVENTS.reserve::<OpenatEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        fill_header(&mut event.header, EVENT_DENY_OPENAT);
        unsafe {
            gen::bpf_probe_read_kernel(
                event.filename.as_mut_ptr() as *mut _,
                (len as u32).min(PATH_LEN as u32),
                buf_ref.as_ptr() as *const _,
            );
        }
        event.flags = 0;
        event.ret = -1;
        entry.submit(0);
    }

    if is_enforce() { Ok(-1) } else { Ok(0) }
}

// --- Shared helpers ---

#[inline(always)]
fn lookup_root(tgid: u32) -> u32 {
    WATCHED_PIDS
        .get_ptr(&tgid)
        .map(|p| unsafe { *p })
        .unwrap_or(tgid)
}

/// Fill common event header using the current task's TGID (process ID).
#[inline(always)]
fn fill_header(h: &mut EventHeader, event_type: u32) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    fill_header_with_tgid(h, event_type, tgid, lookup_root(tgid));
}

/// Fill header with an explicit root_pid (used by fork where root comes
/// from the parent's TGID, not the current task).
#[inline(always)]
fn fill_header_with_root(h: &mut EventHeader, event_type: u32, root_pid: u32) {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    fill_header_with_tgid(h, event_type, tgid, root_pid);
}

#[inline(always)]
fn fill_header_with_tgid(h: &mut EventHeader, event_type: u32, tgid: u32, root_pid: u32) {
    let uid_gid = bpf_get_current_uid_gid();

    h.event_type = event_type;
    h.pid = tgid;
    h.root_pid = root_pid;
    h.uid = uid_gid as u32;
    h.timestamp_ns = unsafe { gen::bpf_ktime_get_ns() };
    h.comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => {
            // Zero comm byte-by-byte. Array literals and core::mem::zeroed()
            // both emit memset calls to .text, which aya 0.13 can't link into
            // per-section LSM programs.
            h.comm[0] = 0;
            return;
        }
    };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
