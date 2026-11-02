#![no_std]
#![no_main]

use core::mem::{offset_of, size_of};

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, gen},
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use k11_common::{
    arg, syscall_arg_offset, ChownEvent, ConnectEvent, EventHeader, ExecveEvent, ExitEvent,
    ForkEvent, ListenEvent, PathEvent, PathPairEvent, PtraceEvent, RawEvent, UnixConnectEvent,
    AF_INET, AF_INET6, AF_UNIX, AT_FDCWD, CLONE_THREAD, COMM_LEN, CONFIG_ENFORCE, CONFIG_WATCH_ALL,
    CREAT_FLAGS, EPERM, EVENT_BIND, EVENT_CHMOD, EVENT_CHOWN, EVENT_CONNECT, EVENT_EXECVE,
    EVENT_EXIT, EVENT_FORK, EVENT_LISTEN, EVENT_OPENAT, EVENT_OPENAT_AUDITED, EVENT_OPENAT_DENIED,
    EVENT_PTRACE, EVENT_RENAME, EVENT_SYMLINK, EVENT_UNIX_CONNECT, EVENT_UNLINK, KOFF_COUNT,
    KOFF_FILE_F_FLAGS, KOFF_FILE_F_PATH, MAX_DENY_PATHS, MAX_EVENT_SIZE, OFFSETS_LEN,
    OFF_EXEC_FILENAME, OFF_EXEC_OLD_PID, OFF_EXIT_GROUP_DEAD, OFF_FORK_CHILD_PID,
    OFF_FORK_CLONE_FLAGS, PATH_LEN, POLICY_PATH_LEN, STAT_COUNT, STAT_LINEAGE_FULL,
    STAT_PENDING_FULL, STAT_READ_FAILED, STAT_RING_FULL, SYSCALL_RET_OFFSET, UNIX_PATH_LEN,
};

// The byte size here is a placeholder: the daemon sets the real size at load
// time from config (probe.ring_buffer_kb).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_COUNT, 0);

/// Lineage: tgid to the root tgid of its agent tree.
#[map]
static WATCHED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

/// The record built at sys_enter, keyed by pid_tgid, waiting for the result
/// at sys_exit. A thread is in at most one syscall, so one slot per thread
/// serves every traced syscall. `header.len == 0` marks a record that must
/// not be output: an exec in progress, or an open the LSM hook already
/// reported.
#[map]
static PENDING: HashMap<u64, RawEvent> = HashMap::with_max_entries(10240, 0);

/// Build space: records do not fit the BPF stack. Slot 0 is for tracepoint
/// programs, which run with preemption disabled. Slot 1 is for the LSM hook,
/// which can be preempted but never runs twice at once on one CPU (the
/// kernel's per-program recursion guard skips the second entry).
#[map]
static SCRATCH: PerCpuArray<RawEvent> = PerCpuArray::with_max_entries(2, 0);
const SLOT_TP: u32 = 0;
const SLOT_LSM: u32 = 1;

/// Comm names that start a new agent tree on exec.
#[map]
static WATCH_COMMS: HashMap<[u8; COMM_LEN], u8> = HashMap::with_max_entries(64, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

/// `TRACEPOINT_FIELDS` offsets, discovered from tracefs by the daemon.
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(OFFSETS_LEN, 0);

/// `struct file` offsets from BTF (`KOFF_*` indices), set as .rodata before
/// load. Read through volatile so the zero initializer is never folded; the
/// verifier still sees constants, which bpf_d_path needs to type `file +
/// f_path` as `struct path *`.
#[no_mangle]
static K_OFFSETS: [u32; KOFF_COUNT] = [0; KOFF_COUNT];

#[map]
static DENY_FILE_PATHS: Array<[u8; POLICY_PATH_LEN]> = Array::with_max_entries(MAX_DENY_PATHS, 0);
#[map]
static DENY_FILE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// Shared helpers. Everything is inline(always): aya 0.13 cannot link .text
// subprograms into LSM sections, and inlining keeps one verifier unit per
// program.
// ---------------------------------------------------------------------------

#[inline(always)]
fn count(stat: u32) {
    if let Some(c) = STATS.get_ptr_mut(stat) {
        unsafe { *c += 1 };
    }
}

#[inline(always)]
fn config_flags() -> u32 {
    unsafe { CONFIG.get_ptr(0).map(|p| *p).unwrap_or(0) }
}

#[inline(always)]
fn koff(index: usize) -> u64 {
    unsafe { core::ptr::read_volatile(K_OFFSETS.as_ptr().add(index)) as u64 }
}

/// Root of the agent tree `tgid` belongs to. In watch-all mode an unknown
/// process is its own root, so trees still form for pre-existing processes.
/// One lookup: checking membership and reading the root separately let a
/// concurrent leader exit slip between the two.
#[inline(always)]
fn resolve_root(tgid: u32) -> Option<u32> {
    match WATCHED_PIDS.get_ptr(&tgid) {
        Some(p) => Some(unsafe { *p }),
        None if config_flags() & CONFIG_WATCH_ALL != 0 => Some(tgid),
        None => None,
    }
}

#[inline(always)]
fn tp_offset(index: u32) -> usize {
    unsafe { OFFSETS.get_ptr(index).map(|p| *p as usize).unwrap_or(0) }
}

#[inline(always)]
fn fill_header(h: &mut EventHeader, event_type: u32, tgid: u32, root: u32) {
    h.event_type = event_type;
    h.pid = tgid;
    h.root_pid = root;
    h.uid = bpf_get_current_uid_gid() as u32;
    h.timestamp_ns = unsafe { gen::bpf_ktime_get_boot_ns() };
    h.ret = 0;
    h.len = 0;
    // Straight into the record: the safe wrapper zeroes a stack array first,
    // which compiles to a memset subprogram aya cannot link into LSM sections.
    let r = unsafe { gen::bpf_get_current_comm(h.comm.as_mut_ptr() as *mut _, COMM_LEN as u32) };
    if r < 0 {
        h.comm[0] = 0;
    }
}

/// pid_tgid, tgid and tree root of the current task, or None when it is not
/// watched. Called before any other work so unwatched processes pay one map
/// lookup.
#[inline(always)]
fn caller() -> Option<(u64, u32, u32)> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let root = resolve_root(tgid)?;
    Some((pid_tgid, tgid, root))
}

/// Start a record in `slot` with a filled header.
#[inline(always)]
fn begin(slot: u32, event_type: u32, tgid: u32, root: u32) -> Option<*mut RawEvent> {
    let raw = SCRATCH.get_ptr_mut(slot)?;
    fill_header(unsafe { &mut (*raw).header }, event_type, tgid, root);
    Some(raw)
}

/// Write the first `len` bytes of a record to the ring. `len` is clamped so
/// the verifier can bound the access whatever the record says.
#[inline(always)]
fn submit(raw: *const RawEvent, len: u32) {
    let mut len = len as usize;
    if len > MAX_EVENT_SIZE {
        len = MAX_EVENT_SIZE;
    }
    let bytes = unsafe { core::slice::from_raw_parts(raw as *const u8, len) };
    if EVENTS.output(bytes, 0).is_err() {
        count(STAT_RING_FULL);
    }
}

/// Park a sys_enter record until sys_exit supplies the result.
#[inline(always)]
fn stash(pid_tgid: u64, raw: *mut RawEvent, len: usize) {
    unsafe { (*raw).header.len = len as u32 };
    if PENDING.insert(&pid_tgid, unsafe { &*raw }, 0).is_err() {
        count(STAT_PENDING_FULL);
    }
}

/// A read failure drops the event and counts it, rather than recording a
/// made-up value.
#[inline(always)]
fn run(result: Result<(), i64>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(_) => {
            count(STAT_READ_FAILED);
            1
        }
    }
}

#[inline(always)]
fn arg(ctx: &TracePointContext, index: usize) -> Result<u64, i64> {
    unsafe { ctx.read_at::<u64>(syscall_arg_offset(index)) }
}

/// Where an argument comes from: a syscall slot, or a constant the syscall
/// implies (creat's open flags, unlink's zero flags).
#[derive(Clone, Copy)]
enum Src {
    Arg(usize),
    Fixed(i32),
}

#[inline(always)]
fn src(ctx: &TracePointContext, s: Src) -> Result<i32, i64> {
    match s {
        Src::Arg(i) => Ok(arg(ctx, i)? as i32),
        Src::Fixed(v) => Ok(v),
    }
}

/// Copy a NUL-terminated user string; returns bytes written including the
/// NUL. A null pointer yields an empty string: the syscall will fail with
/// EFAULT and the record shows exactly that.
#[inline(always)]
fn read_user_str(dst: *mut u8, cap: usize, src: u64) -> Result<usize, i64> {
    if src == 0 {
        unsafe { *dst = 0 };
        return Ok(1);
    }
    let n = unsafe { gen::bpf_probe_read_user_str(dst as *mut _, cap as u32, src as *const _) };
    if n < 0 {
        Err(n)
    } else {
        Ok(n as usize)
    }
}

#[inline(always)]
fn read_user_into(dst: *mut u8, len: usize, src: u64) -> Result<(), i64> {
    let r = unsafe { gen::bpf_probe_read_user(dst as *mut _, len as u32, src as *const _) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

#[inline(always)]
fn read_user_u16(src: u64) -> Result<u16, i64> {
    let mut v: u16 = 0;
    read_user_into(&mut v as *mut u16 as *mut u8, 2, src)?;
    Ok(v)
}

#[inline(always)]
fn read_user_u64(src: u64) -> Result<u64, i64> {
    let mut v: u64 = 0;
    read_user_into(&mut v as *mut u64 as *mut u8, 8, src)?;
    Ok(v)
}

#[inline(always)]
fn read_kernel_into(dst: *mut u8, len: usize, src: u64) -> Result<(), i64> {
    let r = unsafe { gen::bpf_probe_read_kernel(dst as *mut _, len as u32, src as *const _) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// Copy a NUL-terminated kernel string; returns bytes written including the NUL.
#[inline(always)]
fn read_kernel_str(dst: *mut u8, cap: usize, src: u64) -> Result<usize, i64> {
    let n = unsafe { gen::bpf_probe_read_kernel_str(dst as *mut _, cap as u32, src as *const _) };
    if n < 0 {
        Err(n)
    } else {
        Ok(n as usize)
    }
}

// ---------------------------------------------------------------------------
// Syscall enter programs. Each stashes a record; k11_syscall_exit finishes it.
// ---------------------------------------------------------------------------

macro_rules! path_syscall {
    ($prog:ident, $event:expr, dfd: $dfd:expr, path: $path:expr, flags: $flags:expr) => {
        #[tracepoint]
        pub fn $prog(ctx: TracePointContext) -> u32 {
            #[inline(always)]
            fn handle(ctx: &TracePointContext) -> Result<(), i64> {
                let Some((pid_tgid, tgid, root)) = caller() else {
                    return Ok(());
                };
                let Some(raw) = begin(SLOT_TP, $event, tgid, root) else {
                    return Ok(());
                };
                let ev = unsafe { &mut (*raw).path };
                ev.dfd = src(ctx, $dfd)?;
                ev.flags = src(ctx, $flags)?;
                let n = read_user_str(ev.path.as_mut_ptr(), PATH_LEN, arg(ctx, $path)?)?;
                stash(pid_tgid, raw, offset_of!(PathEvent, path) + n);
                Ok(())
            }
            run(handle(&ctx))
        }
    };
}

macro_rules! path_pair_syscall {
    ($prog:ident, $event:expr, dfd: $dfd:expr, path: $path:expr, dfd2: $dfd2:expr, path2: $path2:expr) => {
        #[tracepoint]
        pub fn $prog(ctx: TracePointContext) -> u32 {
            #[inline(always)]
            fn handle(ctx: &TracePointContext) -> Result<(), i64> {
                let Some((pid_tgid, tgid, root)) = caller() else {
                    return Ok(());
                };
                let Some(raw) = begin(SLOT_TP, $event, tgid, root) else {
                    return Ok(());
                };
                let ev = unsafe { &mut (*raw).pair };
                ev.dfd = src(ctx, $dfd)?;
                ev.dfd2 = src(ctx, $dfd2)?;
                ev._pad = 0;
                let mut n1 = read_user_str(ev.paths.as_mut_ptr(), PATH_LEN, arg(ctx, $path)?)?;
                if n1 > PATH_LEN {
                    n1 = PATH_LEN;
                }
                ev.first_len = n1 as u32;
                let second = unsafe { ev.paths.as_mut_ptr().add(n1) };
                let n2 = read_user_str(second, PATH_LEN, arg(ctx, $path2)?)?;
                stash(pid_tgid, raw, offset_of!(PathPairEvent, paths) + n1 + n2);
                Ok(())
            }
            run(handle(&ctx))
        }
    };
}

macro_rules! chown_syscall {
    ($prog:ident, dfd: $dfd:expr, path: $path:expr, user: $user:expr, group: $group:expr) => {
        #[tracepoint]
        pub fn $prog(ctx: TracePointContext) -> u32 {
            #[inline(always)]
            fn handle(ctx: &TracePointContext) -> Result<(), i64> {
                let Some((pid_tgid, tgid, root)) = caller() else {
                    return Ok(());
                };
                let Some(raw) = begin(SLOT_TP, EVENT_CHOWN, tgid, root) else {
                    return Ok(());
                };
                let ev = unsafe { &mut (*raw).chown };
                ev.dfd = src(ctx, $dfd)?;
                ev.owner_uid = arg(ctx, $user)? as u32;
                ev.owner_gid = arg(ctx, $group)? as u32;
                ev._pad = 0;
                let n = read_user_str(ev.path.as_mut_ptr(), PATH_LEN, arg(ctx, $path)?)?;
                stash(pid_tgid, raw, offset_of!(ChownEvent, path) + n);
                Ok(())
            }
            run(handle(&ctx))
        }
    };
}

/// connect and bind. AF_UNIX is recorded for connect only; a bound unix
/// socket is low signal for an agent.
macro_rules! sockaddr_syscall {
    ($prog:ident, $event:expr, addr: $addr:expr, unix: $unix:expr) => {
        #[tracepoint]
        pub fn $prog(ctx: TracePointContext) -> u32 {
            #[inline(always)]
            fn handle(ctx: &TracePointContext) -> Result<(), i64> {
                let Some((pid_tgid, tgid, root)) = caller() else {
                    return Ok(());
                };
                let sockaddr = arg(ctx, $addr)?;
                if sockaddr == 0 {
                    return Ok(());
                }
                let family = read_user_u16(sockaddr)?;
                if family == AF_INET || family == AF_INET6 {
                    let Some(raw) = begin(SLOT_TP, $event, tgid, root) else {
                        return Ok(());
                    };
                    let ev = unsafe { &mut (*raw).connect };
                    ev.af = family;
                    ev._pad = 0;
                    // Port sits at offset 2 in both sockaddr_in and sockaddr_in6.
                    ev.port = u16::from_be(read_user_u16(sockaddr + 2)?);
                    if family == AF_INET {
                        read_user_into(ev.addr.as_mut_ptr(), 4, sockaddr + 4)?;
                    } else {
                        read_user_into(ev.addr.as_mut_ptr(), 16, sockaddr + 8)?;
                    }
                    stash(pid_tgid, raw, size_of::<ConnectEvent>());
                } else if family == AF_UNIX && $unix {
                    let Some(raw) = begin(SLOT_TP, EVENT_UNIX_CONNECT, tgid, root) else {
                        return Ok(());
                    };
                    let ev = unsafe { &mut (*raw).unix };
                    // sun_path starts at offset 2 in sockaddr_un.
                    let n = read_user_str(ev.path.as_mut_ptr(), UNIX_PATH_LEN, sockaddr + 2)?;
                    stash(pid_tgid, raw, offset_of!(UnixConnectEvent, path) + n);
                }
                // AF_UNSPEC (UDP disconnect) and other families carry no signal.
                Ok(())
            }
            run(handle(&ctx))
        }
    };
}

path_syscall!(k11_open, EVENT_OPENAT,
    dfd: Src::Fixed(AT_FDCWD), path: arg::open::filename, flags: Src::Arg(arg::open::flags));
path_syscall!(k11_openat, EVENT_OPENAT,
    dfd: Src::Arg(arg::openat::dfd), path: arg::openat::filename, flags: Src::Arg(arg::openat::flags));
path_syscall!(k11_creat, EVENT_OPENAT,
    dfd: Src::Fixed(AT_FDCWD), path: arg::creat::pathname, flags: Src::Fixed(CREAT_FLAGS));
path_syscall!(k11_unlink, EVENT_UNLINK,
    dfd: Src::Fixed(AT_FDCWD), path: arg::unlink::pathname, flags: Src::Fixed(0));
path_syscall!(k11_unlinkat, EVENT_UNLINK,
    dfd: Src::Arg(arg::unlinkat::dfd), path: arg::unlinkat::pathname, flags: Src::Arg(arg::unlinkat::flag));
path_syscall!(k11_chmod, EVENT_CHMOD,
    dfd: Src::Fixed(AT_FDCWD), path: arg::chmod::filename, flags: Src::Arg(arg::chmod::mode));
path_syscall!(k11_fchmodat, EVENT_CHMOD,
    dfd: Src::Arg(arg::fchmodat::dfd), path: arg::fchmodat::filename, flags: Src::Arg(arg::fchmodat::mode));
path_syscall!(k11_fchmodat2, EVENT_CHMOD,
    dfd: Src::Arg(arg::fchmodat2::dfd), path: arg::fchmodat2::filename, flags: Src::Arg(arg::fchmodat2::mode));

path_pair_syscall!(k11_rename, EVENT_RENAME,
    dfd: Src::Fixed(AT_FDCWD), path: arg::rename::oldname,
    dfd2: Src::Fixed(AT_FDCWD), path2: arg::rename::newname);
path_pair_syscall!(k11_renameat, EVENT_RENAME,
    dfd: Src::Arg(arg::renameat::olddfd), path: arg::renameat::oldname,
    dfd2: Src::Arg(arg::renameat::newdfd), path2: arg::renameat::newname);
path_pair_syscall!(k11_renameat2, EVENT_RENAME,
    dfd: Src::Arg(arg::renameat2::olddfd), path: arg::renameat2::oldname,
    dfd2: Src::Arg(arg::renameat2::newdfd), path2: arg::renameat2::newname);
// For symlinks the first path is the target (stored verbatim in the link,
// never resolved) and the second is the link being created.
path_pair_syscall!(k11_symlink, EVENT_SYMLINK,
    dfd: Src::Fixed(AT_FDCWD), path: arg::symlink::oldname,
    dfd2: Src::Fixed(AT_FDCWD), path2: arg::symlink::newname);
path_pair_syscall!(k11_symlinkat, EVENT_SYMLINK,
    dfd: Src::Fixed(AT_FDCWD), path: arg::symlinkat::oldname,
    dfd2: Src::Arg(arg::symlinkat::newdfd), path2: arg::symlinkat::newname);

chown_syscall!(k11_chown,
    dfd: Src::Fixed(AT_FDCWD), path: arg::chown::filename, user: arg::chown::user, group: arg::chown::group);
chown_syscall!(k11_lchown,
    dfd: Src::Fixed(AT_FDCWD), path: arg::lchown::filename, user: arg::lchown::user, group: arg::lchown::group);
chown_syscall!(k11_fchownat,
    dfd: Src::Arg(arg::fchownat::dfd), path: arg::fchownat::filename, user: arg::fchownat::user, group: arg::fchownat::group);

sockaddr_syscall!(k11_connect, EVENT_CONNECT, addr: arg::connect::uservaddr, unix: true);
sockaddr_syscall!(k11_bind, EVENT_BIND, addr: arg::bind::umyaddr, unix: false);

/// openat2 takes its flags from a user-space `struct open_how { u64 flags;
/// u64 mode; u64 resolve; }`.
#[tracepoint]
pub fn k11_openat2(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let Some((pid_tgid, tgid, root)) = caller() else {
            return Ok(());
        };
        let Some(raw) = begin(SLOT_TP, EVENT_OPENAT, tgid, root) else {
            return Ok(());
        };
        let ev = unsafe { &mut (*raw).path };
        ev.dfd = arg(ctx, arg::openat2::dfd)? as i32;
        let how = arg(ctx, arg::openat2::how)?;
        ev.flags = if how == 0 {
            0
        } else {
            read_user_u64(how)? as i32
        };
        let n = read_user_str(
            ev.path.as_mut_ptr(),
            PATH_LEN,
            arg(ctx, arg::openat2::filename)?,
        )?;
        stash(pid_tgid, raw, offset_of!(PathEvent, path) + n);
        Ok(())
    }
    run(handle(&ctx))
}

#[tracepoint]
pub fn k11_listen(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let Some((pid_tgid, tgid, root)) = caller() else {
            return Ok(());
        };
        let Some(raw) = begin(SLOT_TP, EVENT_LISTEN, tgid, root) else {
            return Ok(());
        };
        let ev = unsafe { &mut (*raw).listen };
        ev.backlog = arg(ctx, arg::listen::backlog)? as i32;
        ev._pad = 0;
        stash(pid_tgid, raw, size_of::<ListenEvent>());
        Ok(())
    }
    run(handle(&ctx))
}

#[tracepoint]
pub fn k11_ptrace(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let Some((pid_tgid, tgid, root)) = caller() else {
            return Ok(());
        };
        let Some(raw) = begin(SLOT_TP, EVENT_PTRACE, tgid, root) else {
            return Ok(());
        };
        let ev = unsafe { &mut (*raw).ptrace };
        ev.request = arg(ctx, arg::ptrace::request)? as u32;
        ev.target_pid = arg(ctx, arg::ptrace::pid)? as u32;
        stash(pid_tgid, raw, size_of::<PtraceEvent>());
        Ok(())
    }
    run(handle(&ctx))
}

/// execve and execveat: nothing to report at exit (sched_process_exec does
/// that), but while the marker is parked the LSM hook knows that opens are
/// the kernel loading the image, not the process reading files.
#[tracepoint]
pub fn k11_exec_marker(_ctx: TracePointContext) -> u32 {
    let Some((pid_tgid, _, _)) = caller() else {
        return 0;
    };
    let Some(raw) = SCRATCH.get_ptr_mut(SLOT_TP) else {
        return 0;
    };
    unsafe {
        (*raw).header.event_type = EVENT_EXECVE;
    }
    stash(pid_tgid, raw, 0);
    0
}

/// Attached to every traced sys_exit_*: stamp the result on the parked
/// record and ship it. An open the LSM hook already recorded has `len == 0`
/// and is dropped here, so each syscall yields exactly one event. Relative
/// paths are made absolute in userspace (dfd-aware), keyed by the dfd this
/// record carries.
#[tracepoint]
pub fn k11_syscall_exit(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let pid_tgid = bpf_get_current_pid_tgid();
        let Some(raw) = PENDING.get_ptr_mut(&pid_tgid) else {
            return Ok(());
        };
        let outcome = unsafe { ctx.read_at::<i64>(SYSCALL_RET_OFFSET) }.map(|ret| {
            unsafe { (*raw).header.ret = ret as i32 };
            let len = unsafe { (*raw).header.len };
            if len > 0 {
                submit(raw, len);
            }
        });
        let _ = PENDING.remove(&pid_tgid);
        outcome
    }
    run(handle(&ctx))
}

// ---------------------------------------------------------------------------
// Process lifecycle
// ---------------------------------------------------------------------------

/// task_newtask fires in the parent once the child exists, before it runs.
/// Lineage is looked up by tgid, so a new thread needs no entry and is not a
/// new process: only processes are inserted and reported.
#[tracepoint]
pub fn k11_fork(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let Some((_, parent, root)) = caller() else {
            return Ok(());
        };
        // Little-endian: the low 32 bits carry CLONE_THREAD whether the
        // kernel declares the field 4 or 8 bytes wide.
        let clone_flags: u32 = unsafe { ctx.read_at(tp_offset(OFF_FORK_CLONE_FLAGS))? };
        if clone_flags & CLONE_THREAD != 0 {
            return Ok(());
        }
        let child: i32 = unsafe { ctx.read_at(tp_offset(OFF_FORK_CHILD_PID))? };
        let child = child as u32;
        if WATCHED_PIDS.insert(&child, &root, 0).is_err() {
            count(STAT_LINEAGE_FULL);
        }
        match EVENTS.reserve::<ForkEvent>(0) {
            Some(mut entry) => {
                let ev = unsafe { &mut *entry.as_mut_ptr() };
                fill_header(&mut ev.header, EVENT_FORK, parent, root);
                ev.header.len = size_of::<ForkEvent>() as u32;
                ev.child_pid = child;
                ev._pad = 0;
                entry.submit(0);
            }
            None => count(STAT_RING_FULL),
        }
        Ok(())
    }
    run(handle(&ctx))
}

/// sched_process_exit fires once per thread; the process ends with its last
/// thread. Recent kernels say so (`group_dead`). Older ones do not, and the
/// leader's exit stands in: a leader that leaves before its threads, or is
/// replaced by an exec from another thread, ends the record early.
#[tracepoint]
pub fn k11_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    // A thread that dies inside a syscall never reaches sys_exit.
    let _ = PENDING.remove(&pid_tgid);
    let leader = pid_tgid as u32 == tgid;
    let process_ends = match tp_offset(OFF_EXIT_GROUP_DEAD) {
        0 => leader,
        off => unsafe { ctx.read_at::<u8>(off) }.map_or(leader, |dead| dead != 0),
    };
    if !process_ends {
        return 0;
    }
    // Resolve the root before removing the entry, or the Exit event loses
    // its tree in watch-specific mode.
    let root = resolve_root(tgid);
    let _ = WATCHED_PIDS.remove(&tgid);
    let Some(root) = root else {
        return 0;
    };
    match EVENTS.reserve::<ExitEvent>(0) {
        Some(mut entry) => {
            let ev = unsafe { &mut *entry.as_mut_ptr() };
            fill_header(&mut ev.header, EVENT_EXIT, tgid, root);
            ev.header.len = size_of::<ExitEvent>() as u32;
            entry.submit(0);
        }
        None => count(STAT_RING_FULL),
    }
    0
}

/// sched_process_exec fires after the image is replaced, so comm is the new
/// binary's name: a watched name launched from an unwatched shell is found
/// here and becomes the root of a new tree.
#[tracepoint]
pub fn k11_exec(ctx: TracePointContext) -> u32 {
    #[inline(always)]
    fn handle(ctx: &TracePointContext) -> Result<(), i64> {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let known = resolve_root(tgid);
        if known.is_some() {
            // The exec succeeded: its parked record is done. An exec from a
            // non-leader thread took over the leader's pid, so the record is
            // parked under the thread's old one.
            let old_pid: i32 = unsafe { ctx.read_at(tp_offset(OFF_EXEC_OLD_PID))? };
            let _ = PENDING.remove(&(((tgid as u64) << 32) | old_pid as u32 as u64));
        }
        // The header is filled first: the comm it captures is the discovery key.
        let Some(raw) = begin(SLOT_TP, EVENT_EXECVE, tgid, known.unwrap_or(tgid)) else {
            return Ok(());
        };
        let ev = unsafe { &mut (*raw).execve };
        if known.is_none() {
            if WATCH_COMMS.get_ptr(&ev.header.comm).is_none() {
                return Ok(());
            }
            if WATCHED_PIDS.insert(&tgid, &tgid, 0).is_err() {
                count(STAT_LINEAGE_FULL);
            }
        }
        // __data_loc: low 16 bits are the offset of the string in the record.
        let data_loc: u32 = unsafe { ctx.read_at(tp_offset(OFF_EXEC_FILENAME))? };
        let src = unsafe { (ctx.as_ptr() as *const u8).add((data_loc & 0xffff) as usize) };
        let n = read_kernel_str(ev.filename.as_mut_ptr(), PATH_LEN, src as u64)?;
        ev.header.len = (offset_of!(ExecveEvent, filename) + n) as u32;
        submit(raw, ev.header.len);
        Ok(())
    }
    run(handle(&ctx))
}

// ---------------------------------------------------------------------------
// LSM file_open: the canonical open recorder and the enforcement point.
//
// This hook runs inside the opening syscall after path lookup, so it sees the
// resolved path (dirfd honoured, symlinks followed, no user-memory race) for
// every open that reaches a file, whatever syscall made it. It records the
// open and blanks the record sys_enter parked, so sys_exit only reports opens
// that failed before reaching a file. Without BPF LSM the tracepoint pair
// alone records every open with the path as requested.
//
// One open syscall has one user-visible file: any further file_open inside
// the same syscall is the filesystem opening a backing file (overlayfs,
// copy-up). Those, like the kernel's own opens during exec, still go through
// the deny rules but are not recorded unless a rule matches.
// ---------------------------------------------------------------------------

#[inline(always)]
fn deny_rule_count() -> u32 {
    unsafe { DENY_FILE_COUNT.get_ptr(0).map(|p| *p).unwrap_or(0) }
}

/// Prefix match against the deny rules. Both loops have compile-time bounds.
#[inline(always)]
fn matches_deny_paths(path: &[u8; PATH_LEN], count: u32) -> bool {
    let mut i: u32 = 0;
    while i < MAX_DENY_PATHS {
        if i >= count {
            break;
        }
        if let Some(prefix_ptr) = DENY_FILE_PATHS.get_ptr(i) {
            let prefix = unsafe { &*prefix_ptr };
            let mut matched = true;
            let mut j: usize = 0;
            while j < POLICY_PATH_LEN {
                if prefix[j] == 0 {
                    break;
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

/// Written out instead of `#[lsm]`: the macro's wrapper returns i32, which
/// LLVM zero-extends into r0, so a negative errno reaches the verifier as a
/// large positive value and fails the [-4095, 0] range check newer kernels
/// apply to LSM return values. A 64-bit return keeps the sign, and passing
/// the previous program's result through keeps the range the kernel knows.
#[no_mangle]
#[link_section = "lsm/file_open"]
pub fn k11_lsm_file_open(ctx: *mut core::ffi::c_void) -> i64 {
    let ctx = LsmContext::new(ctx);
    match handle_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => {
            count(STAT_READ_FAILED);
            0
        }
    }
}

#[inline(always)]
fn handle_file_open(ctx: &LsmContext) -> Result<i64, i64> {
    // An earlier program on this hook already refused: sys_exit will record
    // the failure.
    let retval: i64 = unsafe { ctx.arg(1) };
    if retval != 0 {
        return Ok(retval);
    }
    let Some((pid_tgid, tgid, root)) = caller() else {
        return Ok(0);
    };
    let file: *const u8 = unsafe { ctx.arg(0) };
    if file.is_null() {
        return Ok(0);
    }
    let Some(raw) = SCRATCH.get_ptr_mut(SLOT_LSM) else {
        return Ok(0);
    };
    let ev = unsafe { &mut (*raw).path };

    let pending = PENDING.get_ptr_mut(&pid_tgid);
    let nested = pending.is_some_and(|p| unsafe { (*p).header.len } == 0);

    // Resolve first: when d_path cannot render the path (too long, foreign
    // mount namespace) the parked record stays and sys_exit reports the
    // request as made.
    let path_off = koff(KOFF_FILE_F_PATH) as usize;
    let n = unsafe {
        gen::bpf_d_path(
            file.add(path_off) as *mut _,
            ev.path.as_mut_ptr() as *mut _,
            PATH_LEN as u32,
        )
    };
    if n <= 0 {
        return Ok(0);
    }

    fill_header(&mut ev.header, EVENT_OPENAT, tgid, root);
    let mut flags: u32 = 0;
    read_kernel_into(
        &mut flags as *mut u32 as *mut u8,
        4,
        file as u64 + koff(KOFF_FILE_F_FLAGS),
    )?;
    ev.flags = flags as i32;
    ev.dfd = AT_FDCWD;

    let rules = deny_rule_count();
    let matched = rules > 0 && matches_deny_paths(&ev.path, rules);
    if nested && !matched {
        return Ok(0);
    }
    let enforce = matched && config_flags() & CONFIG_ENFORCE != 0;
    if enforce {
        ev.header.event_type = EVENT_OPENAT_DENIED;
        ev.header.ret = -EPERM;
    } else if matched {
        ev.header.event_type = EVENT_OPENAT_AUDITED;
    }
    ev.header.len = (offset_of!(PathEvent, path) + n as usize) as u32;
    submit(raw, ev.header.len);

    // The parked open record is now spoken for; sys_exit drops it.
    if let Some(p) = pending {
        if unsafe { (*p).header.event_type } == EVENT_OPENAT {
            unsafe { (*p).header.len = 0 };
        }
    }

    Ok(if enforce { -(EPERM as i64) } else { 0 })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
