//! Wire format between the k11 eBPF probe and the daemon.
//!
//! Every ring buffer record starts with an `EventHeader`. Records whose last
//! field is a string are trimmed after the NUL, so a record is a prefix of one
//! of the structs below; `EventHeader::len` says how long. The daemon copies a
//! record into a zeroed `RawEvent` before reading it, which keeps every string
//! NUL-terminated regardless of how much was trimmed.
//!
//! 64-bit kernels only: syscall argument slots are 8 bytes wide.

#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
/// Bytes of a command line kept; `ExecEvent::args_len` says when more ran.
pub const ARGS_LEN: usize = 1024;
pub const UNIX_PATH_LEN: usize = 108;
pub const POLICY_PATH_LEN: usize = 128;
pub const MAX_DENY_PATHS: u32 = 32;
/// The deny-path array holds two rule sets: the daemon writes the idle one,
/// then publishes it in one store to `DENY_RULES` as `deny_rules(first, count)`.
/// A set is never written while the probe can be reading it.
pub const DENY_PATH_SLOTS: u32 = 2 * MAX_DENY_PATHS;

#[inline(always)]
pub const fn deny_rules(first: u32, count: u32) -> u32 {
    (first << 16) | count
}

pub const EVENT_EXECVE: u32 = 1;
pub const EVENT_OPEN: u32 = 2;
pub const EVENT_CONNECT: u32 = 3;
pub const EVENT_FORK: u32 = 4;
pub const EVENT_EXIT: u32 = 5;
pub const EVENT_UNIX_CONNECT: u32 = 6;
/// Matched a deny rule while enforcing: the open failed with EPERM.
pub const EVENT_OPEN_DENIED: u32 = 7;
/// Matched a deny rule in audit mode: the open went ahead.
pub const EVENT_OPEN_AUDITED: u32 = 8;
pub const EVENT_BIND: u32 = 10;
pub const EVENT_LISTEN: u32 = 11;
pub const EVENT_UNLINK: u32 = 12;
pub const EVENT_RENAME: u32 = 13;
pub const EVENT_CHMOD: u32 = 14;
pub const EVENT_CHOWN: u32 = 15;
pub const EVENT_SYMLINK: u32 = 16;
pub const EVENT_PTRACE: u32 = 17;
/// A successful exec, with its command line (`ExecEvent`). `EVENT_EXECVE`
/// is the attempt, shipped only when it fails.
pub const EVENT_EXEC: u32 = 18;
/// A getaddrinfo call: the name asked and what it resolved to (`ResolveEvent`).
pub const EVENT_RESOLVE: u32 = 19;

/// Addresses kept per lookup; getaddrinfo lists each one per socket type.
pub const RESOLVE_ADDRS: usize = 12;

pub const CONFIG_WATCH_ALL: u32 = 1;
pub const CONFIG_ENFORCE: u32 = 2;

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// The kernel's AT_FDCWD. Also used by records whose path is already absolute.
pub const AT_FDCWD: i32 = -100;
pub const EPERM: i32 = 1;
/// creat(2) is openat with these flags.
pub const CREAT_FLAGS: i32 = 0x40 | 0x1 | 0x200;

// Per-CPU counters the probe increments and the daemon reports. Every branch
// that loses or refuses an event counts it, so the record is never silently
// incomplete and never carries invented values.
pub const STAT_RING_FULL: u32 = 0;
pub const STAT_PENDING_FULL: u32 = 1;
pub const STAT_LINEAGE_FULL: u32 = 2;
pub const STAT_READ_FAILED: u32 = 3;
pub const STAT_COUNT: u32 = 4;

// Process lifecycle tracepoint layouts changed across kernel versions, so
// these offsets are discovered from tracefs at startup and handed to the
// probe via a map. An optional field the kernel lacks reads as offset 0,
// which no real field has (the common header sits there).
pub const OFF_FORK_CHILD_PID: u32 = 0;
pub const OFF_FORK_CLONE_FLAGS: u32 = 1;
pub const OFF_EXEC_FILENAME: u32 = 2;
pub const OFF_EXEC_OLD_PID: u32 = 3;
pub const OFF_EXIT_GROUP_DEAD: u32 = 4;
pub const OFFSETS_LEN: u32 = 5;

/// (index, category, tracepoint, field, optional) for every `OFF_*`.
pub const TRACEPOINT_FIELDS: [(u32, &str, &str, &str, bool); OFFSETS_LEN as usize] = [
    (OFF_FORK_CHILD_PID, "task", "task_newtask", "pid", false),
    (
        OFF_FORK_CLONE_FLAGS,
        "task",
        "task_newtask",
        "clone_flags",
        false,
    ),
    (
        OFF_EXEC_FILENAME,
        "sched",
        "sched_process_exec",
        "filename",
        false,
    ),
    (
        OFF_EXEC_OLD_PID,
        "sched",
        "sched_process_exec",
        "old_pid",
        false,
    ),
    // Recent kernels only; without it the leader's exit ends the process.
    (
        OFF_EXIT_GROUP_DEAD,
        "sched",
        "sched_process_exit",
        "group_dead",
        true,
    ),
];

pub const CLONE_THREAD: u32 = 0x0001_0000;

// syscalls/sys_enter_* records are `trace_entry` (8 bytes), `int nr`, then
// one 8-byte slot per argument; sys_exit_* is `trace_entry`, `int nr`, `long
// ret`. The daemon checks this against tracefs before attaching.
pub const SYSCALL_ARGS_OFFSET: usize = 16;
pub const SYSCALL_ARG_SIZE: usize = 8;
pub const SYSCALL_RET_OFFSET: usize = 16;

#[inline(always)]
pub const fn syscall_arg_offset(index: usize) -> usize {
    SYSCALL_ARGS_OFFSET + index * SYSCALL_ARG_SIZE
}

/// One traced syscall: the tracepoint suffix, the probe's enter program, and
/// the argument slots that program reads with the field name tracefs must
/// show at each. Every syscall shares the exit program `k11_syscall_exit`.
pub struct Syscall {
    pub name: &'static str,
    pub enter_prog: &'static str,
    pub args: &'static [(usize, &'static str)],
}

macro_rules! syscalls {
    ($( $name:ident => $prog:ident { $( $arg:ident = $idx:expr ),* $(,)? } )*) => {
        pub const SYSCALLS: &[Syscall] = &[
            $( Syscall {
                name: stringify!($name),
                enter_prog: stringify!($prog),
                args: &[ $( ($idx, stringify!($arg)) ),* ],
            }, )*
        ];

        /// Argument slot per syscall, for the probe's enter handlers.
        pub mod arg {
            $( #[allow(non_upper_case_globals)]
            pub mod $name { $( pub const $arg: usize = $idx; )* } )*
        }
    };
}

// glibc on x86_64 uses the legacy forms (unlink, rename, chmod, chown,
// symlink); arm64 only has the *at forms. The daemon attaches whichever
// exist on the running kernel.
syscalls! {
    open      => k11_open      { filename = 0, flags = 1 }
    openat    => k11_openat    { dfd = 0, filename = 1, flags = 2 }
    openat2   => k11_openat2   { dfd = 0, filename = 1, how = 2 }
    creat     => k11_creat     { pathname = 0 }
    unlink    => k11_unlink    { pathname = 0 }
    unlinkat  => k11_unlinkat  { dfd = 0, pathname = 1, flag = 2 }
    rename    => k11_rename    { oldname = 0, newname = 1 }
    renameat  => k11_renameat  { olddfd = 0, oldname = 1, newdfd = 2, newname = 3 }
    renameat2 => k11_renameat2 { olddfd = 0, oldname = 1, newdfd = 2, newname = 3 }
    chmod     => k11_chmod     { filename = 0, mode = 1 }
    fchmodat  => k11_fchmodat  { dfd = 0, filename = 1, mode = 2 }
    fchmodat2 => k11_fchmodat2 { dfd = 0, filename = 1, mode = 2 }
    chown     => k11_chown     { filename = 0, user = 1, group = 2 }
    lchown    => k11_lchown    { filename = 0, user = 1, group = 2 }
    fchownat  => k11_fchownat  { dfd = 0, filename = 1, user = 2, group = 3 }
    symlink   => k11_symlink   { oldname = 0, newname = 1 }
    symlinkat => k11_symlinkat { oldname = 0, newdfd = 1, newname = 2 }
    connect   => k11_connect   { uservaddr = 1 }
    bind      => k11_bind      { umyaddr = 1 }
    listen    => k11_listen    { backlog = 1 }
    ptrace    => k11_ptrace    { request = 0, pid = 1 }
    execve    => k11_execve    { filename = 0 }
    execveat  => k11_execveat  { fd = 0, filename = 1, flags = 4 }
}

pub const SYSCALL_EXIT_PROG: &str = "k11_syscall_exit";

/// ptrace requests worth a record: taking a tracee (TRACEME, ATTACH, SEIZE)
/// or writing into one (POKE*, SET*REGS, SETREGSET, SETSIGINFO). Reads and
/// resumes follow an attach already recorded, and a tracer issues them by
/// the thousand per second.
#[inline(always)]
pub const fn ptrace_recorded(request: u32) -> bool {
    matches!(
        request,
        0 | 4 | 5 | 6 | 13 | 15 | 16 | 0x4203 | 0x4205 | 0x4206
    )
}

// Kernel struct field offsets, read from BTF by the daemon and handed over
// as one .rodata array (`K_OFFSETS`) so the verifier sees constants:
// bpf_d_path requires `file + f_path` to type as `struct path *`. The LSM
// hook needs the `struct file` ones; exec needs the rest for argv, and they
// stay 0 unless BTF has them all.
pub const KOFF_FILE_F_PATH: usize = 0;
pub const KOFF_FILE_F_FLAGS: usize = 1;
pub const KOFF_TASK_MM: usize = 2;
pub const KOFF_MM_ARG_START: usize = 3;
pub const KOFF_MM_ARG_END: usize = 4;
pub const KOFF_COUNT: usize = 5;

/// (index, struct, field) for every `KOFF_*`.
pub const KERNEL_FIELDS: [(usize, &str, &str); KOFF_COUNT] = [
    (KOFF_FILE_F_PATH, "file", "f_path"),
    (KOFF_FILE_F_FLAGS, "file", "f_flags"),
    (KOFF_TASK_MM, "task_struct", "mm"),
    (KOFF_MM_ARG_START, "mm_struct", "arg_start"),
    (KOFF_MM_ARG_END, "mm_struct", "arg_end"),
];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub event_type: u32,
    pub pid: u32,
    pub root_pid: u32,
    pub uid: u32,
    /// CLOCK_BOOTTIME nanoseconds, so timestamps survive suspend.
    pub timestamp_ns: u64,
    /// The task's cgroup (v2) id: names its container, if any.
    pub cgroup_id: u64,
    pub comm: [u8; COMM_LEN],
    /// Syscall result: fd or 0 on success, negative errno on failure. Zero
    /// for fork, exit and a successful exec.
    pub ret: i32,
    /// Bytes of this record actually written to the ring.
    pub len: u32,
}

/// open/openat/openat2/creat (flags), unlink/unlinkat (flags),
/// chmod/fchmodat/fchmodat2 (mode carried in `flags`), and execve/execveat
/// (execveat flags).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathEvent {
    pub header: EventHeader,
    pub flags: i32,
    /// Directory fd the path is relative to; AT_FDCWD when absolute.
    pub dfd: i32,
    pub path: [u8; PATH_LEN],
}

/// rename/renameat/renameat2 and symlink/symlinkat. Both strings are packed
/// back to back in `paths`, each NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathPairEvent {
    pub header: EventHeader,
    pub dfd: i32,
    pub dfd2: i32,
    pub paths: [u8; 2 * PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChownEvent {
    pub header: EventHeader,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub dfd: i32,
    pub _pad: u32,
    pub path: [u8; PATH_LEN],
}

/// connect and bind. `addr` holds 4 bytes for AF_INET, 16 for AF_INET6,
/// both in network byte order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub header: EventHeader,
    pub addr: [u8; 16],
    pub port: u16,
    pub af: u16,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnixConnectEvent {
    pub header: EventHeader,
    pub path: [u8; UNIX_PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub header: EventHeader,
    pub child_pid: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub header: EventHeader,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenEvent {
    pub header: EventHeader,
    pub backlog: i32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub header: EventHeader,
    pub request: u32,
    pub target_pid: u32,
}

/// Storage large enough for any record. The probe builds and stashes events
/// in one of these; the daemon decodes into one.
#[repr(C)]
#[derive(Clone, Copy)]
pub union RawEvent {
    pub header: EventHeader,
    pub path: PathEvent,
    pub pair: PathPairEvent,
    pub chown: ChownEvent,
    pub connect: ConnectEvent,
    pub unix: UnixConnectEvent,
    pub fork: ForkEvent,
    pub exit: ExitEvent,
    pub listen: ListenEvent,
    pub ptrace: PtraceEvent,
}

pub const MAX_EVENT_SIZE: usize = core::mem::size_of::<RawEvent>();

/// A successful exec: the new image's path, and argv as the kernel laid it
/// out, NUL-separated. Built in the ring rather than in `Pending`, so the
/// per-thread slots do not grow by a command line.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    /// argv's whole length; past `ARGS_LEN`, `args` holds its start.
    pub args_len: u32,
    pub _pad: u32,
    pub path: [u8; PATH_LEN],
    /// Valid up to `header.len`; the rest is whatever the ring held.
    pub args: [u8; ARGS_LEN],
}

/// A name a process looked up through libc, and the first `RESOLVE_ADDRS`
/// answers. `header.ret` is getaddrinfo's: 0, or an EAI_ code.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ResolveEvent {
    pub header: EventHeader,
    pub count: u32,
    pub _pad: u32,
    /// AF_INET or AF_INET6 per address.
    pub families: [u16; RESOLVE_ADDRS],
    /// 4 bytes for AF_INET, 16 for AF_INET6, in network byte order.
    pub addrs: [[u8; 16]; RESOLVE_ADDRS],
    pub name: [u8; PATH_LEN],
}

/// What the ring carries.
#[repr(C)]
#[derive(Clone, Copy)]
pub union WireEvent {
    pub raw: RawEvent,
    pub exec: ExecEvent,
    pub resolve: ResolveEvent,
}

pub const MAX_WIRE_SIZE: usize = core::mem::size_of::<WireEvent>();

/// A syscall in flight: the record being built and what sys_exit and the LSM
/// hook need to finish it. Never shipped as is.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pending {
    pub event: RawEvent,
    /// User pointers the record's strings (or sockaddr) come from. A page the
    /// process never touched is not resident at sys_enter and cannot be read
    /// there; by sys_exit the kernel has faulted it in.
    pub user: [u64; 2],
    pub flags: u32,
    pub _pad: u32,
}

/// Read `user` again at sys_exit.
pub const PENDING_DEFERRED: u32 = 1;
/// The LSM hook put the opened file's canonical path in the record.
pub const PENDING_RESOLVED: u32 = 2;

// Both sides compile these asserts, so an ABI drift fails the build.
const _: () = assert!(core::mem::size_of::<EventHeader>() == 56);
const _: () = assert!(core::mem::size_of::<PathEvent>() == 320);
const _: () = assert!(core::mem::size_of::<PathPairEvent>() == 576);
const _: () = assert!(core::mem::size_of::<ChownEvent>() == 328);
const _: () = assert!(core::mem::size_of::<ConnectEvent>() == 80);
const _: () = assert!(core::mem::size_of::<UnixConnectEvent>() == 168);
const _: () = assert!(core::mem::size_of::<ForkEvent>() == 64);
const _: () = assert!(core::mem::size_of::<ExitEvent>() == 56);
const _: () = assert!(core::mem::size_of::<ListenEvent>() == 64);
const _: () = assert!(core::mem::size_of::<PtraceEvent>() == 64);
const _: () = assert!(MAX_EVENT_SIZE == 576);
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 1344);
const _: () = assert!(MAX_WIRE_SIZE == 1344);
const _: () = assert!(core::mem::size_of::<ResolveEvent>() == 536);
// The probe bounds the argv copy with a mask.
const _: () = assert!(ARGS_LEN.is_power_of_two());
const _: () = assert!(core::mem::align_of::<RawEvent>() == 8);
const _: () = assert!(core::mem::size_of::<Pending>() == 600);
