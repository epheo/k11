#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
/// Shorter path for dual-path events (rename, symlink) to stay within BPF's 512-byte stack limit.
pub const DUAL_PATH_LEN: usize = 192;

pub const EVENT_EXECVE: u32 = 1;
pub const EVENT_OPENAT: u32 = 2;
pub const EVENT_CONNECT: u32 = 3;
pub const EVENT_FORK: u32 = 4;
pub const EVENT_EXIT: u32 = 5;
pub const EVENT_UNIX_CONNECT: u32 = 6;
pub const EVENT_DENY_OPENAT: u32 = 7;
pub const EVENT_BIND: u32 = 10;
pub const EVENT_LISTEN: u32 = 11;
pub const EVENT_UNLINK: u32 = 12;
pub const EVENT_RENAME: u32 = 13;
pub const EVENT_CHMOD: u32 = 14;
pub const EVENT_CHOWN: u32 = 15;
pub const EVENT_SYMLINK: u32 = 16;
pub const EVENT_PTRACE: u32 = 17;

pub const CONFIG_WATCH_ALL: u32 = 1;
pub const CONFIG_ENFORCE: u32 = 2;

pub const POLICY_PATH_LEN: usize = 128;
pub const MAX_DENY_PATHS: u32 = 32;

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const UNIX_PATH_LEN: usize = 108;

// Tracepoint field offset indices (for OFFSETS BPF array map).
// Values are populated at runtime from tracefs format files.
pub const OFF_FORK_CHILD_PID: u32 = 0;
pub const OFF_EXEC_FILENAME: u32 = 1;
pub const OFF_OPENAT_FILENAME: u32 = 2;
pub const OFF_OPENAT_FLAGS: u32 = 3;
pub const OFF_OPENAT_RET: u32 = 4;
pub const OFF_CONNECT_ADDR: u32 = 5;
pub const OFF_CONNECT_RET: u32 = 6;
// OFF_FILE_F_PATH is passed via .rodata global, not the OFFSETS map,
// because bpf_d_path requires a constant offset for BTF type resolution.

// Tier 1+2 syscall tracepoint offsets
pub const OFF_BIND_ADDR: u32 = 7;
pub const OFF_BIND_RET: u32 = 8;
pub const OFF_LISTEN_BACKLOG: u32 = 9;
pub const OFF_LISTEN_RET: u32 = 10;
pub const OFF_UNLINK_PATHNAME: u32 = 11;
pub const OFF_UNLINK_FLAGS: u32 = 12;
pub const OFF_UNLINK_RET: u32 = 13;
pub const OFF_RENAME_OLDNAME: u32 = 14;
pub const OFF_RENAME_NEWNAME: u32 = 15;
pub const OFF_RENAME_RET: u32 = 16;
pub const OFF_CHMOD_FILENAME: u32 = 17;
pub const OFF_CHMOD_MODE: u32 = 18;
pub const OFF_CHMOD_RET: u32 = 19;
pub const OFF_CHOWN_FILENAME: u32 = 20;
pub const OFF_CHOWN_UID: u32 = 21;
pub const OFF_CHOWN_GID: u32 = 22;
pub const OFF_CHOWN_RET: u32 = 23;
pub const OFF_SYMLINK_OLDNAME: u32 = 24;
pub const OFF_SYMLINK_NEWNAME: u32 = 25;
pub const OFF_SYMLINK_RET: u32 = 26;
pub const OFF_PTRACE_REQUEST: u32 = 27;
pub const OFF_PTRACE_PID: u32 = 28;
pub const OFF_PTRACE_RET: u32 = 29;
pub const OFFSETS_LEN: u32 = 30;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventHeader {
    pub event_type: u32,
    pub pid: u32,
    pub root_pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecveEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenatEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub flags: i32,
    /// Syscall return value: fd (>=0) on success, negative errno on failure.
    pub ret: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub header: EventHeader,
    pub addr_v4: u32,
    pub addr_v6: [u8; 16],
    pub port: u16,
    pub af: u16,
    /// Syscall return value: 0 on success, negative errno on failure.
    pub ret: i32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnixConnectEvent {
    pub header: EventHeader,
    pub path: [u8; UNIX_PATH_LEN],
    /// Syscall return value: 0 on success, negative errno on failure.
    pub ret: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub header: EventHeader,
    pub child_pid: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub header: EventHeader,
}

// --- Tier 1+2 event structs ---

/// Used by renameat2 and symlinkat (two paths + ret).
/// Uses DUAL_PATH_LEN (192) instead of PATH_LEN (256) to fit within BPF's 512-byte stack limit.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RenameEvent {
    pub header: EventHeader,
    pub old_path: [u8; DUAL_PATH_LEN],
    pub new_path: [u8; DUAL_PATH_LEN],
    pub ret: i32,
    pub _padding: u32,
}

/// Used by fchownat (filename + uid + gid + ret).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChownEvent {
    pub header: EventHeader,
    pub filename: [u8; PATH_LEN],
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub ret: i32,
    pub _padding: u32,
}

/// Used by ptrace (request + target_pid + ret).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub header: EventHeader,
    pub request: u32,
    pub target_pid: u32,
    pub ret: i32,
    pub _padding: u32,
}

/// Used by listen (backlog + ret).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListenEvent {
    pub header: EventHeader,
    pub backlog: i32,
    pub ret: i32,
}

// Prevent silent ABI breakage between BPF and userspace targets.
const _: () = assert!(core::mem::size_of::<EventHeader>() == 40);
const _: () = assert!(core::mem::size_of::<ExecveEvent>() == 296);
const _: () = assert!(core::mem::size_of::<OpenatEvent>() == 304);
const _: () = assert!(core::mem::size_of::<ConnectEvent>() == 72);
const _: () = assert!(core::mem::size_of::<UnixConnectEvent>() == 152);
const _: () = assert!(core::mem::size_of::<ForkEvent>() == 48);
const _: () = assert!(core::mem::size_of::<ExitEvent>() == 40);
const _: () = assert!(core::mem::size_of::<RenameEvent>() == 432);
const _: () = assert!(core::mem::size_of::<ChownEvent>() == 312);
const _: () = assert!(core::mem::size_of::<PtraceEvent>() == 56);
const _: () = assert!(core::mem::size_of::<ListenEvent>() == 48);

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OpenatEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for UnixConnectEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ForkEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExitEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RenameEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ChownEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PtraceEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ListenEvent {}
