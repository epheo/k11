//! Linux 6.19 to 7.1 lose syscall enter programs on most CPUs.
//!
//! These kernels copy a syscall's string arguments into its trace record
//! before running BPF. Stable backports of "tracing: perf: Fix stale head for
//! perf syscall tracing" then return early when this CPU holds no perf event
//! for the tracepoint, skipping the programs. A program's own event sits on
//! CPU 0 (aya and libbpf both attach there), so opens, execs and renames on
//! every other CPU went unrecorded. An idle counting event on each other CPU
//! restores them; it never counts, because the programs return 0. Linux 7.2
//! runs the programs first.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

use anyhow::{Context, Result};
use aya_obj::generated::{
    perf_event_attr, perf_type_id::PERF_TYPE_TRACEPOINT, PERF_FLAG_FD_CLOEXEC,
};

/// Whether this kernel needs the cover for an enter tracepoint whose format
/// shows copied arguments.
pub fn needed(release: &str) -> bool {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let mut next = || parts.next().and_then(|p| p.parse::<u32>().ok());
    matches!((next(), next()), (Some(major), Some(minor)) if (major, minor) < (7, 2))
}

/// One counting event per tracepoint on every online CPU but 0. The events
/// stay open as long as the returned fds.
pub fn open(tracepoint_ids: &[u64]) -> Result<Vec<OwnedFd>> {
    if tracepoint_ids.is_empty() {
        return Ok(Vec::new());
    }
    let cpus = aya::util::online_cpus().map_err(|(path, e)| anyhow::anyhow!("{path}: {e}"))?;
    raise_nofile();
    let mut fds = Vec::new();
    for &id in tracepoint_ids {
        for &cpu in cpus.iter().filter(|&&cpu| cpu != 0) {
            fds.push(
                open_counting(id, cpu)
                    .with_context(|| format!("perf event for tracepoint {id} on CPU {cpu}"))?,
            );
        }
    }
    Ok(fds)
}

fn open_counting(id: u64, cpu: u32) -> io::Result<OwnedFd> {
    // SAFETY: perf_event_attr is plain data; zero is "no options".
    let mut attr: perf_event_attr = unsafe { std::mem::zeroed() };
    attr.type_ = PERF_TYPE_TRACEPOINT as u32;
    attr.size = size_of::<perf_event_attr>() as u32;
    attr.config = id;
    // SAFETY: a valid attr; pid -1 with a CPU is a system-wide event there.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr,
            -1,
            cpu as libc::c_int,
            -1,
            PERF_FLAG_FD_CLOEXEC as libc::c_ulong,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Tracepoints times CPUs can exceed the default soft limit of 1024.
fn raise_nofile() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointers; failure leaves the limit as it was.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::needed;

    #[test]
    fn kernels_before_7_2_need_cover() {
        assert!(needed("7.0.0-1017-azure"));
        assert!(needed("7.1.5"));
        assert!(needed("6.19.3-200.fc43.x86_64"));
        assert!(!needed("7.2.8-200.fc44.x86_64"));
        assert!(!needed("7.10.0"));
        assert!(!needed("8.0"));
        assert!(!needed("unknown"));
    }
}
