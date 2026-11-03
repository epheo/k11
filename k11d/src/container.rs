//! Which container, if any, an event's process runs in.
//!
//! The probe stamps every record with the task's cgroup v2 id. That id is
//! also a kernfs file handle for the cgroup's directory, and container
//! runtimes put the container's id in that directory's path. Processes on
//! the host or in a VM resolve to none.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use k11_proto as proto;
use tracing::info;

#[derive(Debug, PartialEq, Eq)]
pub struct Container {
    /// podman, docker, containerd, cri-o or lxc.
    pub runtime: &'static str,
    /// A 64-hex id, or an LXC container's name.
    pub id: String,
}

impl Container {
    /// As `podman ps` and `docker ps` show it.
    pub fn short_id(&self) -> &str {
        if is_id(&self.id) {
            &self.id[..12]
        } else {
            &self.id
        }
    }
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.runtime, self.short_id())
    }
}

impl From<&Container> for proto::Container {
    fn from(c: &Container) -> Self {
        Self {
            runtime: c.runtime.into(),
            id: c.id.clone(),
        }
    }
}

/// Cgroups come and go with every container and session; past this many
/// resolved ids the cache starts over.
const CACHE_MAX: usize = 4096;

pub struct Containers {
    /// The cgroup2 mount the handles resolve against. Without one, nothing
    /// resolves.
    mount: Option<File>,
    cache: HashMap<u64, Option<Arc<Container>>>,
}

impl Containers {
    pub fn new() -> Self {
        let mount = cgroup2_mount().and_then(|path| File::open(path).ok());
        if mount.is_none() {
            info!("no cgroup2 mount: events will not name their container");
        }
        Self {
            mount,
            cache: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            mount: None,
            cache: HashMap::new(),
        }
    }

    pub fn lookup(&mut self, cgroup_id: u64) -> Option<Arc<Container>> {
        if let Some(known) = self.cache.get(&cgroup_id) {
            return known.clone();
        }
        let mount = self.mount.as_ref()?;
        // Cgroup ids are never reused, so a cgroup already gone stays none.
        let found = cgroup_path(mount, cgroup_id)
            .and_then(|path| parse(&path))
            .map(Arc::new);
        if self.cache.len() >= CACHE_MAX {
            self.cache.clear();
        }
        self.cache.insert(cgroup_id, found.clone());
        found
    }
}

fn cgroup2_mount() -> Option<String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    // 30 23 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw
    mountinfo
        .lines()
        .find_map(|line| {
            let (fields, fs) = line.split_once(" - ")?;
            (fs.split_whitespace().next()? == "cgroup2")
                .then(|| fields.split_whitespace().nth(4))?
        })
        .map(String::from)
}

/// The cgroup directory's path, through its kernfs file handle.
fn cgroup_path(mount: &File, cgroup_id: u64) -> Option<String> {
    #[repr(C)]
    struct KernfsHandle {
        handle_bytes: u32,
        handle_type: i32,
        id: u64,
    }
    const FILEID_KERNFS: i32 = 0xfe;
    let mut handle = KernfsHandle {
        handle_bytes: 8,
        handle_type: FILEID_KERNFS,
        id: cgroup_id,
    };
    // SAFETY: a file_handle header followed by its 8 bytes of handle.
    let fd = unsafe {
        libc::open_by_handle_at(
            mount.as_raw_fd(),
            &mut handle as *mut KernfsHandle as *mut libc::file_handle,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).ok()?;
    Some(path.to_string_lossy().into_owned())
}

/// The container a cgroup path names. A container that runs its own
/// systemd nests cgroups under its own, and a container can run inside
/// another: the innermost match is the one the process is in.
fn parse(path: &str) -> Option<Container> {
    const SCOPES: [(&str, &str); 4] = [
        ("libpod-", "podman"),
        ("docker-", "docker"),
        ("cri-containerd-", "containerd"),
        ("crio-", "cri-o"),
    ];
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate().rev() {
        // systemd driver: libpod-<id>.scope; podman's cgroupfs driver drops
        // the suffix. Conmon's own libpod-conmon-<id> is not an id.
        let unit = part.strip_suffix(".scope").unwrap_or(part);
        for (prefix, runtime) in SCOPES {
            if let Some(id) = unit.strip_prefix(prefix).filter(|id| is_id(id)) {
                return Some(Container {
                    runtime,
                    id: id.into(),
                });
            }
        }
        // docker's cgroupfs driver: /docker/<id>.
        if is_id(part) && i > 0 && parts[i - 1] == "docker" {
            return Some(Container {
                runtime: "docker",
                id: part.to_string(),
            });
        }
        // LXC and Incus.
        if let Some(name) = part.strip_prefix("lxc.payload.").filter(|n| !n.is_empty()) {
            return Some(Container {
                runtime: "lxc",
                id: name.into(),
            });
        }
    }
    None
}

fn is_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f2a1b9c0d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";

    fn found(path: &str) -> Option<(&'static str, String)> {
        parse(path).map(|c| (c.runtime, c.id))
    }

    #[test]
    fn runtimes_by_cgroup_path() {
        let id = ID.to_string();
        let cases = [
            (format!("/sys/fs/cgroup/machine.slice/libpod-{ID}.scope"), "podman"),
            (
                format!("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{ID}.scope/container"),
                "podman",
            ),
            (format!("/sys/fs/cgroup/libpod_parent/libpod-{ID}"), "podman"),
            (format!("/sys/fs/cgroup/system.slice/docker-{ID}.scope"), "docker"),
            (format!("/sys/fs/cgroup/docker/{ID}"), "docker"),
            (
                format!("/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1.slice/cri-containerd-{ID}.scope"),
                "containerd",
            ),
            (format!("/sys/fs/cgroup/kubepods.slice/crio-{ID}.scope"), "cri-o"),
        ];
        for (path, runtime) in cases {
            assert_eq!(found(&path), Some((runtime, id.clone())), "{path}");
        }
        assert_eq!(
            found("/sys/fs/cgroup/lxc.payload.web/init.scope"),
            Some(("lxc", "web".into()))
        );
    }

    #[test]
    fn host_and_runtime_helpers_are_not_containers() {
        for path in [
            "/sys/fs/cgroup/user.slice/user-1000.slice/session-2.scope".to_string(),
            "/sys/fs/cgroup/system.slice/sshd.service".to_string(),
            format!("/sys/fs/cgroup/machine.slice/libpod-conmon-{ID}.scope"),
            format!("/sys/fs/cgroup/system.slice/crio-conmon-{ID}.scope"),
            "/sys/fs/cgroup/".to_string(),
        ] {
            assert_eq!(found(&path), None, "{path}");
        }
    }

    #[test]
    fn innermost_container_wins() {
        let inner = "a".repeat(64);
        let path = format!("/sys/fs/cgroup/system.slice/docker-{ID}.scope/libpod-{inner}.scope");
        assert_eq!(found(&path), Some(("podman", inner)));
    }

    #[test]
    fn short_id_as_runtimes_print_it() {
        let c = Container {
            runtime: "podman",
            id: ID.into(),
        };
        assert_eq!(c.to_string(), "podman 3f2a1b9c0d4e");
        let lxc = Container {
            runtime: "lxc",
            id: "web".into(),
        };
        assert_eq!(lxc.to_string(), "lxc web");
    }
}
