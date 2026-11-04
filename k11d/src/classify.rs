//! Path, address and result classification shared by the store, the OCSF
//! mapper and the wire events, so the dashboard never has to reimplement it.

use std::borrow::Cow;
use std::net::IpAddr;

/// Absolute locations holding secrets, matched as path prefixes on
/// component boundaries (`/root` covers `/root/x`, not `/rootfs`).
const SENSITIVE_ROOTS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
    "/root",
    // k11's own control token, state and config: an agent reading them is
    // probing its recorder.
    "/run/k11",
    "/var/lib/k11",
    "/etc/k11",
];

/// Credential directories under any home, matched as whole components.
const SENSITIVE_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".config/gcloud",
    ".config/gh",
];

/// Credential files wherever they sit, matched by file name.
const SENSITIVE_NAMES: &[&str] = &[
    ".env",
    ".envrc",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".pgpass",
];

/// `path` is `dir` or lies under it.
pub fn is_under(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// `seq` appears in `path` as whole components.
fn has_components(path: &str, seq: &str) -> bool {
    path.match_indices(seq).any(|(i, _)| {
        path[..i].ends_with('/') && matches!(path.as_bytes().get(i + seq.len()), None | Some(b'/'))
    })
}

pub fn is_sensitive_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    SENSITIVE_ROOTS.iter().any(|root| is_under(path, root))
        || SENSITIVE_DIRS.iter().any(|dir| has_components(path, dir))
        || SENSITIVE_NAMES.contains(&name)
        || name.starts_with(".env.")
}

/// Routable beyond this machine and its private networks. v4-mapped IPv6
/// addresses (dual-stack sockets) are judged as the IPv4 address they carry.
pub fn is_external(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            let cgnat = a == 100 && (64..128).contains(&b);
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || cgnat)
        }
        IpAddr::V6(ip) => {
            let seg0 = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (seg0 & 0xffc0) == 0xfe80) // link local fe80::/10
        }
    }
}

/// Reachable from other hosts: a bind to anything but loopback, on a fixed
/// port (port 0 is a client picking its source address).
pub fn is_exposed(ip: IpAddr, port: u16) -> bool {
    port != 0 && !ip.to_canonical().is_loopback()
}

/// O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
pub fn opens_for_write(flags: i32) -> bool {
    flags & (0x1 | 0x2 | 0x40 | 0x200 | 0x400) != 0
}

const EINPROGRESS: i32 = 115;

/// The syscall failed. A non-blocking connect returning EINPROGRESS has
/// started, not failed.
pub fn failed(ret: i32) -> bool {
    ret < 0 && ret != -EINPROGRESS
}

/// Map a negative syscall return value to its errno name.
pub fn errno_name(ret: i32) -> Cow<'static, str> {
    let name = match -ret {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        17 => "EEXIST",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        26 => "ETXTBSY",
        28 => "ENOSPC",
        30 => "EROFS",
        36 => "ENAMETOOLONG",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        61 => "ENODATA",
        95 => "EOPNOTSUPP",
        97 => "EAFNOSUPPORT",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        106 => "EISCONN",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        n => return Cow::Owned(format!("E?{n}")),
    };
    Cow::Borrowed(name)
}

/// The errno name when the syscall failed, else None.
pub fn error(ret: i32) -> Option<Cow<'static, str>> {
    failed(ret).then(|| errno_name(ret))
}

/// The PTRACE_* name of a ptrace request.
pub fn ptrace_request(request: u32) -> Cow<'static, str> {
    let name = match request {
        0 => "PTRACE_TRACEME",
        1 => "PTRACE_PEEKTEXT",
        2 => "PTRACE_PEEKDATA",
        3 => "PTRACE_PEEKUSER",
        4 => "PTRACE_POKETEXT",
        5 => "PTRACE_POKEDATA",
        6 => "PTRACE_POKEUSER",
        7 => "PTRACE_CONT",
        8 => "PTRACE_KILL",
        9 => "PTRACE_SINGLESTEP",
        12 => "PTRACE_GETREGS",
        13 => "PTRACE_SETREGS",
        16 => "PTRACE_ATTACH",
        17 => "PTRACE_DETACH",
        24 => "PTRACE_SYSCALL",
        0x4200 => "PTRACE_SETOPTIONS",
        0x4201 => "PTRACE_GETEVENTMSG",
        0x4202 => "PTRACE_GETSIGINFO",
        0x4204 => "PTRACE_GETREGSET",
        0x4205 => "PTRACE_SETREGSET",
        0x4206 => "PTRACE_SEIZE",
        0x4207 => "PTRACE_INTERRUPT",
        n => return Cow::Owned(format!("ptrace request {n}")),
    };
    Cow::Borrowed(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn external_addresses() {
        for addr in ["8.8.8.8", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_external(ip(addr)), "{addr}");
        }
        for addr in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.251",
            "255.255.255.255",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::fb",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_external(ip(addr)), "{addr}");
        }
    }

    #[test]
    fn exposed_binds() {
        assert!(is_exposed(ip("0.0.0.0"), 8080));
        assert!(is_exposed(ip("::"), 8080));
        assert!(is_exposed(ip("192.168.1.5"), 22));
        assert!(!is_exposed(ip("127.0.0.1"), 8080));
        assert!(!is_exposed(ip("::ffff:127.0.0.1"), 8080));
        assert!(!is_exposed(ip("0.0.0.0"), 0));
    }

    #[test]
    fn sensitive_paths() {
        for path in [
            "/home/u/.ssh",
            "/home/u/.ssh/id_ed25519",
            "/root",
            "/root/.bashrc",
            "/etc/shadow",
            "/etc/sudoers.d/admins",
            "/home/u/.config/gh/hosts.yml",
            "/home/u/proj/.env",
            "/home/u/proj/.env.local",
            "/home/u/.netrc",
        ] {
            assert!(is_sensitive_path(path), "{path}");
        }
        for path in [
            "/etc/passwd",
            "/home/u/proj/root/x",
            "/rootfs/x",
            "/home/u/x.ssh/key",
            "/home/u/.ssh-backup/key",
            "/home/u/.config/ghostty",
            "/home/u/proj/.environment",
            "/etc/shadowsocks.json",
        ] {
            assert!(!is_sensitive_path(path), "{path}");
        }
    }

    #[test]
    fn results() {
        assert!(failed(-2));
        assert!(!failed(-115));
        assert!(!failed(3));
        assert_eq!(error(-2).as_deref(), Some("ENOENT"));
        assert_eq!(error(-115), None);
        assert_eq!(errno_name(-999), "E?999");
    }
}
