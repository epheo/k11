//! Path and address classification shared by the store, the OCSF mapper and
//! the wire events, so the dashboard never has to reimplement it.

use std::borrow::Cow;
use std::net::IpAddr;

/// Canonical list of sensitive paths.
pub const SENSITIVE_PATHS: &[&str] = &[
    ".ssh/",
    ".gnupg/",
    ".aws/",
    ".kube/",
    ".docker/",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
    "/root/",
];

pub fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.iter().any(|p| path.contains(p))
}

/// Parse an address as the probe renders it (IPv6 in brackets).
pub fn parse_ip(addr: &str) -> Option<IpAddr> {
    addr.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// External = routable beyond this machine and its private networks.
/// Loopback, RFC1918, link-local, unspecified, and IPv6 unique-local are not
/// external. Unparseable addresses (e.g. "af=5") count as external.
pub fn is_external_addr(addr: &str) -> bool {
    match parse_ip(addr) {
        Some(IpAddr::V4(ip)) => {
            !(ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified())
        }
        Some(IpAddr::V6(ip)) => {
            let seg0 = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00   // unique local fc00::/7
                || (seg0 & 0xffc0) == 0xfe80) // link local fe80::/10
        }
        None => true,
    }
}

/// Map a negative syscall return value to its errno name.
pub fn errno_name(ret: i32) -> Cow<'static, str> {
    let name = match -ret {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
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
        40 => "ELOOP",
        61 => "ENODATA",
        98 => "EADDRINUSE",
        99 => "EADDRNOTAVAIL",
        100 => "ENETDOWN",
        101 => "ENETUNREACH",
        103 => "ECONNABORTED",
        104 => "ECONNRESET",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        113 => "EHOSTUNREACH",
        114 => "EALREADY",
        115 => "EINPROGRESS",
        n => return Cow::Owned(format!("E?{n}")),
    };
    Cow::Borrowed(name)
}

/// "ok" or the errno name.
pub fn status(ret: i32) -> Cow<'static, str> {
    if ret >= 0 {
        Cow::Borrowed("ok")
    } else {
        errno_name(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_addr_classification() {
        assert!(is_external_addr("8.8.8.8"));
        assert!(is_external_addr("[2606:4700::1111]"));
        assert!(!is_external_addr("127.0.0.1"));
        assert!(!is_external_addr("127.1.2.3"));
        assert!(!is_external_addr("10.0.0.5"));
        assert!(!is_external_addr("192.168.1.1"));
        assert!(!is_external_addr("172.16.0.1"));
        assert!(!is_external_addr("172.31.255.1"));
        assert!(is_external_addr("172.32.0.1"));
        assert!(!is_external_addr("169.254.1.1"));
        assert!(!is_external_addr("0.0.0.0"));
        assert!(!is_external_addr("[::1]"));
        assert!(!is_external_addr("[fd00::1]"));
        assert!(!is_external_addr("[fe80::1]"));
        assert!(is_external_addr("af=5"));
    }

    #[test]
    fn errno_names() {
        assert_eq!(errno_name(-2), "ENOENT");
        assert_eq!(errno_name(-999), "E?999");
        assert_eq!(status(3), "ok");
        assert_eq!(status(-13), "EACCES");
    }
}
