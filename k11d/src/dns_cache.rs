//! Lightweight reverse-DNS cache. Cache miss signals the caller to spawn a
//! background lookup; the result is inserted when ready. Subsequent lookups
//! for the same address see the in-flight state and skip re-spawning.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

pub struct DnsCache {
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

struct Entry {
    hostname: Option<String>,
    in_flight: bool,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Parse an address string as an `IpAddr`, stripping optional IPv6 square brackets.
    pub fn parse_ip(addr: &str) -> Option<IpAddr> {
        let bare = addr.trim_start_matches('[').trim_end_matches(']');
        bare.parse().ok()
    }

    /// Look up the cached hostname for `addr`. On cache miss, record an
    /// in-flight placeholder and return `(None, true)` — the caller should
    /// spawn a lookup. Further calls before `insert` return `(None, false)`.
    pub fn get_or_spawn(&self, addr: &str) -> (Option<String>, bool) {
        let Some(ip) = Self::parse_ip(addr) else {
            return (None, false);
        };
        let mut map = self.entries.lock().unwrap();
        if let Some(entry) = map.get(&ip) {
            return (entry.hostname.clone(), false);
        }
        map.insert(ip, Entry { hostname: None, in_flight: true });
        (None, true)
    }

    /// Store the result of a background lookup.
    pub fn insert(&self, ip: IpAddr, hostname: Option<String>) {
        let mut map = self.entries.lock().unwrap();
        map.insert(ip, Entry { hostname, in_flight: false });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_handles_brackets() {
        assert!(DnsCache::parse_ip("127.0.0.1").is_some());
        assert!(DnsCache::parse_ip("[::1]").is_some());
        assert!(DnsCache::parse_ip("::1").is_some());
        assert!(DnsCache::parse_ip("not-an-ip").is_none());
    }

    #[test]
    fn first_miss_requests_spawn() {
        let cache = DnsCache::new();
        let (hostname, spawn) = cache.get_or_spawn("8.8.8.8");
        assert!(hostname.is_none());
        assert!(spawn);
        // Second call for same addr sees the in-flight entry.
        let (hostname, spawn) = cache.get_or_spawn("8.8.8.8");
        assert!(hostname.is_none());
        assert!(!spawn);
    }

    #[test]
    fn insert_makes_hostname_visible() {
        let cache = DnsCache::new();
        let (_, _) = cache.get_or_spawn("1.1.1.1");
        let ip = DnsCache::parse_ip("1.1.1.1").unwrap();
        cache.insert(ip, Some("one.one.one.one".into()));
        let (hostname, spawn) = cache.get_or_spawn("1.1.1.1");
        assert_eq!(hostname.as_deref(), Some("one.one.one.one"));
        assert!(!spawn);
    }
}
