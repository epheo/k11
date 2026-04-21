use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

const SUCCESS_TTL_SECS: u64 = 300; // 5 minutes
const FAILURE_TTL_SECS: u64 = 120; // 2 minutes

struct CacheEntry {
    hostname: Option<String>,
    resolved_at: Instant,
    in_flight: bool,
}

pub struct DnsCache {
    inner: Mutex<HashMap<IpAddr, CacheEntry>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Parse an address string (possibly bracketed IPv6) into an IpAddr.
    pub fn parse_ip(addr: &str) -> Option<IpAddr> {
        addr.trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()
    }

    /// Returns `(cached_hostname, should_spawn_lookup)`.
    /// Atomically checks and marks in-flight to prevent duplicate lookups.
    pub fn get_or_spawn(&self, addr: &str) -> (Option<String>, bool) {
        let ip = match Self::parse_ip(addr) {
            Some(ip) => ip,
            None => return (None, false),
        };

        // Skip localhost addresses
        if ip.is_loopback() || addr == "0.0.0.0" {
            return (None, false);
        }

        let mut cache = self.inner.lock().unwrap();

        if let Some(entry) = cache.get_mut(&ip) {
            let ttl = if entry.hostname.is_some() {
                SUCCESS_TTL_SECS
            } else {
                FAILURE_TTL_SECS
            };

            if entry.resolved_at.elapsed().as_secs() < ttl {
                return (entry.hostname.clone(), false);
            }

            // Expired — mark in-flight for re-resolve
            if !entry.in_flight {
                entry.in_flight = true;
                return (entry.hostname.clone(), true);
            }
            return (entry.hostname.clone(), false);
        }

        // Not in cache — insert in-flight placeholder
        cache.insert(
            ip,
            CacheEntry {
                hostname: None,
                resolved_at: Instant::now(),
                in_flight: true,
            },
        );
        (None, true)
    }

    /// Store the result of a DNS lookup.
    pub fn insert(&self, ip: IpAddr, hostname: Option<String>) {
        let mut cache = self.inner.lock().unwrap();
        cache.insert(
            ip,
            CacheEntry {
                hostname,
                resolved_at: Instant::now(),
                in_flight: false,
            },
        );
    }
}
