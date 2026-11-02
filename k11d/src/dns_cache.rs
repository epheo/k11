use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SUCCESS_TTL: Duration = Duration::from_secs(300);
const FAILURE_TTL: Duration = Duration::from_secs(120);
/// Expired entries are swept once the table grows past this.
const SWEEP_AT: usize = 10_000;

struct CacheEntry {
    hostname: Option<String>,
    resolved_at: Instant,
    in_flight: bool,
}

impl CacheEntry {
    fn expired(&self) -> bool {
        let ttl = if self.hostname.is_some() {
            SUCCESS_TTL
        } else {
            FAILURE_TTL
        };
        self.resolved_at.elapsed() >= ttl
    }
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

    /// The cached hostname, if any, without starting a lookup.
    pub fn cached(&self, ip: IpAddr) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .get(&ip)
            .and_then(|e| e.hostname.clone())
    }

    /// `(cached_hostname, caller_should_resolve)`. Marks the entry in flight
    /// atomically so one address gets one lookup at a time.
    pub fn get_or_claim(&self, ip: IpAddr) -> (Option<String>, bool) {
        if ip.is_loopback() || ip.is_unspecified() {
            return (None, false);
        }
        let mut cache = self.inner.lock().unwrap();
        match cache.get_mut(&ip) {
            Some(entry) => {
                let claim = entry.expired() && !entry.in_flight;
                if claim {
                    entry.in_flight = true;
                }
                (entry.hostname.clone(), claim)
            }
            None => {
                if cache.len() >= SWEEP_AT {
                    cache.retain(|_, e| e.in_flight || !e.expired());
                }
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
        }
    }

    pub fn insert(&self, ip: IpAddr, hostname: Option<String>) {
        self.inner.lock().unwrap().insert(
            ip,
            CacheEntry {
                hostname,
                resolved_at: Instant::now(),
                in_flight: false,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_once_until_resolved() {
        let cache = DnsCache::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(cache.get_or_claim(ip), (None, true));
        assert_eq!(cache.get_or_claim(ip), (None, false));
        cache.insert(ip, Some("dns.google".into()));
        assert_eq!(cache.get_or_claim(ip), (Some("dns.google".into()), false));
        assert_eq!(cache.cached(ip), Some("dns.google".into()));
    }

    #[test]
    fn skips_local_addresses() {
        let cache = DnsCache::new();
        assert_eq!(
            cache.get_or_claim("127.0.0.1".parse().unwrap()),
            (None, false)
        );
        assert_eq!(
            cache.get_or_claim("0.0.0.0".parse().unwrap()),
            (None, false)
        );
    }
}
