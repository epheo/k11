use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SUCCESS_TTL: Duration = Duration::from_secs(300);
const FAILURE_TTL: Duration = Duration::from_secs(120);
/// Addresses remembered at once. A full table sweeps expired entries, at
/// most once per `SWEEP_EVERY` so a crawler cannot turn every miss into a
/// full scan; past that, new addresses go unresolved.
const MAX_ENTRIES: usize = 4096;
const SWEEP_EVERY: Duration = Duration::from_secs(30);

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

struct Table {
    entries: HashMap<IpAddr, CacheEntry>,
    swept_at: Instant,
}

pub struct DnsCache {
    inner: Mutex<Table>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Table {
                entries: HashMap::new(),
                swept_at: Instant::now(),
            }),
        }
    }

    /// The cached hostname, if any, without starting a lookup.
    pub fn cached(&self, ip: IpAddr) -> Option<String> {
        let table = self.inner.lock().unwrap();
        table.entries.get(&ip).and_then(|e| e.hostname.clone())
    }

    /// `(cached_hostname, caller_should_resolve)`. Marks the entry in flight
    /// atomically so one address gets one lookup at a time.
    pub fn get_or_claim(&self, ip: IpAddr) -> (Option<String>, bool) {
        if ip.is_loopback() || ip.is_unspecified() {
            return (None, false);
        }
        let mut table = self.inner.lock().unwrap();
        if let Some(entry) = table.entries.get_mut(&ip) {
            let claim = entry.expired() && !entry.in_flight;
            entry.in_flight |= claim;
            return (entry.hostname.clone(), claim);
        }
        if table.entries.len() >= MAX_ENTRIES {
            if table.swept_at.elapsed() < SWEEP_EVERY {
                return (None, false);
            }
            table.entries.retain(|_, e| e.in_flight || !e.expired());
            table.swept_at = Instant::now();
            if table.entries.len() >= MAX_ENTRIES {
                return (None, false);
            }
        }
        table.entries.insert(
            ip,
            CacheEntry {
                hostname: None,
                resolved_at: Instant::now(),
                in_flight: true,
            },
        );
        (None, true)
    }

    /// Record a lookup result. A failed refresh keeps the name already known.
    pub fn insert(&self, ip: IpAddr, hostname: Option<String>) {
        let mut table = self.inner.lock().unwrap();
        let entry = table.entries.entry(ip).or_insert(CacheEntry {
            hostname: None,
            resolved_at: Instant::now(),
            in_flight: false,
        });
        if hostname.is_some() {
            entry.hostname = hostname;
        }
        entry.resolved_at = Instant::now();
        entry.in_flight = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn claims_once_until_resolved() {
        let cache = DnsCache::new();
        assert_eq!(cache.get_or_claim(ip("8.8.8.8")), (None, true));
        assert_eq!(cache.get_or_claim(ip("8.8.8.8")), (None, false));
        cache.insert(ip("8.8.8.8"), Some("dns.google".into()));
        assert_eq!(
            cache.get_or_claim(ip("8.8.8.8")),
            (Some("dns.google".into()), false)
        );
        assert_eq!(cache.cached(ip("8.8.8.8")), Some("dns.google".into()));
    }

    #[test]
    fn failed_refresh_keeps_known_name() {
        let cache = DnsCache::new();
        cache.insert(ip("8.8.8.8"), Some("dns.google".into()));
        cache.insert(ip("8.8.8.8"), None);
        assert_eq!(cache.cached(ip("8.8.8.8")), Some("dns.google".into()));
    }

    #[test]
    fn skips_local_addresses() {
        let cache = DnsCache::new();
        assert_eq!(cache.get_or_claim(ip("127.0.0.1")), (None, false));
        assert_eq!(cache.get_or_claim(ip("0.0.0.0")), (None, false));
    }

    #[test]
    fn full_table_stops_claiming() {
        let cache = DnsCache::new();
        for i in 0..MAX_ENTRIES as u32 {
            assert!(
                cache
                    .get_or_claim(IpAddr::from((i + (1 << 24)).to_be_bytes()))
                    .1
            );
        }
        assert_eq!(cache.get_or_claim(ip("9.9.9.9")), (None, false));
    }
}
