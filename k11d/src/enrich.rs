//! Enrichment pipeline — reverse DNS, GeoIP country/city, ASN, uid → username.
//!
//! A single `lookup_addr` function drives both the dashboard path
//! (`enrich_connections` over `ConnectionAccess` batches) and the SIEM export
//! path (`enrich_event` over a single `store::Event`). Both consumers share
//! the same `DnsCache`, GeoIP readers, and passwd cache — no duplication.

use std::collections::HashMap;
use std::sync::Arc;

use maxminddb::Reader as GeoIpReader;
use tracing::warn;

use crate::dns_cache::DnsCache;
use crate::store::{self, Event, Payload};

#[derive(serde::Deserialize)]
struct GeoCity {
    country: Option<GeoCityCountry>,
    city: Option<GeoCityNames>,
}

#[derive(serde::Deserialize)]
struct GeoCityCountry {
    iso_code: Option<String>,
}

#[derive(serde::Deserialize)]
struct GeoCityNames {
    names: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct GeoAsn {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

/// Enrichment data for a single remote address.
#[derive(Clone, Default)]
pub struct EnrichedAddr {
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
}

/// Enrichment data for a single event.
///
/// `addr` is populated for events with a remote peer (Connect, Bind);
/// `username` whenever the event's uid resolves via /etc/passwd.
#[derive(Clone, Default)]
pub struct EnrichedEvent {
    pub addr: Option<EnrichedAddr>,
    pub username: Option<String>,
}

/// uid → username cache. Loaded once from /etc/passwd at startup.
/// Missing uids fall through — containers with sparse /etc/passwd stay functional.
pub struct PasswdCache {
    map: HashMap<u32, String>,
}

impl PasswdCache {
    pub fn load() -> Self {
        let map = std::fs::read_to_string("/etc/passwd")
            .map(|contents| parse_passwd(&contents))
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to read /etc/passwd — uid→username resolution disabled");
                HashMap::new()
            });
        Self { map }
    }

    pub fn lookup(&self, uid: u32) -> Option<&str> {
        self.map.get(&uid).map(String::as_str)
    }
}

fn parse_passwd(contents: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let mut parts = line.split(':');
        let name = parts.next();
        let _pw = parts.next();
        let uid = parts.next().and_then(|s| s.parse::<u32>().ok());
        if let (Some(name), Some(uid)) = (name, uid) {
            map.insert(uid, name.to_owned());
        }
    }
    map
}

/// Look up enrichment for a single address. Spawns a background DNS lookup
/// on cache miss and returns whatever is currently known (possibly partial).
pub async fn lookup_addr(
    addr: &str,
    dns_cache: &Arc<DnsCache>,
    geoip: &Option<Arc<GeoIpReader<Vec<u8>>>>,
    geoip_asn: &Option<Arc<GeoIpReader<Vec<u8>>>>,
) -> EnrichedAddr {
    let mut out = EnrichedAddr::default();

    let (hostname, should_spawn) = dns_cache.get_or_spawn(addr);
    out.hostname = hostname;

    if should_spawn {
        let cache = Arc::clone(dns_cache);
        let addr_owned = addr.to_owned();
        tokio::spawn(async move {
            let addr2 = addr_owned.clone();
            let result = tokio::task::spawn_blocking(move || {
                let ip = DnsCache::parse_ip(&addr2)?;
                dns_lookup::lookup_addr(&ip).ok()
            })
            .await;
            // Insert even on failure: a None entry clears in_flight and gets
            // the failure TTL, so the lookup is retried instead of stuck.
            let hostname = result.ok().flatten();
            if let Some(ip) = DnsCache::parse_ip(&addr_owned) {
                cache.insert(ip, hostname);
            }
        });
    }

    if let Some(ip) = DnsCache::parse_ip(addr) {
        if let Some(ref reader) = geoip {
            if let Ok(geo) = reader.lookup::<GeoCity>(ip) {
                out.country = geo.country.and_then(|c| c.iso_code);
                out.city = geo
                    .city
                    .and_then(|c| c.names)
                    .and_then(|mut n| n.remove("en"));
            }
        }
        if let Some(ref reader) = geoip_asn {
            if let Ok(asn) = reader.lookup::<GeoAsn>(ip) {
                let num = asn.autonomous_system_number;
                let org = asn.autonomous_system_organization;
                out.asn = match (num, org) {
                    (Some(n), Some(o)) => Some(format!("AS{n} {o}")),
                    (Some(n), None) => Some(format!("AS{n}")),
                    (None, Some(o)) => Some(o),
                    (None, None) => None,
                };
            }
        }
    }

    out
}

/// Enrich a batch of `ConnectionAccess` records in place — dashboard path.
pub async fn enrich_connections(
    connections: &mut [store::ConnectionAccess],
    dns_cache: &Arc<DnsCache>,
    geoip: &Option<Arc<GeoIpReader<Vec<u8>>>>,
    geoip_asn: &Option<Arc<GeoIpReader<Vec<u8>>>>,
) {
    for conn in connections {
        let enriched = lookup_addr(&conn.addr, dns_cache, geoip, geoip_asn).await;
        conn.hostname = enriched.hostname;
        conn.country = enriched.country;
        conn.city = enriched.city;
        conn.asn = enriched.asn;
    }
}

/// Enrich a single event — SIEM export path. Returns an `EnrichedEvent`
/// with fields populated where applicable for the event's kind.
pub async fn enrich_event(
    event: &Event,
    dns_cache: &Arc<DnsCache>,
    geoip: &Option<Arc<GeoIpReader<Vec<u8>>>>,
    geoip_asn: &Option<Arc<GeoIpReader<Vec<u8>>>>,
    passwd: &Arc<PasswdCache>,
) -> EnrichedEvent {
    let mut out = EnrichedEvent::default();

    match &event.payload {
        Payload::Connect { addr, .. } | Payload::Bind { addr, .. } => {
            out.addr = Some(lookup_addr(addr, dns_cache, geoip, geoip_asn).await);
        }
        _ => {}
    }

    out.username = passwd.lookup(event.meta.uid).map(str::to_owned);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_passwd_basic() {
        let input = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
        let map = parse_passwd(input);
        assert_eq!(map.get(&0).map(String::as_str), Some("root"));
        assert_eq!(map.get(&1).map(String::as_str), Some("daemon"));
    }

    #[test]
    fn parse_passwd_skips_malformed() {
        let input = "broken-line\nroot:x:0:0::/:/bin/sh\n";
        let map = parse_passwd(input);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&0).map(String::as_str), Some("root"));
    }

    #[test]
    fn passwd_cache_missing_uid_returns_none() {
        let cache = PasswdCache { map: HashMap::new() };
        assert!(cache.lookup(1000).is_none());
    }
}
