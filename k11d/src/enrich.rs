//! Enrichment: reverse DNS, GeoIP country/city, ASN, uid to username.
//!
//! One `Enricher` serves the dashboard (connection views) and the OCSF
//! export (single events). Every source degrades to "unknown" when
//! unavailable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::{Mmap, Reader};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::GeoipConfig;
use crate::dns_cache::DnsCache;
use crate::store::{Event, Payload};

/// Reverse lookups in flight at once. Beyond this, addresses stay unresolved
/// until they are looked at again, so a crawler cannot pile up threads.
const DNS_CONCURRENCY: usize = 8;

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

/// Enrichment data for a single event: `addr` for a connect's peer,
/// `username` whenever the uid resolves.
#[derive(Clone, Default)]
pub struct EnrichedEvent {
    pub addr: Option<EnrichedAddr>,
    pub username: Option<String>,
}

pub struct Enricher {
    dns: DnsCache,
    dns_permits: Arc<Semaphore>,
    geoip: Option<Reader<Mmap>>,
    asn: Option<Reader<Mmap>>,
    passwd: HashMap<u32, String>,
}

impl Enricher {
    pub fn load(config: &GeoipConfig) -> Arc<Self> {
        let open = |path: &str, what: &str| match Reader::open_mmap(path) {
            Ok(reader) => {
                info!(path, "loaded {what} database");
                Some(reader)
            }
            Err(e) => {
                warn!(path, error = %e, "{what} database not available, lookups disabled");
                None
            }
        };
        let passwd = std::fs::read_to_string("/etc/passwd")
            .map(|contents| parse_passwd(&contents))
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to read /etc/passwd, uid to username resolution disabled");
                HashMap::new()
            });
        Arc::new(Self {
            dns: DnsCache::new(),
            dns_permits: Arc::new(Semaphore::new(DNS_CONCURRENCY)),
            geoip: open(&config.database, "GeoIP city"),
            asn: open(&config.asn_database, "GeoIP ASN"),
            passwd,
        })
    }

    /// What is known about `ip` right now. A DNS miss starts a lookup in the
    /// background (needs a Tokio runtime); the answer shows up next time.
    pub fn addr(self: &Arc<Self>, ip: IpAddr) -> EnrichedAddr {
        let ip = ip.to_canonical();
        let mut out = EnrichedAddr {
            hostname: self.hostname(ip),
            ..EnrichedAddr::default()
        };

        if let Some(reader) = &self.geoip {
            if let Ok(geo) = reader.lookup::<GeoCity>(ip) {
                out.country = geo.country.and_then(|c| c.iso_code);
                out.city = geo
                    .city
                    .and_then(|c| c.names)
                    .and_then(|mut n| n.remove("en"));
            }
        }
        if let Some(reader) = &self.asn {
            if let Ok(asn) = reader.lookup::<GeoAsn>(ip) {
                out.asn = match (
                    asn.autonomous_system_number,
                    asn.autonomous_system_organization,
                ) {
                    (Some(n), Some(o)) => Some(format!("AS{n} {o}")),
                    (Some(n), None) => Some(format!("AS{n}")),
                    (None, Some(o)) => Some(o),
                    (None, None) => None,
                };
            }
        }
        out
    }

    fn hostname(self: &Arc<Self>, ip: IpAddr) -> Option<String> {
        let Ok(permit) = Arc::clone(&self.dns_permits).try_acquire_owned() else {
            return self.dns.cached(ip);
        };
        let (hostname, claimed) = self.dns.get_or_claim(ip);
        if claimed {
            let this = Arc::clone(self);
            tokio::task::spawn_blocking(move || {
                // Insert even on failure: that clears in-flight and sets the
                // failure TTL, so the lookup is retried later.
                this.dns.insert(ip, dns_lookup::lookup_addr(&ip).ok());
                drop(permit);
            });
        }
        hostname
    }

    pub fn event(self: &Arc<Self>, event: &Event) -> EnrichedEvent {
        EnrichedEvent {
            addr: match event.payload {
                Payload::Connect { addr } => Some(self.addr(addr.ip())),
                _ => None,
            },
            username: self.passwd.get(&event.meta.uid).cloned(),
        }
    }
}

fn parse_passwd(contents: &str) -> HashMap<u32, String> {
    passwd_entries(contents)
        .map(|(uid, name, _)| (uid, name.to_owned()))
        .collect()
}

/// (uid, name, home) per well-formed /etc/passwd line.
pub fn passwd_entries(contents: &str) -> impl Iterator<Item = (u32, &str, &str)> {
    contents.lines().filter_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _password = parts.next()?;
        let uid = parts.next()?.parse().ok()?;
        let home = parts.nth(2).unwrap_or("");
        Some((uid, name, home))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_passwd_basic() {
        let map = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        );
        assert_eq!(map.get(&0).map(String::as_str), Some("root"));
        assert_eq!(map.get(&1).map(String::as_str), Some("daemon"));
    }

    #[test]
    fn parse_passwd_skips_malformed() {
        let map = parse_passwd("broken-line\nroot:x:0:0::/:/bin/sh\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&0).map(String::as_str), Some("root"));
    }
}
