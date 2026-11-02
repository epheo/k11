use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tracing::info;

const DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/k11/k11.toml", "config/k11.toml"];

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub grpc: GrpcConfig,
    pub watch: WatchConfig,
    pub geoip: GeoipConfig,
    pub policy: PolicyConfig,
    pub export: ExportConfig,
    pub store: StoreConfig,
    pub probe: ProbeConfig,
    pub session: SessionConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Where `k11 run` registers itself.
    pub socket: PathBuf,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_SOCKET),
        }
    }
}

pub const DEFAULT_SOCKET: &str = "/run/k11/k11.sock";

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GrpcConfig {
    pub listen: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        // Localhost: the API is unauthenticated and can toggle enforcement.
        Self {
            listen: "127.0.0.1:1100".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ExportConfig {
    pub enabled: bool,
    /// "-" for stdout, or a file path.
    pub output: String,
    /// A file past this size moves to `<output>.1`, replacing the previous
    /// one, so the record takes at most twice this on disk. 0: never.
    pub max_mb: u64,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output: "-".into(),
            max_mb: 256,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct StoreConfig {
    /// Raw events kept per agent for the raw log; aggregates are unaffected.
    pub max_events_per_agent: usize,
    /// Raw events kept across all agents; the largest tree gives way first.
    pub max_total_events: usize,
    /// Drop an agent tree this long after its last event once all processes exited.
    pub evict_exited_after_secs: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_events_per_agent: 10_000,
            max_total_events: 200_000,
            evict_exited_after_secs: 900,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    /// Kernel ring buffer between probe and daemon. Power of two, at least 4.
    pub ring_buffer_kb: u32,
    /// Lineage-map capacity in watch-all mode: it must hold every live task,
    /// so size it above the host's peak task count. Only used with
    /// `watch.all`; sessions and binaries need far fewer.
    pub max_tracked_pids: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            ring_buffer_kb: 1024,
            max_tracked_pids: 131072,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// If true, file-path deny rules return EPERM. If false, audit-only.
    pub enforce: bool,
    /// Path prefixes to block for file access (e.g. "/home/user/.ssh/").
    pub deny_file_paths: Vec<String>,
}

/// What is recorded: `k11 run` sessions always, trees started by these
/// binaries, or every process on the host.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    /// Every process: heavy, and deny rules are refused.
    pub all: bool,
    /// Comm names (15 chars) that start a tree when exec'd.
    pub binaries: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeoipConfig {
    pub database: String,
    pub asn_database: String,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        Self {
            database: "/usr/share/GeoIP/GeoLite2-City.mmdb".into(),
            asn_database: "/usr/share/GeoIP/GeoLite2-ASN.mmdb".into(),
        }
    }
}

impl Config {
    /// `explicit` (from the command line) wins over $K11_CONFIG, which wins
    /// over the default search path. No file at all means defaults.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = explicit
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("K11_CONFIG").map(PathBuf::from))
            .or_else(|| {
                DEFAULT_CONFIG_PATHS
                    .iter()
                    .map(PathBuf::from)
                    .find(|p| p.exists())
            });

        let config = match path {
            Some(p) => {
                info!(path = %p.display(), "loading config");
                let contents = std::fs::read_to_string(&p)
                    .with_context(|| format!("failed to read {}", p.display()))?;
                toml::from_str(&contents)
                    .with_context(|| format!("invalid config {}", p.display()))?
            }
            None => {
                info!("no config file found, using defaults");
                Config::default()
            }
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let kb = self.probe.ring_buffer_kb;
        if kb < 4 || !kb.is_power_of_two() {
            bail!("probe.ring_buffer_kb must be a power of two of at least 4, got {kb}");
        }
        if self.store.max_events_per_agent == 0 || self.store.max_total_events == 0 {
            bail!("store.max_events_per_agent and store.max_total_events must be positive");
        }
        if self.probe.max_tracked_pids < 1024 {
            bail!(
                "probe.max_tracked_pids must be at least 1024, got {}",
                self.probe.max_tracked_pids
            );
        }
        Ok(())
    }

    pub fn ring_buffer_bytes(&self) -> u32 {
        self.probe.ring_buffer_kb * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn rejects_bad_ring_size() {
        let mut c = Config::default();
        c.probe.ring_buffer_kb = 100;
        assert!(c.validate().is_err());
        c.probe.ring_buffer_kb = 2;
        assert!(c.validate().is_err());
        c.probe.ring_buffer_kb = 4096;
        c.validate().unwrap();
    }

    #[test]
    fn rejects_tiny_tracked_pids() {
        let mut c = Config::default();
        c.probe.max_tracked_pids = 512;
        assert!(c.validate().is_err());
        c.probe.max_tracked_pids = 1024;
        c.validate().unwrap();
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let c: Config = toml::from_str("[probe]\nring_buffer_kb = 512\n").unwrap();
        assert_eq!(c.probe.ring_buffer_kb, 512);
        assert_eq!(c.probe.max_tracked_pids, 131072);
        assert_eq!(c.grpc.listen, "127.0.0.1:1100");
        assert_eq!(c.store.max_events_per_agent, 10_000);
    }
}
