use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Deserialize;
use tracing::info;

const DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/k11/k11.toml", "config/k11.toml"];

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub grpc: GrpcConfig,
    #[serde(default)]
    pub watch: WatchConfig,
    #[serde(default)]
    pub geoip: GeoipConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub store: StoreConfig,
}

// Localhost by default: the API is unauthenticated and can toggle enforcement.
fn default_grpc_listen() -> String {
    "127.0.0.1:1100".into()
}

#[derive(Debug, Deserialize)]
pub struct GrpcConfig {
    #[serde(default = "default_grpc_listen")]
    pub listen: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen: default_grpc_listen(),
        }
    }
}

fn default_output() -> String {
    "-".into()
}

#[derive(Debug, Deserialize)]
pub struct ExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_output")]
    pub output: String,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output: default_output(),
        }
    }
}

fn default_max_events_per_agent() -> usize {
    crate::store::DEFAULT_MAX_EVENTS_PER_AGENT
}

fn default_evict_exited_after_secs() -> u64 {
    900
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    /// Raw events kept per agent for the raw log; aggregates are unaffected.
    #[serde(default = "default_max_events_per_agent")]
    pub max_events_per_agent: usize,
    /// Drop an agent tree this long after its last event once all processes exited.
    #[serde(default = "default_evict_exited_after_secs")]
    pub evict_exited_after_secs: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            max_events_per_agent: default_max_events_per_agent(),
            evict_exited_after_secs: default_evict_exited_after_secs(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct PolicyConfig {
    /// If true, file-path deny rules return EPERM. If false, audit-only (log but allow).
    #[serde(default)]
    pub enforce: bool,
    /// Path prefixes to block for file access (e.g. "/home/user/.ssh/").
    #[serde(default)]
    pub deny_file_paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct WatchConfig {
    #[serde(default)]
    pub binaries: Vec<String>,
}

fn default_geoip_path() -> String {
    "/usr/share/GeoIP/GeoLite2-City.mmdb".to_string()
}

fn default_asn_path() -> String {
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb".to_string()
}

#[derive(Debug, Deserialize)]
pub struct GeoipConfig {
    #[serde(default = "default_geoip_path")]
    pub database: String,
    #[serde(default = "default_asn_path")]
    pub asn_database: String,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        Self {
            database: default_geoip_path(),
            asn_database: default_asn_path(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::env::var("K11_CONFIG")
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                DEFAULT_CONFIG_PATHS
                    .iter()
                    .map(Path::new)
                    .find(|p| p.exists())
                    .map(PathBuf::from)
            });

        match path {
            Some(p) => {
                info!(path = %p.display(), "loading config");
                let contents = std::fs::read_to_string(&p)?;
                let config: Config = toml::from_str(&contents)?;
                Ok(config)
            }
            None => {
                info!("no config file found, using defaults");
                Ok(Config {
                    grpc: GrpcConfig::default(),
                    watch: WatchConfig::default(),
                    geoip: GeoipConfig::default(),
                    policy: PolicyConfig::default(),
                    export: ExportConfig::default(),
                    store: StoreConfig::default(),
                })
            }
        }
    }
}
