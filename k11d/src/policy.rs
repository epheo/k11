//! Deny rules and the enforcement switch. Sole writer of the probe's CONFIG
//! map and the deny-path maps.

use anyhow::{bail, Context, Result};
use aya::maps::{Array, MapData};
use aya::Ebpf;
use k11_common::{CONFIG_ENFORCE, CONFIG_WATCH_ALL, MAX_DENY_PATHS, POLICY_PATH_LEN};
use tracing::{info, warn};

use k11_proto::PolicySnapshot;

use crate::config::PolicyConfig;

const WATCH_ALL_REFUSAL: &str =
    "deny rules are off in watch-all mode: they would apply to every process on the host";
const NO_LSM: &str = "deny rules need the BPF LSM hook, which this kernel lacks (see k11d --check)";

/// Validate and normalize a deny path for the BPF prefix matcher.
/// Rejects what the matcher would misinterpret: an empty prefix matches
/// every path ("/" normalizes to empty), a relative path never matches
/// bpf_d_path output, and anything longer than the map slot would silently
/// truncate into a broader rule.
fn normalize_deny_path(path: &str) -> Result<String> {
    let p = path.trim().trim_end_matches('/');
    if p.is_empty() {
        bail!("deny path {path:?} would match every file: denying / is not supported");
    }
    if !p.starts_with('/') {
        bail!("deny path {path:?} must be absolute");
    }
    if p.len() >= POLICY_PATH_LEN {
        bail!(
            "deny path {path:?} exceeds {} bytes and would be truncated",
            POLICY_PATH_LEN - 1
        );
    }
    Ok(p.to_string())
}

pub struct PolicyMaps {
    deny_file_paths: Array<MapData, [u8; POLICY_PATH_LEN]>,
    deny_file_count: Array<MapData, u32>,
    config: Array<MapData, u32>,
    // Userspace mirror: source of truth for API reads.
    file_paths: Vec<String>,
    enforce: bool,
    watch_all: bool,
    /// Rules only take effect through the LSM hook.
    lsm_available: bool,
}

impl PolicyMaps {
    /// Take ownership of the policy maps and seed them from config.
    pub fn new(
        ebpf: &mut Ebpf,
        policy: &PolicyConfig,
        watch_all: bool,
        lsm_available: bool,
    ) -> Result<Self> {
        // Refused at startup so the user learns now, not during an incident.
        if watch_all && (policy.enforce || !policy.deny_file_paths.is_empty()) {
            bail!("policy: {WATCH_ALL_REFUSAL}; set watch.binaries");
        }
        if policy.enforce && !lsm_available {
            bail!("policy.enforce: {NO_LSM}");
        }
        if !policy.deny_file_paths.is_empty() && !lsm_available {
            warn!("deny rules configured but the BPF LSM hook is unavailable: rules will not match; see k11d --check");
        }
        let file_paths = policy
            .deny_file_paths
            .iter()
            .map(|p| normalize_deny_path(p))
            .collect::<Result<Vec<_>>>()?;
        if file_paths.len() > MAX_DENY_PATHS as usize {
            bail!("policy.deny_file_paths exceeds the maximum of {MAX_DENY_PATHS} rules");
        }

        let mut pm = Self {
            deny_file_paths: Array::try_from(
                ebpf.take_map("DENY_FILE_PATHS")
                    .context("DENY_FILE_PATHS map not found")?,
            )?,
            deny_file_count: Array::try_from(
                ebpf.take_map("DENY_FILE_COUNT")
                    .context("DENY_FILE_COUNT map not found")?,
            )?,
            config: Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map not found")?)?,
            file_paths,
            enforce: policy.enforce,
            watch_all,
            lsm_available,
        };
        pm.sync_file_paths()?;
        pm.sync_config()?;
        if !pm.file_paths.is_empty() {
            info!(
                file_paths = pm.file_paths.len(),
                enforce = pm.enforce,
                "loaded policy deny rules"
            );
        }
        Ok(pm)
    }

    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            enforce: self.enforce,
            deny_file_paths: self.file_paths.clone(),
            unavailable: self.unavailable().unwrap_or_default().into(),
        }
    }

    /// Why rules cannot be changed, if they cannot.
    fn unavailable(&self) -> Option<&'static str> {
        if self.watch_all {
            Some(WATCH_ALL_REFUSAL)
        } else if !self.lsm_available {
            Some(NO_LSM)
        } else {
            None
        }
    }

    pub fn add_deny_file_path(&mut self, path: &str) -> Result<()> {
        if let Some(reason) = self.unavailable() {
            bail!(reason);
        }
        let path = normalize_deny_path(path)?;
        if self.file_paths.len() >= MAX_DENY_PATHS as usize {
            bail!("maximum {MAX_DENY_PATHS} file deny rules reached");
        }
        if self.file_paths.contains(&path) {
            return Ok(());
        }
        self.file_paths.push(path.clone());
        self.sync_file_paths()?;
        info!(path, "added file deny rule");
        Ok(())
    }

    pub fn remove_deny_file_path(&mut self, path: &str) -> Result<()> {
        let path = path.trim().trim_end_matches('/');
        if let Some(pos) = self.file_paths.iter().position(|p| p == path) {
            self.file_paths.remove(pos);
            self.sync_file_paths()?;
            info!(path, "removed file deny rule");
        }
        Ok(())
    }

    pub fn set_enforce(&mut self, enforce: bool) -> Result<()> {
        if let Some(reason) = self.unavailable().filter(|_| enforce) {
            bail!(reason);
        }
        self.enforce = enforce;
        self.sync_config()?;
        info!(enforce, "enforcement toggled");
        Ok(())
    }

    fn sync_file_paths(&mut self) -> Result<()> {
        for i in 0..MAX_DENY_PATHS as usize {
            let mut slot = [0u8; POLICY_PATH_LEN];
            if let Some(path) = self.file_paths.get(i) {
                slot[..path.len()].copy_from_slice(path.as_bytes());
            }
            self.deny_file_paths.set(i as u32, slot, 0)?;
        }
        self.deny_file_count
            .set(0, self.file_paths.len() as u32, 0)?;
        Ok(())
    }

    fn sync_config(&mut self) -> Result<()> {
        let mut flags = 0;
        if self.watch_all {
            flags |= CONFIG_WATCH_ALL;
        }
        if self.enforce {
            flags |= CONFIG_ENFORCE;
        }
        self.config.set(0, flags, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_path_normalization() {
        assert_eq!(
            normalize_deny_path("/home/u/.ssh/").unwrap(),
            "/home/u/.ssh"
        );
        assert_eq!(
            normalize_deny_path("  /etc/shadow ").unwrap(),
            "/etc/shadow"
        );
    }

    #[test]
    fn deny_path_rejects_match_all() {
        assert!(normalize_deny_path("/").is_err());
        assert!(normalize_deny_path("").is_err());
        assert!(normalize_deny_path("//").is_err());
    }

    #[test]
    fn deny_path_rejects_relative() {
        assert!(normalize_deny_path("home/u/.ssh").is_err());
    }

    #[test]
    fn deny_path_rejects_oversized() {
        let long = format!("/{}", "a".repeat(POLICY_PATH_LEN));
        assert!(normalize_deny_path(&long).is_err());
    }
}
