use anyhow::{bail, Context, Result};
use aya::maps::{Array, MapData};
use aya::Ebpf;
use k11_common::{CONFIG_ENFORCE, CONFIG_WATCH_ALL, MAX_DENY_PATHS, POLICY_PATH_LEN};
use serde::Serialize;
use tracing::info;

use crate::config::PolicyConfig;

/// Runtime policy state — owns BPF map handles for live updates from the API.
pub struct PolicyMaps {
    deny_file_paths: Array<MapData, [u8; POLICY_PATH_LEN]>,
    deny_file_count: Array<MapData, u32>,
    config: Array<MapData, u32>,
    // Userspace mirror — source of truth for API reads.
    file_paths: Vec<String>,
    enforce: bool,
    watch_all: bool,
}

#[derive(Clone, Serialize)]
pub struct PolicySnapshot {
    pub enforce: bool,
    pub deny_file_paths: Vec<String>,
}

impl PolicyMaps {
    /// Take ownership of policy BPF maps from the Ebpf object, seed from config.
    /// Must be called AFTER lineage::set_watch_all (which also uses CONFIG map via borrow).
    pub fn new(ebpf: &mut Ebpf, policy: &PolicyConfig, watch_all: bool) -> Result<Self> {
        let deny_file_paths = Array::try_from(
            ebpf.take_map("DENY_FILE_PATHS").context("DENY_FILE_PATHS map not found")?,
        )?;
        let deny_file_count = Array::try_from(
            ebpf.take_map("DENY_FILE_COUNT").context("DENY_FILE_COUNT map not found")?,
        )?;
        let config = Array::try_from(
            ebpf.take_map("CONFIG").context("CONFIG map not found")?,
        )?;

        let mut pm = Self {
            deny_file_paths,
            deny_file_count,
            config,
            file_paths: policy.deny_file_paths.clone(),
            enforce: policy.enforce,
            watch_all,
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
        }
    }

    pub fn add_deny_file_path(&mut self, path: &str) -> Result<()> {
        let path = path.trim_end_matches('/');
        if self.file_paths.len() >= MAX_DENY_PATHS as usize {
            bail!("maximum {} file deny rules reached", MAX_DENY_PATHS);
        }
        if self.file_paths.iter().any(|p| p == path) {
            return Ok(());
        }
        self.file_paths.push(path.to_string());
        self.sync_file_paths()?;
        info!(path, "added file deny rule");
        Ok(())
    }

    pub fn remove_deny_file_path(&mut self, path: &str) -> Result<()> {
        let path = path.trim_end_matches('/');
        if let Some(pos) = self.file_paths.iter().position(|p| p == path) {
            self.file_paths.remove(pos);
            self.sync_file_paths()?;
            info!(path, "removed file deny rule");
        }
        Ok(())
    }

    pub fn set_enforce(&mut self, enforce: bool) -> Result<()> {
        self.enforce = enforce;
        self.sync_config()?;
        info!(enforce, "enforcement toggled");
        Ok(())
    }

    fn sync_file_paths(&mut self) -> Result<()> {
        for (i, path) in self.file_paths.iter().enumerate() {
            let mut key = [0u8; POLICY_PATH_LEN];
            let bytes = path.as_bytes();
            let len = bytes.len().min(POLICY_PATH_LEN);
            key[..len].copy_from_slice(&bytes[..len]);
            self.deny_file_paths.set(i as u32, key, 0)?;
        }
        // Zero out slots beyond current count (handles removals)
        for i in self.file_paths.len()..MAX_DENY_PATHS as usize {
            self.deny_file_paths.set(i as u32, [0u8; POLICY_PATH_LEN], 0)?;
        }
        self.deny_file_count.set(0, self.file_paths.len() as u32, 0)?;
        Ok(())
    }

    fn sync_config(&mut self) -> Result<()> {
        let mut flags: u32 = 0;
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
