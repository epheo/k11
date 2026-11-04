//! What the dashboard changed, kept across restarts.
//!
//! Each section the dashboard touched replaces the matching part of
//! k11.toml at the next start; deleting the file starts from k11.toml
//! again. Only touched sections are written, so a config edit to the other
//! one still takes effect.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::Config;

pub const PATH: &str = "/var/lib/k11/state.toml";

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct State {
    #[serde(skip_serializing_if = "Option::is_none")]
    watch: Option<Watch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<Policy>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Watch {
    binaries: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Policy {
    enforce: bool,
    deny_file_paths: Vec<String>,
}

pub struct Kept {
    path: PathBuf,
    state: State,
}

impl Kept {
    /// No file is no change.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).with_context(|| {
                format!(
                    "invalid {}: fix it, or delete it to start from k11.toml",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, state })
    }

    pub fn apply(&self, config: &mut Config) {
        if let Some(watch) = &self.state.watch {
            config.watch.binaries = watch.binaries.clone();
        }
        if let Some(policy) = &self.state.policy {
            config.policy.enforce = policy.enforce;
            config.policy.deny_file_paths = policy.deny_file_paths.clone();
        }
        if self.state != State::default() {
            info!(path = %self.path.display(), "dashboard changes replace the config's");
        }
    }

    pub fn set_watch(&mut self, binaries: &[String]) {
        self.state.watch = Some(Watch {
            binaries: binaries.to_vec(),
        });
        self.save();
    }

    pub fn set_policy(&mut self, enforce: bool, deny_file_paths: &[String]) {
        self.state.policy = Some(Policy {
            enforce,
            deny_file_paths: deny_file_paths.to_vec(),
        });
        self.save();
    }

    /// A failed write loses the change at the next start, not now.
    fn save(&self) {
        if let Err(e) = write(&self.path, &self.state) {
            warn!(path = %self.path.display(), error = %format!("{e:#}"), "dashboard change not kept");
        }
    }
}

fn write(path: &Path, state: &State) -> Result<()> {
    let text = format!(
        "# Written by k11 when the dashboard changes the watch list or the deny rules.\n\
         # Each section replaces k11.toml's; delete this file to start from k11.toml.\n\n{}",
        toml::to_string(state)?
    );
    write_private(path, &text)
}

/// Root-only, and replaced whole: a crash mid-write leaves the old file.
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?
        .write_all(text.as_bytes())?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("k11-state-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("k11").join("state.toml")
    }

    #[test]
    fn no_file_changes_nothing() {
        let kept = Kept::load(temp_path("none")).unwrap();
        let mut config = Config::default();
        config.watch.binaries = vec!["codex".into()];
        kept.apply(&mut config);
        assert_eq!(config.watch.binaries, ["codex"]);
    }

    #[test]
    fn kept_sections_replace_the_config_after_a_restart() {
        let path = temp_path("kept");
        let mut kept = Kept::load(&path).unwrap();
        kept.set_watch(&["claude".into()]);
        let restarted = Kept::load(&path).unwrap();
        let mut config = Config::default();
        config.watch.binaries = vec!["codex".into()];
        config.policy.deny_file_paths = vec!["/home/u/.ssh".into()];
        restarted.apply(&mut config);
        assert_eq!(config.watch.binaries, ["claude"]);
        // Untouched by the dashboard: still the config's.
        assert_eq!(config.policy.deny_file_paths, ["/home/u/.ssh"]);

        let mut kept = restarted;
        kept.set_policy(true, &[]);
        let mut config = Config::default();
        config.policy.deny_file_paths = vec!["/home/u/.ssh".into()];
        Kept::load(&path).unwrap().apply(&mut config);
        assert!(config.policy.enforce && config.policy.deny_file_paths.is_empty());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn a_broken_file_names_itself() {
        let path = temp_path("broken");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "[watch\n").unwrap();
        let err = format!("{:#}", Kept::load(&path).err().unwrap());
        assert!(
            err.contains("state.toml") && err.contains("delete it"),
            "{err}"
        );
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}
