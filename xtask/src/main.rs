use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Xtask {
    /// Build the BPF probe and daemon
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build and run the daemon
    Run {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
}

/// Build the BPF probe (requires nightly + bpfel target).
fn build_probe() -> Result<()> {
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .current_dir("k11-probe")
        .status()
        .context("failed to run cargo build for BPF probe")?;
    if !status.success() {
        bail!("BPF probe build failed");
    }
    Ok(())
}

/// Build the Svelte frontend. Installs npm deps on first run; `npm run build`
/// triggers the `prebuild` hook which regenerates the proto TS client.
fn build_web() -> Result<()> {
    if !std::path::Path::new("k11-web/node_modules").exists() {
        let status = Command::new("npm")
            .arg("install")
            .current_dir("k11-web")
            .status()
            .context("failed to run npm install for k11-web")?;
        if !status.success() {
            bail!("npm install failed");
        }
    }

    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir("k11-web")
        .status()
        .context("failed to run npm build for k11-web")?;
    if !status.success() {
        bail!("k11-web build failed");
    }
    Ok(())
}

fn build(release: bool) -> Result<()> {
    build_probe()?;
    build_web()?;

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "k11d"]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to run cargo build")?;
    if !status.success() {
        bail!("build failed");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Xtask::parse();

    match args {
        Xtask::Build { release } => {
            build(release)?;
        }
        Xtask::Run { release } => {
            build(release)?;

            let bin = if release {
                "target/release/k11d"
            } else {
                "target/debug/k11d"
            };
            let status = Command::new(bin)
                .status()
                .with_context(|| format!("failed to run {bin}"))?;
            if !status.success() {
                bail!("k11d exited with error");
            }
        }
    }

    Ok(())
}
