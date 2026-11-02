use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Xtask {
    /// Build the BPF probe, the dashboard, and the daemon
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything and run the daemon as root (it loads eBPF)
    Run {
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Arguments passed to k11d, e.g. `-- --check`
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn run(mut cmd: Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {what}"))?;
    if !status.success() {
        bail!("{what} failed");
    }
    Ok(())
}

/// The probe needs nightly and build-std; k11-probe/rust-toolchain.toml
/// selects them, so the host workspace stays on stable.
fn build_probe() -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "--release",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ])
    .current_dir("k11-probe");
    run(cmd, "BPF probe build")
}

/// Installs npm deps on first run; `npm run build` regenerates the proto
/// client and type-checks before bundling.
fn build_web() -> Result<()> {
    if !std::path::Path::new("k11-web/node_modules").exists() {
        let mut cmd = Command::new("npm");
        cmd.arg("install").current_dir("k11-web");
        run(cmd, "npm install")?;
    }
    let mut cmd = Command::new("npm");
    cmd.args(["run", "build"]).current_dir("k11-web");
    run(cmd, "dashboard build")
}

fn build(release: bool) -> Result<()> {
    build_probe()?;
    build_web()?;
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "k11d"]);
    if release {
        cmd.arg("--release");
    }
    run(cmd, "k11d build")
}

fn main() -> Result<()> {
    match Xtask::parse() {
        Xtask::Build { release } => build(release),
        Xtask::Run { release, args } => {
            build(release)?;
            let bin = if release {
                "target/release/k11d"
            } else {
                "target/debug/k11d"
            };
            let mut cmd = Command::new("sudo");
            cmd.args(["--preserve-env=RUST_LOG,K11_CONFIG", bin])
                .args(args);
            run(cmd, bin)
        }
    }
}
