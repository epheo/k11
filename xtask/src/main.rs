use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Build the BPF probe and daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the BPF probe and daemon
    Build {
        #[arg(long)]
        release: bool,
        /// Skip building the Svelte web dashboard
        #[arg(long)]
        no_web: bool,
    },
    /// Build and run the daemon
    Run {
        #[arg(long)]
        release: bool,
        /// Arguments passed through to k11d
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build { release, no_web } => build(release, no_web),
        Cmd::Run { release, args } => run(release, args),
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(PathBuf::from)
        .context("xtask has no parent directory")
}

fn build(release: bool, no_web: bool) -> Result<()> {
    let root = workspace_root()?;

    // Build the web assets first so the daemon's build.rs picks them up if needed.
    if !no_web {
        let web_dir = root.join("k11-web");
        if web_dir.join("package.json").exists() {
            run_cmd(Command::new("npm").args(["run", "build"]).current_dir(&web_dir))?;
        }
    }

    // Build the workspace (which invokes aya-build to compile the BPF probe via build.rs).
    let mut cargo = Command::new("cargo");
    cargo.current_dir(&root).args(["build", "--workspace"]);
    if release {
        cargo.arg("--release");
    }
    run_cmd(&mut cargo)
}

fn run(release: bool, args: Vec<String>) -> Result<()> {
    build(release, false)?;
    let root = workspace_root()?;
    let profile = if release { "release" } else { "debug" };
    let bin = root.join("target").join(profile).join("k11d");
    let mut cmd = Command::new(&bin);
    cmd.args(&args);
    run_cmd(&mut cmd)
}

fn run_cmd(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("failed to spawn {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} exited with {status}");
    }
    Ok(())
}
