mod vm;

use std::path::{Path, PathBuf};
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
    /// Boot a kernel in qemu with k11 and the integration test as /init
    Vm {
        /// Kernel image (default: the running kernel's)
        #[arg(long)]
        kernel: Option<PathBuf>,
        /// Extra kernel arguments, e.g. `lsm=landlock,lockdown,yama,apparmor,bpf`
        #[arg(long)]
        append: Option<String>,
        /// Also run the dashboard smoke test (puts node in the VM)
        #[arg(long)]
        smoke: bool,
        /// Only print what the kernel supports
        #[arg(long)]
        check: bool,
    },
    /// Build everything, then run it with sudo (the daemon loads eBPF)
    Run {
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Arguments passed to k11, e.g. `-- check` (default: `daemon --open`)
        #[arg(last = true)]
        args: Vec<String>,
    },
}

pub(crate) fn run(mut cmd: Command, what: &str) -> Result<()> {
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
    .current_dir("k11-probe")
    // `cargo xtask` runs under the workspace toolchain and rustup passes it
    // down, which would override k11-probe/rust-toolchain.toml.
    .env_remove("RUSTUP_TOOLCHAIN");
    run(cmd, "BPF probe build")
}

/// Installs npm deps on first run; `npm run build` regenerates the proto
/// client and type-checks before bundling.
fn build_web() -> Result<()> {
    if !Path::new("k11-web/node_modules").exists() {
        let mut cmd = Command::new("npm");
        cmd.arg("install").current_dir("k11-web");
        run(cmd, "npm install")?;
    }
    let mut cmd = Command::new("npm");
    cmd.args(["run", "build"]).current_dir("k11-web");
    run(cmd, "dashboard build")
}

/// The target every xtask build produces: a static binary runs on any
/// distribution, including one whose libc differs from where it was built,
/// and is the release artifact.
fn static_target() -> String {
    format!("{}-unknown-linux-musl", std::env::consts::ARCH)
}

/// Probe, dashboard, then the static `k11`; returns its path.
fn build(release: bool) -> Result<PathBuf> {
    build_probe()?;
    build_web()?;
    let target = static_target();
    let mut add = Command::new("rustup");
    add.args(["target", "add", &target]);
    run(add, &format!("rustup target add {target}"))?;
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "k11d", "--target", &target]);
    if release {
        cmd.arg("--release");
    }
    run(cmd, "k11 build")?;
    let profile = if release { "release" } else { "debug" };
    Ok(std::env::current_dir()?.join(format!("target/{target}/{profile}/k11")))
}

fn main() -> Result<()> {
    match Xtask::parse() {
        Xtask::Build { release } => {
            let bin = build(release)?;
            println!(
                "built {}: run it as root, e.g. sudo {} daemon",
                bin.display(),
                bin.display()
            );
            Ok(())
        }
        Xtask::Run { release, args } => {
            let bin = build(release)?;
            let args = if args.is_empty() {
                vec!["daemon".into(), "--open".into()]
            } else {
                args
            };
            let mut cmd = Command::new("sudo");
            cmd.arg("--preserve-env=RUST_LOG,K11_CONFIG")
                .arg(&bin)
                .args(args);
            run(cmd, "k11")
        }
        Xtask::Vm {
            kernel,
            append,
            smoke,
            check,
        } => vm::run(kernel, append, smoke, check, || build(false)),
    }
}
