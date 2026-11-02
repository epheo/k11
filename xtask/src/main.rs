mod vm;

use std::path::PathBuf;
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
    /// Build a release, install it with its systemd unit, and start it
    Install,
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
    /// Build everything and run the daemon as root (it loads eBPF)
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
    run(cmd, "k11 build")
}

fn main() -> Result<()> {
    match Xtask::parse() {
        Xtask::Build { release } => build(release),
        Xtask::Run { release, args } => {
            build(release)?;
            let bin = if release {
                "target/release/k11"
            } else {
                "target/debug/k11"
            };
            let args = if args.is_empty() {
                vec!["daemon".into(), "--open".into()]
            } else {
                args
            };
            let mut cmd = Command::new("sudo");
            cmd.args(["--preserve-env=RUST_LOG,K11_CONFIG", bin])
                .args(args);
            run(cmd, bin)
        }
        Xtask::Install => install(),
        Xtask::Vm {
            kernel,
            append,
            smoke,
            check,
        } => vm::run(kernel, append, smoke, check, || build(false)),
    }
}

/// The binary, the unit and (once) a config, then start recording.
fn install() -> Result<()> {
    build(true)?;
    let sudo = |args: &[&str]| {
        let mut cmd = Command::new("sudo");
        cmd.args(args);
        run(cmd, &args.join(" "))
    };
    sudo(&[
        "install",
        "-Dm755",
        "target/release/k11",
        "/usr/local/bin/k11",
    ])?;
    sudo(&[
        "install",
        "-Dm644",
        "dist/k11.service",
        "/etc/systemd/system/k11.service",
    ])?;
    if !std::path::Path::new("/etc/k11/k11.toml").exists() {
        sudo(&[
            "install",
            "-Dm644",
            "config/k11.toml.example",
            "/etc/k11/k11.toml",
        ])?;
    }
    sudo(&["systemctl", "daemon-reload"])?;
    sudo(&["systemctl", "enable", "--now", "k11"])?;
    println!("k11 is recording. Dashboard: http://127.0.0.1:1100");
    println!("Record an agent: k11 run -- <command>");
    Ok(())
}
