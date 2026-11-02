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

/// The target every xtask build produces: a static binary runs on any
/// distribution, including a host whose libc differs from the build box
/// (a toolbox or distrobox), and is the release artifact.
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
        Xtask::Build { release } => build(release).map(drop),
        Xtask::Run { release, args } => {
            let bin = build(release)?;
            let args = if args.is_empty() {
                vec!["daemon".into(), "--open".into()]
            } else {
                args
            };
            let mut line = format!("sudo --preserve-env=RUST_LOG,K11_CONFIG {}", quote(&bin));
            for arg in &args {
                line.push(' ');
                line.push_str(&quote(arg));
            }
            on_host(&line, "k11")
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

/// The binary, the unit and (once) a config, then (re)start recording.
fn install() -> Result<()> {
    let bin = build(true)?;
    let root = std::env::current_dir()?;
    let script = format!(
        "set -e
cd {root}
sudo install -Dm755 {bin} /usr/local/bin/k11
sudo install -Dm644 dist/k11.service /etc/systemd/system/k11.service
[ -e /etc/k11/k11.toml ] || sudo install -Dm644 config/k11.toml.example /etc/k11/k11.toml
sudo systemctl daemon-reload
sudo systemctl enable k11
sudo systemctl restart k11",
        root = quote(&root),
        bin = quote(&bin),
    );
    on_host(&script, "install")?;
    println!("k11 is recording. Dashboard: http://127.0.0.1:1100");
    println!("Record an agent: k11 run -- <command>");
    Ok(())
}

/// Run a shell script where systemd and the kernel's BPF live. Inside a
/// toolbox or distrobox that is the host: root in the container can load no
/// probe and has no systemd. The checkout must be visible there, which a
/// home directory is.
fn on_host(script: &str, what: &str) -> Result<()> {
    let in_container =
        Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists();
    let mut cmd = if in_container {
        let root = std::env::current_dir()?;
        if !Path::new("/run/host")
            .join(root.strip_prefix("/")?)
            .exists()
        {
            bail!(
                "{} is not visible on the host: run this from a shared directory, or on the host",
                root.display()
            );
        }
        let (tool, prefix): (&str, &[&str]) = [
            ("distrobox-host-exec", &[][..]),
            ("host-spawn", &[][..]),
            ("flatpak-spawn", &["--host"][..]),
        ]
        .into_iter()
        .find(|(tool, _)| on_path(tool))
        .context("in a container with no way to reach the host (distrobox-host-exec, host-spawn): run this on the host")?;
        let mut cmd = Command::new(tool);
        cmd.args(prefix).arg("sh");
        cmd
    } else {
        Command::new("sh")
    };
    cmd.args(["-c", script]);
    run(cmd, what)
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
}

/// Single-quoted for sh.
fn quote(s: impl AsRef<std::ffi::OsStr>) -> String {
    format!("'{}'", s.as_ref().to_string_lossy().replace('\'', "'\\''"))
}
