mod btf_offsets;
mod classify;
mod cmdline;
mod config;
mod container;
mod control;
mod cpu_cover;
mod daemon;
mod decode;
mod dns_cache;
mod enrich;
mod export;
mod grpc;
mod lineage;
mod notices;
mod ocsf;
mod policy;
mod probe;
mod report;
mod run;
mod session;
mod state;
mod store;
mod tracefs;
mod web;

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::probe::Probe;

/// Black-box recorder for AI coding agents.
///
/// With no command: record, and open the dashboard to choose what to watch.
#[derive(Parser)]
#[command(name = "k11", version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    #[command(flatten)]
    daemon: daemon::Args,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record: load the probe and serve the dashboard, without opening it.
    Daemon(daemon::Args),
    /// Print what this kernel supports, without recording (needs root).
    Check {
        /// Config file. Default: $K11_CONFIG, else /etc/k11/k11.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Run a command and record what it does (no root needed).
    Run(run::Args),
    /// What recorded sessions did, from the OCSF log (root-only by default).
    Report {
        /// A session's number in the list, or `last`. Without it: the list.
        session: Option<String>,
        /// The OCSF log to read. Default: the export output in the config.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Config file. Default: $K11_CONFIG, else /etc/k11/k11.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Open the dashboard with control: watch list, deny rules (needs root).
    Dashboard {
        /// The daemon's session socket; the control URL sits next to it.
        #[arg(long, env = "K11_SOCKET", default_value = config::DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Cmd::Run(args)) => return run::run(args),
        None => become_root().and_then(|()| {
            record(daemon::Args {
                open: true,
                ..cli.daemon
            })
        }),
        Some(Cmd::Daemon(args)) => become_root().and_then(|()| record(args)),
        Some(Cmd::Check { config }) => become_root().and_then(|()| {
            init_logging();
            check(config)
        }),
        Some(Cmd::Report {
            session,
            file,
            config,
        }) => report::run(session.as_deref(), file, config),
        Some(Cmd::Dashboard { socket }) => {
            become_root().and_then(|()| control::open_dashboard(&socket))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn record(args: daemon::Args) -> Result<()> {
    init_logging();
    tokio::runtime::Runtime::new()?.block_on(daemon::run(args))
}

/// The probe and the control token need root: run again through sudo, which
/// also tells `--open` whose browser to use.
fn become_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    eprintln!("k11: needs root, asking sudo");
    let exe = std::env::current_exe().context("finding this executable")?;
    let err = Command::new("sudo")
        .arg("--preserve-env=RUST_LOG,K11_CONFIG")
        .arg("--")
        .arg(exe)
        .args(std::env::args_os().skip(1))
        .exec();
    Err(err).context("running sudo")
}

fn check(config: Option<PathBuf>) -> Result<()> {
    let config = Config::load(config.as_deref())?;
    print!("{}", Probe::load(&config)?.capabilities.report());
    Ok(())
}

/// On stderr: stdout may carry the OCSF export.
fn init_logging() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
