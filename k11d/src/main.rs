mod btf_offsets;
mod classify;
mod config;
mod control;
mod daemon;
mod decode;
mod dns_cache;
mod enrich;
mod export;
mod grpc;
mod lineage;
mod ocsf;
mod policy;
mod probe;
mod run;
mod session;
mod store;
mod tracefs;
mod web;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::probe::Probe;

/// Black-box recorder for AI coding agents.
#[derive(Parser)]
#[command(name = "k11", version)]
enum Cli {
    /// Record: load the probe and serve the dashboard (needs root).
    Daemon(daemon::Args),
    /// Print what this kernel supports, without recording (needs root).
    Check {
        /// Config file. Default: $K11_CONFIG, /etc/k11/k11.toml, config/k11.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Run a command and record what it does (no root needed).
    Run(run::Args),
    /// Open the dashboard with control over the policy (needs root).
    Dashboard {
        /// The daemon's session socket; the control URL sits next to it.
        #[arg(long, env = "K11_SOCKET", default_value = config::DEFAULT_SOCKET)]
        socket: PathBuf,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse() {
        Cli::Run(args) => return run::run(args),
        Cli::Daemon(args) => {
            init_logging();
            tokio::runtime::Runtime::new()
                .map_err(Into::into)
                .and_then(|rt| rt.block_on(daemon::run(args)))
        }
        Cli::Check { config } => {
            init_logging();
            check(config)
        }
        Cli::Dashboard { socket } => control::open_dashboard(&socket),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
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
