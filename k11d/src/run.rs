//! `k11 run -- <command>`: record one command, run as the calling user with
//! its own environment and terminal. This process registers itself with the
//! daemon before spawning, so the whole tree is recorded from its first fork.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};

use crate::config::DEFAULT_SOCKET;

#[derive(clap::Args)]
pub struct Args {
    /// Session name in the dashboard and the summary (default: the command's name).
    #[arg(long)]
    label: Option<String>,
    /// The daemon's session socket.
    #[arg(long, env = "K11_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// The command to record, and its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Exit with the command's status; 125 when k11 itself failed (as `env` and
/// `timeout` do), 126 or 127 when the command could not be started.
pub fn run(args: Args) -> ExitCode {
    match session(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("k11: {e:#}");
            ExitCode::from(125)
        }
    }
}

fn session(args: Args) -> Result<u8> {
    let program = &args.command[0];
    if !runnable(program) {
        eprintln!("k11: {program}: command not found");
        return Ok(127);
    }
    let label = args.label.clone().unwrap_or_else(|| {
        Path::new(program)
            .file_name()
            .map_or_else(|| program.clone(), |n| n.to_string_lossy().into_owned())
    });
    let stream = UnixStream::connect(&args.socket).with_context(|| {
        format!(
            "no k11 daemon at {}; start one with `k11`",
            args.socket.display()
        )
    })?;
    let mut reply = BufReader::new(stream.try_clone()?);
    writeln!(&stream, "watch {label}")?;
    let mut line = String::new();
    reply.read_line(&mut line)?;
    let Some(url) = line.trim().strip_prefix("ok ") else {
        bail!("the daemon refused the session: {}", line.trim());
    };
    eprintln!("k11: recording {label}, live at {url}");

    // Ctrl-C and Ctrl-\ belong to the command; k11 waits for it and reports.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }
    let mut command = Command::new(program);
    command.args(&args.command[1..]);
    // SAFETY: signal(2) is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    let code = match command.status() {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        Err(e) => {
            eprintln!("k11: {program}: {e}");
            if e.kind() == ErrorKind::NotFound {
                127
            } else {
                126
            }
        }
    };

    stream.shutdown(Shutdown::Write)?;
    let mut summary = String::new();
    reply.read_to_string(&mut summary)?;
    eprint!("{summary}");
    Ok(code as u8)
}

/// Found as the shell would: a path as given, a bare name on PATH. Checked
/// before registering, so a typo opens no session.
fn runnable(program: &str) -> bool {
    let executable = |p: &Path| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if program.contains('/') {
        return executable(Path::new(program));
    }
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| executable(&dir.join(program))))
}
