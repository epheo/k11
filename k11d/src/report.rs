//! `k11 report`: what recorded sessions did, from the OCSF log. The log is
//! replayed through the daemon's own store, so a session reads as the
//! summary `k11 run` prints when its command ends.

use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::past::{Log, Session};
use crate::session::{body, duration};

/// `which`: a session's number in the list, or "last"; None lists them.
pub fn run(which: Option<&str>, file: Option<PathBuf>, config: Option<PathBuf>) -> Result<()> {
    let path = match file {
        Some(path) => path,
        None => {
            let config = Config::load(config.as_deref())?;
            if !config.export.enabled || config.export.output == "-" {
                bail!("the export writes no file (export.enabled, export.output): nothing to read; pass --file");
            }
            PathBuf::from(config.export.output)
        }
    };
    if let Err(e) = File::open(&path) {
        // The log is root-only: read it again as root.
        if e.kind() == ErrorKind::PermissionDenied && unsafe { libc::geteuid() } != 0 {
            crate::become_root()?;
        }
    }
    let log = Log::read(&path)?;
    if log.sessions.is_empty() {
        println!("k11: no sessions in {}", path.display());
        return Ok(());
    }
    if log.lost > 0 {
        println!(
            "k11: the log is missing {} records the daemon lost",
            log.lost
        );
    }
    if log.unreadable > 0 {
        println!("k11: {} lines are not k11 records; skipped", log.unreadable);
    }
    match which {
        None => list(&log, &path),
        Some(which) => {
            let n = match which {
                "last" => log.sessions.len(),
                n => n
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=log.sessions.len()).contains(n))
                    .with_context(|| {
                        format!(
                            "no session {n}: `k11 report` lists 1 to {}",
                            log.sessions.len()
                        )
                    })?,
            };
            show(&log.sessions[n - 1], n, log.sessions.len());
        }
    }
    Ok(())
}

fn list(log: &Log, path: &Path) {
    let n = log.sessions.len();
    println!(
        "k11: {n} session{} in {}",
        if n == 1 { "" } else { "s" },
        path.display()
    );
    for (i, session) in log.sessions.iter().enumerate() {
        let Some(s) = session.store.agents(0).agents.into_iter().next() else {
            continue;
        };
        let place = s
            .container
            .as_ref()
            .map(|c| {
                format!(
                    "  in {}",
                    crate::container::label(
                        &c.runtime,
                        &c.id,
                        Some(c.name.as_str()).filter(|n| !n.is_empty())
                    )
                )
            })
            .unwrap_or_default();
        let risk = if s.risk_reasons.is_empty() {
            s.risk.clone()
        } else {
            format!("{}: {}", s.risk, s.risk_reasons.join(", "))
        };
        println!(
            "  {:>3}  {}  {:>7}  {}{place}  {risk}",
            i + 1,
            local_time(s.first_seen_ms),
            duration(&s),
            s.root_comm,
        );
    }
    println!("`k11 report <number>` shows one; `k11 report last` the latest.");
}

fn show(session: &Session, n: usize, of: usize) {
    let enrich = |ip| session.enrich(ip);
    let Some(d) = session
        .store
        .agent_detail(session.root, 0, &enrich)
        .and_then(|r| r.detail)
    else {
        return;
    };
    let s = d.summary.clone().unwrap_or_default();
    println!(
        "\nk11: {}, {} for {} (session {n} of {of}, {})",
        s.root_comm,
        local_time(s.first_seen_ms),
        duration(&s),
        session.id,
    );
    print!("{}", body(&d, session.root, "with no exit in the log"));
}

/// `2026-11-03 14:02` in this machine's time zone.
pub fn local_time(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    // SAFETY: localtime_r writes only into `tm`; time_t is 64-bit on every
    // target k11 builds for.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(std::ptr::from_ref(&secs).cast(), &mut tm) }.is_null() {
        return String::from("?");
    }
    format!(
        "{}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    )
}
