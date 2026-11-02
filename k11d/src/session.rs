//! The session socket. `k11 run` connects and the daemon makes the caller
//! the root of a new tree; when the connection ends, it answers with what
//! the session did. A caller can only register itself: its pid comes from
//! the kernel (SO_PEERCRED), not from the request.

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use k11_proto::{AgentDetail, ConnectionAccess, FileAccess};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::enrich::Enricher;
use crate::lineage::Lineage;
use crate::store::EventStore;

/// The session's last events can still be in the ring when the client
/// hangs up.
const DRAIN: Duration = Duration::from_millis(300);
const LISTED: usize = 5;

pub struct Sessions {
    pub lineage: Arc<Mutex<Lineage>>,
    pub store: Arc<Mutex<EventStore>>,
    pub enricher: Arc<Enricher>,
    /// Given to the client, so it can point at the live view.
    pub ui_url: String,
}

pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A socket left by an earlier run refuses the bind.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind the session socket {}", path.display()))?;
    // Anyone may record their own commands.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub async fn serve(listener: UnixListener, sessions: Arc<Sessions>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let sessions = Arc::clone(&sessions);
                tokio::spawn(async move {
                    if let Err(e) = sessions.session(stream).await {
                        warn!(error = %e, "session ended with an error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "session socket accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

impl Sessions {
    async fn session(&self, stream: UnixStream) -> Result<()> {
        let pid = stream.peer_cred()?.pid().context("peer has no pid")? as u32;
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let Some(request) = lines.next_line().await? else {
            return Ok(());
        };
        let label = request.strip_prefix("watch ").map(str::trim).unwrap_or("");
        if label.is_empty() {
            write.write_all(b"error expected: watch <label>\n").await?;
            return Ok(());
        }
        let watched = self.lineage.lock().unwrap().watch(pid);
        if let Err(e) = watched {
            write.write_all(format!("error {e:#}\n").as_bytes()).await?;
            return Ok(());
        }
        self.store.lock().unwrap().start_session(pid, label);
        info!(pid, label, "session started");
        write
            .write_all(format!("ok {}\n", self.ui_url).as_bytes())
            .await?;

        // The session lasts as long as the connection.
        while lines.next_line().await?.is_some() {}
        tokio::time::sleep(DRAIN).await;
        let summary = self.summary(pid);
        info!(pid, label, "session ended\n{summary}");
        // The client may be gone; the summary is in the log either way.
        let _ = write.write_all(summary.as_bytes()).await;
        Ok(())
    }

    fn summary(&self, root: u32) -> String {
        let enrich = |ip| self.enricher.addr(ip);
        let detail = self.store.lock().unwrap().agent_detail(root, 0, &enrich);
        match detail.and_then(|r| r.detail) {
            Some(d) => render(&d, root),
            None => "k11: nothing recorded for this session\n".into(),
        }
    }
}

/// The session summary: what ran, what it touched, where it went.
fn render(d: &AgentDetail, root: u32) -> String {
    let s = d.summary.clone().unwrap_or_default();
    let mut out = String::new();
    let secs = s.last_seen_ms.saturating_sub(s.first_seen_ms) / 1000;
    let _ = writeln!(
        out,
        "\nk11: {} recorded for {}m{:02}s{}",
        s.root_comm,
        secs / 60,
        secs % 60,
        if s.root_cwd.is_empty() {
            String::new()
        } else {
            format!(" in {}", s.root_cwd)
        },
    );
    let mut line = |label: &str, text: String| {
        if !text.is_empty() {
            let _ = writeln!(out, "  {label:<10} {text}");
        }
    };

    let left: Vec<String> = d
        .processes
        .iter()
        .filter(|p| p.running && p.pid != root)
        .map(|p| format!("{} {}", p.comm, p.pid))
        .collect();
    line(
        "processes",
        format!("{} started", s.process_count.saturating_sub(1))
            + &if left.is_empty() {
                String::new()
            } else {
                format!(", {} still running: {}", left.len(), listed(left))
            },
    );

    let count = |keep: fn(&FileAccess) -> bool| d.files.iter().filter(|f| keep(f)).count();
    line(
        "files",
        format!(
            "{} read, {} written, {} deleted, {} only failed",
            count(|f| !f.modified && !f.deleted && !only_failed(f)),
            count(|f| f.modified),
            count(|f| f.deleted),
            count(only_failed),
        ),
    );
    line(
        "sensitive",
        listed(
            d.files
                .iter()
                .filter(|f| f.sensitive && !only_failed(f))
                .map(file_mark),
        ),
    );
    line(
        "policy",
        listed(
            d.files
                .iter()
                .filter(|f| f.denied || f.audited)
                .map(file_mark),
        ),
    );
    line(
        "external",
        listed(d.connections.iter().filter(|c| c.external).map(peer)),
    );
    line(
        "exposed",
        listed(d.binds.iter().filter(|b| b.external).map(peer)),
    );
    line(
        "risk",
        if s.risk_reasons.is_empty() {
            s.risk.clone()
        } else {
            format!("{}: {}", s.risk, s.risk_reasons.join(", "))
        },
    );
    out
}

fn only_failed(f: &FileAccess) -> bool {
    f.access
        .as_ref()
        .is_some_and(|a| a.errors.values().sum::<u32>() == a.count)
}

fn file_mark(f: &FileAccess) -> String {
    let how = match () {
        _ if f.denied => "denied",
        _ if f.audited => "rule matched",
        _ if f.deleted => "deleted",
        _ if f.modified => "written",
        _ => "read",
    };
    format!("{} ({how})", f.path)
}

fn peer(c: &ConnectionAccess) -> String {
    let addr = if c.addr.contains(':') {
        format!("[{}]:{}", c.addr, c.port)
    } else {
        format!("{}:{}", c.addr, c.port)
    };
    let name = c
        .hostname
        .as_deref()
        .map(|h| format!("{h} "))
        .unwrap_or_default();
    let asn = c
        .asn
        .as_deref()
        .map(|a| format!(" ({a})"))
        .unwrap_or_default();
    format!("{name}{addr}{asn}")
}

/// The first few, then how many more.
fn listed(items: impl IntoIterator<Item = String>) -> String {
    let items: Vec<String> = items.into_iter().collect();
    let mut text = items
        .iter()
        .take(LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > LISTED {
        let _ = write!(text, ", +{} more", items.len() - LISTED);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use k11_proto::{Access, AgentSummary, ProcessInfo};

    fn file(path: &str, count: u32, errors: u32) -> FileAccess {
        FileAccess {
            path: path.into(),
            access: Some(Access {
                count,
                errors: if errors > 0 {
                    [("ENOENT".to_string(), errors)].into()
                } else {
                    Default::default()
                },
                ..Default::default()
            }),
            sensitive: path.contains(".ssh"),
            ..Default::default()
        }
    }

    #[test]
    fn summary_reads_like_a_report() {
        let d = AgentDetail {
            summary: Some(AgentSummary {
                root_comm: "claude".into(),
                process_count: 3,
                first_seen_ms: 1_000,
                last_seen_ms: 61_000,
                risk: "medium".into(),
                risk_reasons: vec!["sensitive files".into()],
                ..Default::default()
            }),
            processes: vec![
                ProcessInfo {
                    pid: 1,
                    comm: "k11".into(),
                    running: true,
                    ..Default::default()
                },
                ProcessInfo {
                    pid: 2,
                    comm: "node".into(),
                    running: true,
                    ..Default::default()
                },
            ],
            files: vec![
                file("/home/u/.ssh/config", 1, 0),
                file("/tmp/missing", 2, 2),
                FileAccess {
                    modified: true,
                    ..file("/tmp/out", 1, 0)
                },
            ],
            connections: vec![ConnectionAccess {
                addr: "2606:4700::1111".into(),
                port: 443,
                external: true,
                hostname: Some("one.one.one.one".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let text = render(&d, 1);
        for expected in [
            "k11: claude recorded for 1m00s",
            "processes  2 started, 1 still running: node 2",
            "files      1 read, 1 written, 0 deleted, 1 only failed",
            "sensitive  /home/u/.ssh/config (read)",
            "external   one.one.one.one [2606:4700::1111]:443",
            "risk       medium: sensitive files",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
        assert!(!text.contains("policy "), "empty lines are left out");
    }
}
