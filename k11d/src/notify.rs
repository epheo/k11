//! `k11 notify`: a desktop alert for each new notice, with no dashboard
//! open. Run as the user whose desktop it is: it only reads, as the
//! dashboard does without control.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
use k11_proto::k11_client::K11Client;
use k11_proto::{AgentSummary, GetAgentsRequest, GetNoticesRequest, Notice, NoticeKind};
use tonic::transport::Channel;

use crate::config::Config;
use crate::report::local_time;

/// More new at once than this make one alert, not a wall of them.
const BURST: usize = 3;
const POLL: Duration = Duration::from_secs(1);
const RETRY: Duration = Duration::from_secs(3);

#[derive(clap::Args)]
pub struct Args {
    /// Config file, for the daemon's address. Default: $K11_CONFIG, else /etc/k11/k11.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    let config = Config::load(args.config.as_deref())?;
    let mut addr: SocketAddr = config
        .grpc
        .listen
        .parse()
        .with_context(|| format!("grpc.listen {:?}", config.grpc.listen))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
            IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
        });
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(watch(format!("http://{addr}")))
}

async fn watch(url: String) -> Result<()> {
    let mut desktop = Desktop { on: true };
    let mut client: Option<K11Client<Channel>> = None;
    let mut epoch = None;
    let mut after = 0;
    let mut said_down = false;
    loop {
        let Some(c) = client.as_mut() else {
            match K11Client::connect(url.clone()).await {
                Ok(c) => {
                    client = Some(c);
                    said_down = false;
                }
                Err(e) => {
                    if !said_down {
                        eprintln!("k11 notify: no daemon at {url} ({e}); trying again");
                        said_down = true;
                    }
                    tokio::time::sleep(RETRY).await;
                }
            }
            continue;
        };
        let res = match c.get_notices(GetNoticesRequest { after_id: after }).await {
            Ok(res) => res.into_inner(),
            Err(status) => {
                eprintln!("k11 notify: {}; trying again", status.message());
                client = None;
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        if epoch != Some(res.epoch) {
            // A daemon started: its ids start over, and what it already has
            // was there before this watched it.
            let all = c.get_notices(GetNoticesRequest { after_id: 0 }).await?;
            let all = all.into_inner();
            epoch = Some(all.epoch);
            after = all.notices.last().map_or(0, |n| n.id);
            println!(
                "k11 notify: watching {url}, {} notices so far; new ones as desktop alerts",
                all.notices.len()
            );
        } else if let Some(last) = res.notices.last() {
            after = last.id;
            let agents = c
                .get_agents(GetAgentsRequest { if_version_ne: 0 })
                .await
                .map(|r| r.into_inner().agents)
                .unwrap_or_default();
            let titles: HashMap<u32, String> =
                agents.iter().map(|a| (a.root_pid, title(a))).collect();
            alert(&res.notices, &titles, &mut desktop);
        }
        tokio::time::sleep(POLL).await;
    }
}

fn alert(fresh: &[Notice], titles: &HashMap<u32, String>, desktop: &mut Desktop) {
    for n in fresh {
        println!(
            "{} {:<5} {}  {}  {}",
            local_time(n.timestamp_ms),
            tag(n),
            who(n, titles),
            n.summary,
            n.peer_name
        );
    }
    if fresh.len() > BURST {
        desktop.show("k11", &format!("{} new notices", fresh.len()), false);
        return;
    }
    for n in fresh {
        let body = [n.summary.as_str(), n.peer_name.as_str()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        let serious = matches!(tag(n), "RULE" | "TRACE");
        desktop.show(&format!("k11: {}", who(n, titles)), &body, serious);
    }
}

struct Desktop {
    on: bool,
}

impl Desktop {
    fn show(&mut self, title: &str, body: &str, serious: bool) {
        if !self.on {
            return;
        }
        let urgency = if serious { "critical" } else { "normal" };
        let shown = Command::new("notify-send")
            .args([
                "--app-name=k11",
                &format!("--urgency={urgency}"),
                title,
                body,
            ])
            .status();
        match shown {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                eprintln!("k11 notify: no notify-send (libnotify): alerts print here only");
                self.on = false;
            }
            Err(e) => eprintln!("k11 notify: notify-send: {e}"),
        }
    }
}

/// As the dashboard titles a session: its project, or the agent's helper.
fn title(a: &AgentSummary) -> String {
    let cwd = a.root_cwd.trim_end_matches('/');
    if cwd.split('/').any(|c| c == format!(".{}", a.root_comm)) {
        return format!("{} helper", a.root_comm);
    }
    match cwd.rsplit('/').next() {
        Some(project) if !project.is_empty() => project.to_string(),
        _ => a.root_comm.clone(),
    }
}

fn who<'a>(n: &'a Notice, titles: &'a HashMap<u32, String>) -> &'a str {
    titles.get(&n.root_pid).map_or(&n.agent, String::as_str)
}

fn tag(n: &Notice) -> &'static str {
    match NoticeKind::try_from(n.kind) {
        Ok(NoticeKind::Host) => "NET",
        Ok(NoticeKind::Exposed) => "BIND",
        Ok(NoticeKind::Sensitive) => "FILE",
        Ok(NoticeKind::Rule) => "RULE",
        Ok(NoticeKind::Ptrace) => "TRACE",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(cwd: &str) -> AgentSummary {
        AgentSummary {
            root_comm: "claude".into(),
            root_cwd: cwd.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_session_is_titled_as_the_dashboard_does() {
        assert_eq!(title(&agent("/home/u/src/shop")), "shop");
        assert_eq!(title(&agent("/home/u/src/shop/")), "shop");
        assert_eq!(title(&agent("/home/u/.claude/chrome")), "claude helper");
        assert_eq!(title(&agent("")), "claude");
    }
}
