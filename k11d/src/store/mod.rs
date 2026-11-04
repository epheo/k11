//! In-memory view of every agent tree: process table, per-path and per-peer
//! aggregates maintained as events arrive, and a bounded raw event ring for
//! the dashboard's log. The OCSF export is the durable record; this store
//! only has to answer the dashboard quickly. Views are proto messages built
//! directly, and only what changed since the client's version is sent.

mod event;
mod tree;

pub use event::{Event, EventMeta, Payload, Policy};

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use k11_proto as proto;
use tracing::debug;

use crate::enrich::EnrichedAddr;
use crate::lineage::SeededProcess;
use crate::notices::Notices;

use tree::AgentTree;

pub struct EventStore {
    agents: HashMap<u32, AgentTree>,
    pub notices: Notices,
    /// Bumped by every change, so clients can ask for what changed since.
    version: u64,
    max_events_per_agent: usize,
    /// Budget across all trees; when exceeded the largest tree gives way.
    max_total_events: usize,
    total_events: usize,
    /// Events come from the probe, not from a log.
    live: bool,
}

impl EventStore {
    pub fn new(max_events_per_agent: usize, max_total_events: usize) -> Self {
        Self {
            agents: HashMap::new(),
            notices: Notices::new(),
            version: 0,
            max_events_per_agent,
            max_total_events,
            total_events: 0,
            live: true,
        }
    }

    /// For events read back from a log: aggregates only, and nothing read
    /// from this machine's /proc.
    pub fn replay() -> Self {
        Self {
            live: false,
            ..Self::new(1, 1)
        }
    }

    /// Pre-populate a process entry from the /proc scan at startup, so
    /// processes that existed before k11 started have correct parent linkage.
    /// A process already running when its name became watched, as /proc
    /// shows it.
    pub fn seed_process(&mut self, p: &SeededProcess) {
        self.version += 1;
        let agent = self
            .agents
            .entry(p.root_pid)
            .or_insert_with(|| AgentTree::new(p.root_pid, &p.comm, true));
        agent.version = self.version;
        if p.pid == p.root_pid && agent.summary.first_seen_ms == 0 {
            agent.summary.first_seen_ms = p.started_ms;
        }
        let entry = agent.process(p.pid, &Arc::from(p.comm.as_str()), 0);
        entry.first_seen_ms = p.started_ms;
        entry.parent_pid = p.parent_pid;
        entry.cmd_line = p.cmd_line.clone().map(Arc::new);
    }

    /// A `k11 run` session: `root_pid` is the k11 process that will spawn
    /// the command, and the tree is named after the command.
    pub fn start_session(&mut self, root_pid: u32, label: &str) {
        self.version += 1;
        let mut tree = AgentTree::new(root_pid, label, true);
        tree.version = self.version;
        tree.process(root_pid, &Arc::from("k11"), 0);
        self.agents.insert(root_pid, tree);
    }

    /// What makes no notice; an agent's risk then leaves it out too.
    pub fn set_quiet(&mut self, quiet: impl IntoIterator<Item = String>) {
        self.notices.set_quiet(quiet);
        self.version += 1;
    }

    /// Takes the event in, and gives it back under its process's name.
    pub fn push(&mut self, event: Arc<Event>) -> Arc<Event> {
        self.version += 1;
        let root_pid = event.meta.root_pid;
        let live = self.live;
        let agent = self.agents.entry(root_pid).or_insert_with(|| {
            // Trees start with exec (comm discovery) or fork (lineage); in
            // watch-all mode a process older than k11d starts its own.
            if !matches!(event.payload, Payload::Execve { .. } | Payload::Fork { .. }) {
                debug!(root_pid, comm = %event.meta.comm, "agent tree created from a non-exec event");
            }
            AgentTree::new(root_pid, &event.meta.comm, live)
        });
        let event = agent.named(event);
        self.notices.observe(&event, &agent.summary.root_comm);
        let before = agent.events.len();
        agent.ingest(Arc::clone(&event), self.version, self.max_events_per_agent);
        self.total_events += agent.events.len() - before;

        if self.total_events > self.max_total_events {
            if let Some(largest) = self.agents.values_mut().max_by_key(|a| a.events.len()) {
                largest.drop_oldest();
                self.total_events -= 1;
            }
        }
        event
    }

    /// Drop trees whose processes have all exited and whose last event is
    /// older than `ttl_ms`. Returns how many trees were evicted.
    pub fn evict_exited(&mut self, now_ms: u64, ttl_ms: u64) -> usize {
        let before = self.agents.len();
        let mut freed = 0;
        let notices = &mut self.notices;
        self.agents.retain(|&root, agent| {
            let s = &agent.summary;
            let keep = s.running_count > 0 || now_ms.saturating_sub(s.last_seen_ms) < ttl_ms;
            if !keep {
                freed += agent.events.len();
                notices.forget(root);
            }
            keep
        });
        self.total_events -= freed;
        let evicted = before - self.agents.len();
        if evicted > 0 {
            self.version += 1;
        }
        evicted
    }

    /// Every agent's summary, newest first, unless nothing changed since
    /// `if_version_ne`. Not by activity: rows would move under the cursor.
    pub fn agents(&self, if_version_ne: u64) -> proto::GetAgentsResponse {
        let mut agents: Vec<proto::AgentSummary> = if self.version == if_version_ne {
            Vec::new()
        } else {
            self.agents
                .values()
                .map(|a| a.summary(&self.notices.news(a.summary.root_pid)))
                .collect()
        };
        agents.sort_by_key(|a| std::cmp::Reverse((a.first_seen_ms, a.root_pid)));
        proto::GetAgentsResponse {
            version: self.version,
            agents,
        }
    }

    pub fn agent_events(&self, root_pid: u32) -> Option<&VecDeque<Arc<Event>>> {
        self.agents.get(&root_pid).map(|a| &a.events)
    }

    /// What changed in one tree after `since`; None for an unknown tree.
    pub fn agent_detail(
        &self,
        root_pid: u32,
        since: u64,
        enrich: &dyn Fn(IpAddr) -> EnrichedAddr,
    ) -> Option<proto::GetAgentDetailResponse> {
        let tree = self.agents.get(&root_pid)?;
        Some(proto::GetAgentDetailResponse {
            version: tree.version,
            detail: (tree.version > since)
                .then(|| tree.detail(since, enrich, &self.notices.news(root_pid))),
        })
    }
}

#[cfg(test)]
mod tests;
