use std::sync::{Arc, Mutex};

use maxminddb::Reader as GeoIpReader;
use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use k11_proto::k11_server::K11;
use k11_proto::*;

use crate::dns_cache::DnsCache;
use crate::enrich::{self, PasswdCache};
use crate::policy::PolicyMaps;
use crate::store::{self, EventStore};

pub struct K11Service {
    store: Arc<Mutex<EventStore>>,
    event_tx: broadcast::Sender<store::Event>,
    dns_cache: Arc<DnsCache>,
    geoip: Option<Arc<GeoIpReader<Vec<u8>>>>,
    geoip_asn: Option<Arc<GeoIpReader<Vec<u8>>>>,
    passwd: Arc<PasswdCache>,
    policy: Arc<Mutex<PolicyMaps>>,
    hostname: String,
}

impl K11Service {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Mutex<EventStore>>,
        event_tx: broadcast::Sender<store::Event>,
        dns_cache: Arc<DnsCache>,
        geoip: Option<Arc<GeoIpReader<Vec<u8>>>>,
        geoip_asn: Option<Arc<GeoIpReader<Vec<u8>>>>,
        passwd: Arc<PasswdCache>,
        policy: Arc<Mutex<PolicyMaps>>,
        hostname: String,
    ) -> Self {
        Self { store, event_tx, dns_cache, geoip, geoip_asn, passwd, policy, hostname }
    }
}

#[tonic::async_trait]
impl K11 for K11Service {
    async fn get_agents(
        &self,
        _req: Request<GetAgentsRequest>,
    ) -> Result<Response<GetAgentsResponse>, Status> {
        let agents = self.store.lock().unwrap().agents_summary();
        Ok(Response::new(GetAgentsResponse {
            agents: agents.into_iter().map(Into::into).collect(),
        }))
    }

    async fn get_agent_detail(
        &self,
        req: Request<GetAgentDetailRequest>,
    ) -> Result<Response<AgentDetail>, Status> {
        let pid = req.into_inner().root_pid;
        let mut detail = self
            .store
            .lock()
            .unwrap()
            .agent_detail(pid)
            .ok_or_else(|| Status::not_found(format!("agent {pid} not found")))?;

        enrich::enrich_connections(
            &mut detail.connections,
            &self.dns_cache,
            &self.geoip,
            &self.geoip_asn,
        )
        .await;

        Ok(Response::new(detail.into()))
    }

    async fn get_agent_events(
        &self,
        req: Request<GetAgentEventsRequest>,
    ) -> Result<Response<GetAgentEventsResponse>, Status> {
        let inner = req.into_inner();
        let store = self.store.lock().unwrap();
        let all = store.agent_events(inner.root_pid);
        let total = all.len() as u32;

        let offset = inner.offset as usize;
        let limit = if inner.limit == 0 { all.len() } else { inner.limit as usize };

        let events = all
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .map(Into::into)
            .collect();

        Ok(Response::new(GetAgentEventsResponse { events, total }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        req: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let inner = req.into_inner();
        let filter_pid = inner.root_pid;
        let ocsf = inner.format == EventFormat::Ocsf as i32;
        let hostname = self.hostname.clone();

        let mut rx = self.event_tx.subscribe();
        let (tx, out_rx) = tokio::sync::mpsc::channel(256);
        let dns_cache = Arc::clone(&self.dns_cache);
        let geoip = self.geoip.clone();
        let geoip_asn = self.geoip_asn.clone();
        let passwd = Arc::clone(&self.passwd);

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if let Some(pid) = filter_pid {
                            if !event_matches_pid(&event, pid) {
                                continue;
                            }
                        }

                        let payload = if ocsf {
                            let enriched = enrich::enrich_event(
                                &event, &dns_cache, &geoip, &geoip_asn, &passwd,
                            )
                            .await;
                            let json = crate::ocsf::to_ocsf(&event, &enriched, &hostname);
                            stream_events_response::Payload::OcsfJson(json.to_string())
                        } else {
                            stream_events_response::Payload::Event(event.into())
                        };

                        let msg = Ok(StreamEventsResponse {
                            payload: Some(payload),
                        });
                        if tx.send(msg).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "stream_events: client lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(out_rx)))
    }

    async fn get_policy(
        &self,
        _req: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        let snapshot = self.policy.lock().unwrap().snapshot();
        Ok(Response::new(snapshot.into()))
    }

    async fn update_deny_rules(
        &self,
        req: Request<UpdateDenyRulesRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        let inner = req.into_inner();
        let mut policy = self.policy.lock().unwrap();

        for path in &inner.add_deny_file_paths {
            policy
                .add_deny_file_path(path)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        }
        for path in &inner.remove_deny_file_paths {
            policy
                .remove_deny_file_path(path)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        }

        Ok(Response::new(policy.snapshot().into()))
    }

    async fn set_enforce(
        &self,
        req: Request<SetEnforceRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        let mut policy = self.policy.lock().unwrap();
        policy
            .set_enforce(req.into_inner().enforce)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(policy.snapshot().into()))
    }

    async fn get_config(
        &self,
        _req: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        Ok(Response::new(GetConfigResponse {
            sensitive_paths: store::SENSITIVE_PATHS.iter().map(|s| s.to_string()).collect(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn event_matches_pid(event: &store::Event, pid: u32) -> bool {
    match event {
        store::Event::Execve { root_pid, .. } => *root_pid == pid,
        store::Event::Fork { parent_pid, .. } => *parent_pid == pid,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// From conversions: store types → proto types
// ---------------------------------------------------------------------------

impl From<store::Event> for Event {
    fn from(e: store::Event) -> Self {
        let (timestamp_ns, payload) = match e {
            store::Event::Execve { pid, root_pid, uid, comm, filename, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Execve(ExecveEvent { pid, root_pid, uid, comm, filename }),
            ),
            store::Event::Openat { pid, comm, filename, flags, ret, timestamp_ns, denied } => (
                timestamp_ns,
                event::Payload::Openat(OpenatEvent { pid, comm, filename, flags, ret, denied }),
            ),
            store::Event::Connect { pid, comm, addr, port, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Connect(ConnectEvent {
                    pid, comm, addr, port: port as u32, ret,
                }),
            ),
            store::Event::Fork { parent_pid, child_pid, comm, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Fork(ForkEvent { parent_pid, child_pid, comm }),
            ),
            store::Event::UnixConnect { pid, comm, path, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::UnixConnect(UnixConnectEvent { pid, comm, path, ret }),
            ),
            store::Event::Exit { pid, comm, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Exit(ExitEvent { pid, comm }),
            ),
            store::Event::Bind { pid, comm, addr, port, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Bind(BindEvent { pid, comm, addr, port: port as u32, ret }),
            ),
            store::Event::Listen { pid, comm, backlog, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Listen(ListenEvent { pid, comm, backlog, ret }),
            ),
            store::Event::Unlink { pid, comm, filename, flags, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Unlink(UnlinkEvent { pid, comm, filename, flags, ret }),
            ),
            store::Event::Rename { pid, comm, old_path, new_path, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Rename(RenameEvent { pid, comm, old_path, new_path, ret }),
            ),
            store::Event::Chmod { pid, comm, filename, mode, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Chmod(ChmodEvent { pid, comm, filename, mode, ret }),
            ),
            store::Event::Chown { pid, comm, filename, owner_uid, owner_gid, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Chown(ChownEvent { pid, comm, filename, owner_uid, owner_gid, ret }),
            ),
            store::Event::Symlink { pid, comm, target, linkpath, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Symlink(SymlinkEvent { pid, comm, target, linkpath, ret }),
            ),
            store::Event::Ptrace { pid, comm, request, target_pid, ret, timestamp_ns } => (
                timestamp_ns,
                event::Payload::Ptrace(PtraceEvent { pid, comm, request, target_pid, ret }),
            ),
        };
        Event { timestamp_ns, payload: Some(payload) }
    }
}

impl From<store::AgentSummary> for AgentSummary {
    fn from(s: store::AgentSummary) -> Self {
        Self {
            root_pid: s.root_pid,
            root_comm: s.root_comm,
            process_count: s.process_count as u32,
            running_count: s.running_count as u32,
            exited_count: s.exited_count as u32,
            file_count: s.file_count as u32,
            net_count: s.net_count as u32,
            unix_count: s.unix_count as u32,
            exec_count: s.exec_count as u32,
            deny_count: s.deny_count as u32,
            fs_mod_count: s.fs_mod_count as u32,
            bind_count: s.bind_count as u32,
            ptrace_count: s.ptrace_count as u32,
            has_sensitive_files: s.has_sensitive_files,
            has_sensitive_writes: s.has_sensitive_writes,
            has_sensitive_delete: s.has_sensitive_delete,
            has_external_net: s.has_external_net,
            has_listener: s.has_listener,
            has_ptrace: s.has_ptrace,
        }
    }
}

impl From<store::AgentDetail> for AgentDetail {
    fn from(d: store::AgentDetail) -> Self {
        Self {
            root_pid: d.root_pid,
            root_comm: d.root_comm,
            processes: d.processes.into_iter().map(Into::into).collect(),
            files: d.files.into_iter().map(Into::into).collect(),
            connections: d.connections.into_iter().map(Into::into).collect(),
            binds: d.binds.into_iter().map(Into::into).collect(),
            unix_sockets: d.unix_sockets.into_iter().map(Into::into).collect(),
            summary: Some(d.summary.into()),
        }
    }
}

impl From<store::ProcessInfo> for ProcessInfo {
    fn from(p: store::ProcessInfo) -> Self {
        Self {
            pid: p.pid,
            comm: p.comm,
            parent_pid: p.parent_pid,
            running: p.running,
            file_count: p.file_count as u32,
            net_count: p.net_count as u32,
            unix_count: p.unix_count as u32,
            exec_count: p.exec_count as u32,
            first_seen_ms: p.first_seen_ms,
            last_seen_ms: p.last_seen_ms,
        }
    }
}

impl From<store::FileAccess> for FileAccess {
    fn from(f: store::FileAccess) -> Self {
        Self {
            path: f.path,
            count: f.count as u32,
            errors: f.errors.into_iter().map(|(k, v)| (k, v as u32)).collect(),
            comms: f.comms,
            sensitive: f.sensitive,
            modified: f.modified,
            deleted: f.deleted,
            renamed: f.renamed,
            perm_changed: f.perm_changed,
            owner_changed: f.owner_changed,
            is_symlink: f.is_symlink,
            denied: f.denied,
            first_seen_ms: f.first_seen_ms,
            last_seen_ms: f.last_seen_ms,
        }
    }
}

impl From<store::ConnectionAccess> for ConnectionAccess {
    fn from(c: store::ConnectionAccess) -> Self {
        Self {
            addr: c.addr,
            port: c.port as u32,
            count: c.count as u32,
            errors: c.errors.into_iter().map(|(k, v)| (k, v as u32)).collect(),
            comms: c.comms,
            external: c.external,
            hostname: c.hostname,
            country: c.country,
            city: c.city,
            asn: c.asn,
            first_seen_ms: c.first_seen_ms,
            last_seen_ms: c.last_seen_ms,
        }
    }
}

impl From<store::UnixSocketAccess> for UnixSocketAccess {
    fn from(u: store::UnixSocketAccess) -> Self {
        Self {
            path: u.path,
            count: u.count as u32,
            errors: u.errors.into_iter().map(|(k, v)| (k, v as u32)).collect(),
            comms: u.comms,
            first_seen_ms: u.first_seen_ms,
            last_seen_ms: u.last_seen_ms,
        }
    }
}

impl From<crate::policy::PolicySnapshot> for PolicySnapshot {
    fn from(p: crate::policy::PolicySnapshot) -> Self {
        Self {
            enforce: p.enforce,
            deny_file_paths: p.deny_file_paths,
        }
    }
}
