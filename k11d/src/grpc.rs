use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use k11_proto::k11_server::K11;
use k11_proto::*;

use crate::enrich::Enricher;
use crate::ocsf;
use crate::policy::PolicyMaps;
use crate::store::{self, EventStore};

pub struct K11Service {
    store: Arc<Mutex<EventStore>>,
    event_tx: broadcast::Sender<Arc<store::Event>>,
    enricher: Arc<Enricher>,
    policy: Arc<Mutex<PolicyMaps>>,
    hostname: String,
}

impl K11Service {
    pub fn new(
        store: Arc<Mutex<EventStore>>,
        event_tx: broadcast::Sender<Arc<store::Event>>,
        enricher: Arc<Enricher>,
        policy: Arc<Mutex<PolicyMaps>>,
        hostname: String,
    ) -> Self {
        Self {
            store,
            event_tx,
            enricher,
            policy,
            hostname,
        }
    }
}

fn not_found(pid: u32) -> Status {
    Status::not_found(format!("agent {pid} not found"))
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
    ) -> Result<Response<GetAgentDetailResponse>, Status> {
        let req = req.into_inner();
        let detail = {
            let store = self.store.lock().unwrap();
            let version = store
                .agent_version(req.root_pid)
                .ok_or_else(|| not_found(req.root_pid))?;
            if req.if_version_ne != 0 && version == req.if_version_ne {
                return Ok(Response::new(GetAgentDetailResponse {
                    version,
                    detail: None,
                }));
            }
            store.agent_detail(req.root_pid)
        };
        let mut detail = detail.ok_or_else(|| not_found(req.root_pid))?;
        self.enricher.connections(&mut detail.connections);
        Ok(Response::new(GetAgentDetailResponse {
            version: detail.version,
            detail: Some(detail.into()),
        }))
    }

    async fn get_agent_events(
        &self,
        req: Request<GetAgentEventsRequest>,
    ) -> Result<Response<GetAgentEventsResponse>, Status> {
        let req = req.into_inner();
        // Copy the page out as Arcs so the conversion runs outside the lock.
        let (page, total) = {
            let store = self.store.lock().unwrap();
            let events = store
                .agent_events(req.root_pid)
                .ok_or_else(|| not_found(req.root_pid))?;
            let limit = if req.limit == 0 {
                events.len()
            } else {
                req.limit as usize
            };
            let page: Vec<Arc<store::Event>> = events
                .iter()
                .skip(req.offset as usize)
                .take(limit)
                .cloned()
                .collect();
            (page, events.len() as u32)
        };
        Ok(Response::new(GetAgentEventsResponse {
            events: page.iter().map(|e| Event::from(&**e)).collect(),
            total,
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        req: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let req = req.into_inner();
        let filter_pid = req.root_pid;
        let ocsf = req.format == EventFormat::Ocsf as i32;
        let hostname = self.hostname.clone();
        let enricher = Arc::clone(&self.enricher);
        let mut rx = self.event_tx.subscribe();
        let (tx, out_rx) = tokio::sync::mpsc::channel(256);

        tokio::spawn(async move {
            loop {
                let event = match rx.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(dropped = n, "stream_events: client lagged");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if filter_pid.is_some_and(|pid| event.meta.root_pid != pid) {
                    continue;
                }
                let payload = if ocsf {
                    let enriched = enricher.event(&event);
                    let json = serde_json::to_string(&ocsf::record(&event, &enriched, &hostname))
                        .expect("OCSF record serializes");
                    stream_events_response::Payload::OcsfJson(json)
                } else {
                    stream_events_response::Payload::Event(Event::from(&*event))
                };
                if tx
                    .send(Ok(StreamEventsResponse {
                        payload: Some(payload),
                    }))
                    .await
                    .is_err()
                {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(out_rx)))
    }

    async fn get_policy(
        &self,
        _req: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        Ok(Response::new(self.policy.lock().unwrap().snapshot().into()))
    }

    async fn update_deny_rules(
        &self,
        req: Request<UpdateDenyRulesRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        let req = req.into_inner();
        let mut policy = self.policy.lock().unwrap();
        for path in &req.add_deny_file_paths {
            policy
                .add_deny_file_path(path)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        }
        for path in &req.remove_deny_file_paths {
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
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(policy.snapshot().into()))
    }
}

// ---------------------------------------------------------------------------
// store types to proto types
// ---------------------------------------------------------------------------

impl From<&store::Event> for Event {
    fn from(e: &store::Event) -> Self {
        let sensitive = e.is_sensitive();
        let external = e.is_external();
        let payload = match e.payload.clone() {
            store::Payload::Execve { filename } => event::Payload::Execve(ExecveEvent {
                filename,
                sensitive,
            }),
            store::Payload::Openat {
                filename,
                flags,
                ret,
                policy,
            } => event::Payload::Openat(OpenatEvent {
                filename,
                flags,
                ret,
                policy: PolicyOutcome::from(policy) as i32,
                sensitive,
            }),
            store::Payload::Connect { addr, port, ret } => event::Payload::Connect(ConnectEvent {
                addr,
                port: port as u32,
                ret,
                external,
            }),
            store::Payload::Fork { child_pid } => event::Payload::Fork(ForkEvent { child_pid }),
            store::Payload::UnixConnect { path, ret } => {
                event::Payload::UnixConnect(UnixConnectEvent { path, ret })
            }
            store::Payload::Exit => event::Payload::Exit(ExitEvent {}),
            store::Payload::Bind { addr, port, ret } => event::Payload::Bind(BindEvent {
                addr,
                port: port as u32,
                ret,
                external,
            }),
            store::Payload::Listen { backlog, ret } => {
                event::Payload::Listen(ListenEvent { backlog, ret })
            }
            store::Payload::Unlink {
                filename,
                flags,
                ret,
            } => event::Payload::Unlink(UnlinkEvent {
                filename,
                flags,
                ret,
                sensitive,
            }),
            store::Payload::Rename {
                old_path,
                new_path,
                ret,
            } => event::Payload::Rename(RenameEvent {
                old_path,
                new_path,
                ret,
                sensitive,
            }),
            store::Payload::Chmod {
                filename,
                mode,
                ret,
            } => event::Payload::Chmod(ChmodEvent {
                filename,
                mode,
                ret,
                sensitive,
            }),
            store::Payload::Chown {
                filename,
                owner_uid,
                owner_gid,
                ret,
            } => event::Payload::Chown(ChownEvent {
                filename,
                owner_uid,
                owner_gid,
                ret,
                sensitive,
            }),
            store::Payload::Symlink {
                target,
                linkpath,
                ret,
            } => event::Payload::Symlink(SymlinkEvent {
                target,
                linkpath,
                ret,
                sensitive,
            }),
            store::Payload::Ptrace {
                request,
                target_pid,
                ret,
            } => event::Payload::Ptrace(PtraceEvent {
                request,
                target_pid,
                ret,
            }),
        };
        Event {
            timestamp_ns: e.meta.timestamp_ns,
            pid: e.meta.pid,
            root_pid: e.meta.root_pid,
            uid: e.meta.uid,
            comm: e.meta.comm.to_string(),
            payload: Some(payload),
        }
    }
}

impl From<store::Policy> for PolicyOutcome {
    fn from(p: store::Policy) -> Self {
        match p {
            store::Policy::Allowed => PolicyOutcome::Allowed,
            store::Policy::Audited => PolicyOutcome::Audited,
            store::Policy::Denied => PolicyOutcome::Denied,
        }
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
            audit_count: s.audit_count as u32,
            fs_mod_count: s.fs_mod_count as u32,
            bind_count: s.bind_count as u32,
            ptrace_count: s.ptrace_count as u32,
            has_sensitive_files: s.has_sensitive_files,
            has_sensitive_writes: s.has_sensitive_writes,
            has_sensitive_delete: s.has_sensitive_delete,
            has_external_net: s.has_external_net,
            has_listener: s.has_listener,
            has_ptrace: s.has_ptrace,
            events_dropped: s.events_dropped,
        }
    }
}

impl From<store::AgentDetail> for AgentDetail {
    fn from(d: store::AgentDetail) -> Self {
        Self {
            root_pid: d.root_pid,
            root_comm: d.root_comm,
            version: d.version,
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

impl From<store::Access> for Access {
    fn from(a: store::Access) -> Self {
        Self {
            count: a.count as u32,
            errors: a.errors.into_iter().map(|(k, v)| (k, v as u32)).collect(),
            comms: a.comms,
            first_seen_ms: a.first_seen_ms,
            last_seen_ms: a.last_seen_ms,
        }
    }
}

impl From<store::FileAccess> for FileAccess {
    fn from(f: store::FileAccess) -> Self {
        Self {
            path: f.path,
            access: Some(f.access.into()),
            sensitive: f.sensitive,
            modified: f.modified,
            deleted: f.deleted,
            renamed: f.renamed,
            perm_changed: f.perm_changed,
            owner_changed: f.owner_changed,
            is_symlink: f.is_symlink,
            denied: f.denied,
            audited: f.audited,
        }
    }
}

impl From<store::ConnectionAccess> for ConnectionAccess {
    fn from(c: store::ConnectionAccess) -> Self {
        Self {
            addr: c.addr,
            port: c.port as u32,
            access: Some(c.access.into()),
            external: c.external,
            hostname: c.enrich.hostname,
            country: c.enrich.country,
            city: c.enrich.city,
            asn: c.enrich.asn,
        }
    }
}

impl From<store::UnixSocketAccess> for UnixSocketAccess {
    fn from(u: store::UnixSocketAccess) -> Self {
        Self {
            path: u.path,
            access: Some(u.access.into()),
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
