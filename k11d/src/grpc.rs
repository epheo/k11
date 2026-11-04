use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use k11_proto::k11_server::K11;
use k11_proto::*;

use crate::classify::error;
use crate::control::Token;
use crate::enrich::Enricher;
use crate::lineage::Lineage;
use crate::policy::PolicyMaps;
use crate::state::Kept;
use crate::store::{self, EventStore};

/// What the control token gates, and where its changes are kept.
pub struct Control {
    pub token: Token,
    pub policy: Arc<Mutex<PolicyMaps>>,
    pub lineage: Arc<Mutex<Lineage>>,
    pub watch_all: bool,
    pub kept: Mutex<Kept>,
}

pub struct K11Service {
    store: Arc<Mutex<EventStore>>,
    event_tx: broadcast::Sender<Arc<store::Event>>,
    enricher: Arc<Enricher>,
    control: Control,
}

impl K11Service {
    pub fn new(
        store: Arc<Mutex<EventStore>>,
        event_tx: broadcast::Sender<Arc<store::Event>>,
        enricher: Arc<Enricher>,
        control: Control,
    ) -> Self {
        Self {
            store,
            event_tx,
            enricher,
            control,
        }
    }

    /// The answer to a change, after keeping it for the next start.
    fn changed(&self, policy: &PolicyMaps) -> PolicySnapshot {
        let snapshot = self.snapshot(policy);
        self.control
            .kept
            .lock()
            .unwrap()
            .set_policy(snapshot.enforce, &snapshot.deny_file_paths);
        snapshot
    }

    fn watch(&self, lineage: &Lineage, writable: bool) -> WatchSnapshot {
        WatchSnapshot {
            names: lineage.names().to_vec(),
            all: self.control.watch_all,
            writable,
        }
    }

    fn snapshot(&self, policy: &PolicyMaps) -> PolicySnapshot {
        PolicySnapshot {
            writable: true,
            ..policy.snapshot()
        }
    }
}

fn read_only() -> Status {
    Status::permission_denied("read-only dashboard: open it with `k11 dashboard` to make changes")
}

fn not_found(pid: u32) -> Status {
    Status::not_found(format!("agent {pid} not found"))
}

#[tonic::async_trait]
impl K11 for K11Service {
    async fn get_agents(
        &self,
        req: Request<GetAgentsRequest>,
    ) -> Result<Response<GetAgentsResponse>, Status> {
        let since = req.into_inner().if_version_ne;
        Ok(Response::new(self.store.lock().unwrap().agents(since)))
    }

    async fn get_agent_detail(
        &self,
        req: Request<GetAgentDetailRequest>,
    ) -> Result<Response<GetAgentDetailResponse>, Status> {
        let req = req.into_inner();
        let enrich = |ip| self.enricher.addr(ip);
        let response =
            self.store
                .lock()
                .unwrap()
                .agent_detail(req.root_pid, req.since_version, &enrich);
        response
            .map(Response::new)
            .ok_or_else(|| not_found(req.root_pid))
    }

    async fn get_agent_events(
        &self,
        req: Request<GetAgentEventsRequest>,
    ) -> Result<Response<GetAgentEventsResponse>, Status> {
        let req = req.into_inner();
        // Copy the tail out as Arcs so the conversion runs outside the lock.
        let tail: Vec<Arc<store::Event>> = {
            let store = self.store.lock().unwrap();
            let events = store
                .agent_events(req.root_pid)
                .ok_or_else(|| not_found(req.root_pid))?;
            let skip = match req.limit as usize {
                0 => 0,
                limit => events.len().saturating_sub(limit),
            };
            events.iter().skip(skip).cloned().collect()
        };
        Ok(Response::new(GetAgentEventsResponse {
            events: tail.iter().map(|e| Event::from(&**e)).collect(),
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<Event, Status>>;

    async fn stream_events(
        &self,
        req: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let filter_pid = req.into_inner().root_pid;
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
                if tx.send(Ok(Event::from(&*event))).await.is_err() {
                    break; // client disconnected
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(out_rx)))
    }

    async fn get_policy(
        &self,
        req: Request<GetPolicyRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        let snapshot = PolicySnapshot {
            writable: self.control.token.admits(&req),
            ..self.control.policy.lock().unwrap().snapshot()
        };
        Ok(Response::new(snapshot))
    }

    async fn update_deny_rules(
        &self,
        req: Request<UpdateDenyRulesRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        if !self.control.token.admits(&req) {
            return Err(read_only());
        }
        let req = req.into_inner();
        let mut policy = self.control.policy.lock().unwrap();
        policy
            .update_deny_file_paths(&req.add_deny_file_paths, &req.remove_deny_file_paths)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(self.changed(&policy)))
    }

    async fn set_enforce(
        &self,
        req: Request<SetEnforceRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        if !self.control.token.admits(&req) {
            return Err(read_only());
        }
        let mut policy = self.control.policy.lock().unwrap();
        policy
            .set_enforce(req.into_inner().enforce)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(self.changed(&policy)))
    }

    async fn get_notices(
        &self,
        req: Request<GetNoticesRequest>,
    ) -> Result<Response<GetNoticesResponse>, Status> {
        let writable = self.control.token.admits(&req);
        let after = req.into_inner().after_id;
        let enrich = |ip| self.enricher.addr(ip);
        let store = self.store.lock().unwrap();
        Ok(Response::new(GetNoticesResponse {
            writable,
            ..store.notices.view(after, &enrich)
        }))
    }

    /// Answers with the quiet list and no notices: the caller drops what it covers.
    async fn quiet_notices(
        &self,
        req: Request<QuietNoticesRequest>,
    ) -> Result<Response<GetNoticesResponse>, Status> {
        if !self.control.token.admits(&req) {
            return Err(read_only());
        }
        let req = req.into_inner();
        let mut store = self.store.lock().unwrap();
        let mut quiet = store.notices.quiet();
        quiet.retain(|k| !req.remove.contains(k));
        quiet.extend(req.add.into_iter().filter(|k| !k.trim().is_empty()));
        store.notices.set_quiet(quiet);
        let quiet = store.notices.quiet();
        self.control.kept.lock().unwrap().set_quiet(&quiet);
        let epoch = store.notices.view(u64::MAX, &|_| Default::default()).epoch;
        Ok(Response::new(GetNoticesResponse {
            epoch,
            notices: Vec::new(),
            quiet,
            writable: true,
        }))
    }

    async fn get_watch(
        &self,
        req: Request<GetWatchRequest>,
    ) -> Result<Response<WatchSnapshot>, Status> {
        let writable = self.control.token.admits(&req);
        Ok(Response::new(
            self.watch(&self.control.lineage.lock().unwrap(), writable),
        ))
    }

    async fn set_watch(
        &self,
        req: Request<SetWatchRequest>,
    ) -> Result<Response<WatchSnapshot>, Status> {
        if !self.control.token.admits(&req) {
            return Err(read_only());
        }
        if self.control.watch_all {
            return Err(Status::failed_precondition(
                "watch.all records every process: names do not apply",
            ));
        }
        let mut lineage = self.control.lineage.lock().unwrap();
        let seeded = lineage
            .set_names(&req.into_inner().names)
            .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
        self.control.kept.lock().unwrap().set_watch(lineage.names());
        let mut store = self.store.lock().unwrap();
        for sp in &seeded {
            store.seed_process(sp);
        }
        Ok(Response::new(self.watch(&lineage, true)))
    }
}

// ---------------------------------------------------------------------------
// store types to proto types
// ---------------------------------------------------------------------------

impl From<&store::Event> for Event {
    fn from(e: &store::Event) -> Self {
        use store::Payload as P;
        let payload = match e.payload.clone() {
            P::Execve { filename, cmd_line } => event::Payload::Execve(ExecveEvent {
                filename,
                cmd_line: cmd_line.map(|c| c.to_string()).unwrap_or_default(),
            }),
            P::Open {
                filename,
                flags,
                policy,
            } => event::Payload::Open(OpenEvent {
                filename,
                flags,
                policy: PolicyOutcome::from(policy) as i32,
            }),
            P::Connect { addr } => event::Payload::Connect(ConnectEvent {
                addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            P::ResolverConnect { addr } => event::Payload::ResolverConnect(ConnectEvent {
                addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            P::Fork { child_pid } => event::Payload::Fork(ForkEvent { child_pid }),
            P::UnixConnect { path } => event::Payload::UnixConnect(UnixConnectEvent { path }),
            P::Exit => event::Payload::Exit(ExitEvent {}),
            P::Bind { addr } => event::Payload::Bind(BindEvent {
                addr: addr.ip().to_string(),
                port: addr.port() as u32,
            }),
            P::Listen { backlog } => event::Payload::Listen(ListenEvent { backlog }),
            P::Unlink { filename, flags } => {
                event::Payload::Unlink(UnlinkEvent { filename, flags })
            }
            P::Rename { old_path, new_path } => {
                event::Payload::Rename(RenameEvent { old_path, new_path })
            }
            P::Chmod { filename, mode } => event::Payload::Chmod(ChmodEvent { filename, mode }),
            P::Chown {
                filename,
                owner_uid,
                owner_gid,
            } => event::Payload::Chown(ChownEvent {
                filename,
                owner_uid,
                owner_gid,
            }),
            P::Symlink { target, linkpath } => {
                event::Payload::Symlink(SymlinkEvent { target, linkpath })
            }
            P::Ptrace {
                request,
                target_pid,
            } => event::Payload::Ptrace(PtraceEvent {
                request,
                target_pid,
            }),
            P::Resolve { name, addrs } => event::Payload::Resolve(ResolveEvent {
                name,
                addrs: addrs.iter().map(ToString::to_string).collect(),
            }),
        };
        let m = &e.meta;
        Event {
            seq: m.seq,
            timestamp_ns: m.timestamp_ns,
            pid: m.pid,
            root_pid: m.root_pid,
            uid: m.uid,
            comm: m.comm.to_string(),
            ret: m.ret,
            error: error(m.ret).map(String::from).unwrap_or_default(),
            summary: e.describe(),
            sensitive: e.is_sensitive(),
            external: e.is_external(),
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
