use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use k11_proto::k11_server::K11;
use k11_proto::*;

use crate::classify::error;
use crate::control::Token;
use crate::enrich::Enricher;
use crate::policy::PolicyMaps;
use crate::store::{self, EventStore};

pub struct K11Service {
    store: Arc<Mutex<EventStore>>,
    event_tx: broadcast::Sender<Arc<store::Event>>,
    enricher: Arc<Enricher>,
    policy: Arc<Mutex<PolicyMaps>>,
    token: Token,
}

impl K11Service {
    pub fn new(
        store: Arc<Mutex<EventStore>>,
        event_tx: broadcast::Sender<Arc<store::Event>>,
        enricher: Arc<Enricher>,
        policy: Arc<Mutex<PolicyMaps>>,
        token: Token,
    ) -> Self {
        Self {
            store,
            event_tx,
            enricher,
            policy,
            token,
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
    Status::permission_denied(
        "read-only dashboard: open it with `sudo k11 dashboard` to change the policy",
    )
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
            writable: self.token.admits(&req),
            ..self.policy.lock().unwrap().snapshot()
        };
        Ok(Response::new(snapshot))
    }

    async fn update_deny_rules(
        &self,
        req: Request<UpdateDenyRulesRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        if !self.token.admits(&req) {
            return Err(read_only());
        }
        let req = req.into_inner();
        let mut policy = self.policy.lock().unwrap();
        policy
            .update_deny_file_paths(&req.add_deny_file_paths, &req.remove_deny_file_paths)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        Ok(Response::new(self.snapshot(&policy)))
    }

    async fn set_enforce(
        &self,
        req: Request<SetEnforceRequest>,
    ) -> Result<Response<PolicySnapshot>, Status> {
        if !self.token.admits(&req) {
            return Err(read_only());
        }
        let mut policy = self.policy.lock().unwrap();
        policy
            .set_enforce(req.into_inner().enforce)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(self.snapshot(&policy)))
    }
}

// ---------------------------------------------------------------------------
// store types to proto types
// ---------------------------------------------------------------------------

impl From<&store::Event> for Event {
    fn from(e: &store::Event) -> Self {
        use store::Payload as P;
        let payload = match e.payload.clone() {
            P::Execve { filename } => event::Payload::Execve(ExecveEvent { filename }),
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
