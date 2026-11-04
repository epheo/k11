//! Sessions in the OCSF log on disk, replayed through the daemon's own
//! store: what `k11 report` prints and the dashboard's past sessions show.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, ErrorKind, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use k11_proto as proto;

use crate::enrich::EnrichedAddr;
use crate::ocsf::{replay, Line};
use crate::store::EventStore;

pub struct Session {
    /// `<boot id>:<root pid>`, the records' `metadata.correlation_uid`.
    pub id: String,
    pub root: u32,
    pub store: EventStore,
    pub peers: HashMap<IpAddr, EnrichedAddr>,
}

impl Session {
    pub fn enrich(&self, ip: IpAddr) -> EnrichedAddr {
        self.peers.get(&ip).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
pub struct Log {
    /// In order of their first record.
    pub sessions: Vec<Session>,
    index: HashMap<String, usize>,
    /// Records the daemon could not write, as its loss markers count them.
    pub lost: u64,
    pub unreadable: usize,
}

impl Log {
    /// The whole log: the rotated file holds the older records, so it is
    /// read first.
    pub fn read(path: &Path) -> Result<Self> {
        let mut log = Self::default();
        log.read_file(&rotated(path), 0, true)?;
        log.read_file(path, 0, false)?;
        Ok(log)
    }

    /// From `offset`, complete lines only; returns where it stopped.
    fn read_file(&mut self, path: &Path, offset: u64, may_be_missing: bool) -> Result<u64> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound && may_be_missing => return Ok(0),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut at = offset;
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .with_context(|| format!("reading {}", path.display()))?;
            // A line still being written is read next time, whole.
            if n == 0 || !line.ends_with('\n') {
                return Ok(at);
            }
            at += n as u64;
            self.line(&line);
        }
    }

    fn line(&mut self, line: &str) {
        match replay(line) {
            Ok(Some(Line::Event(r))) => {
                let r = *r;
                let sessions = &mut self.sessions;
                let n = *self.index.entry(r.session.clone()).or_insert_with(|| {
                    sessions.push(Session {
                        root: r.event.meta.root_pid,
                        id: r.session.clone(),
                        store: EventStore::replay(),
                        peers: HashMap::new(),
                    });
                    sessions.len() - 1
                });
                let session = &mut self.sessions[n];
                if let Some((ip, known)) = r.peer {
                    session.peers.insert(ip, known);
                }
                session.store.push(Arc::new(r.event));
            }
            Ok(Some(Line::Lost(n))) => self.lost += n,
            Ok(None) => {}
            Err(_) => self.unreadable += 1,
        }
    }

    /// Newest first, leaving out those still live (`live`: their ids).
    pub fn listed(&self, live: &HashSet<String>) -> Vec<proto::PastSession> {
        self.sessions
            .iter()
            .rev()
            .filter(|s| !live.contains(&s.id))
            .filter_map(|s| {
                let summary = s.store.agents(0).agents.into_iter().next()?;
                Some(proto::PastSession {
                    id: s.id.clone(),
                    summary: Some(summary),
                })
            })
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.index.get(id).map(|&n| &self.sessions[n])
    }

    /// The newest `keep`: a log of 256 MB holds more than a page shows.
    fn trim(&mut self, keep: usize) {
        if self.sessions.len() <= keep {
            return;
        }
        self.sessions.drain(..self.sessions.len() - keep);
        self.index = self
            .sessions
            .iter()
            .enumerate()
            .map(|(n, s)| (s.id.clone(), n))
            .collect();
    }
}

fn rotated(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_owned();
    rotated.push(".1");
    PathBuf::from(rotated)
}

/// The log as the daemon serves it: read once, then only what was
/// appended since; from the start again when the export rotates it.
pub struct Tail {
    path: PathBuf,
    keep: usize,
    log: Log,
    inode: u64,
    offset: u64,
}

impl Tail {
    pub fn new(path: PathBuf, keep: usize) -> Self {
        Self {
            path,
            keep,
            log: Log::default(),
            inode: 0,
            offset: 0,
        }
    }

    pub fn refresh(&mut self) -> Result<&mut Log> {
        let meta = match fs::metadata(&self.path) {
            Ok(meta) => meta,
            // Nothing exported yet.
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(&mut self.log),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        if meta.ino() != self.inode || meta.len() < self.offset {
            self.log = Log::default();
            self.log.read_file(&rotated(&self.path), 0, true)?;
            self.inode = meta.ino();
            self.offset = 0;
        }
        self.offset = self.log.read_file(&self.path, self.offset, false)?;
        self.log.trim(self.keep);
        Ok(&mut self.log)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::EnrichedEvent;
    use crate::ocsf::{record, Host};
    use crate::store::{Event, EventMeta, Payload};
    use std::io::Write;

    fn exec(root: u32, at_s: u64, comm: &str) -> String {
        let event = Event {
            meta: EventMeta {
                seq: 1,
                pid: root,
                root_pid: root,
                uid: 1000,
                comm: comm.into(),
                timestamp_ns: at_s * 1_000_000_000,
                ret: 0,
                container: None,
            },
            payload: Payload::Execve {
                filename: format!("/usr/bin/{comm}"),
                cmd_line: None,
            },
        };
        let host = Host {
            hostname: "h".into(),
            boot_id: "b".into(),
        };
        serde_json::to_string(&record(&event, &EnrichedEvent::default(), &host)).unwrap()
    }

    #[test]
    fn past_sessions_newest_first_and_not_the_live_ones() {
        let mut log = Log::default();
        for line in [
            exec(1, 100, "claude"),
            exec(2, 200, "codex"),
            exec(3, 300, "gemini"),
        ] {
            log.line(&line);
        }
        let live: HashSet<String> = ["b:2".to_string()].into();
        let listed: Vec<(String, String)> = log
            .listed(&live)
            .into_iter()
            .map(|p| (p.id, p.summary.unwrap().root_comm))
            .collect();
        assert_eq!(
            listed,
            [
                ("b:3".into(), "gemini".into()),
                ("b:1".into(), "claude".into())
            ]
        );
        assert_eq!(log.get("b:1").map(|s| s.root), Some(1));
    }

    #[test]
    fn appended_lines_are_read_once_and_a_partial_one_waits() {
        let dir = std::env::temp_dir().join(format!("k11-past-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ocsf.jsonl");
        let mut f = File::create(&path).unwrap();
        writeln!(f, "not a record").unwrap();
        let mut tail = Tail::new(path.clone(), 10);
        assert_eq!(tail.refresh().unwrap().unreadable, 1);
        write!(f, "half").unwrap();
        assert_eq!(
            tail.refresh().unwrap().unreadable,
            1,
            "a partial line waits"
        );
        writeln!(f, " a line").unwrap();
        assert_eq!(
            tail.refresh().unwrap().unreadable,
            2,
            "then is read whole, once"
        );
        // Rotated: a new file under the same name, the old one at .1.
        fs::rename(&path, rotated(&path)).unwrap();
        let mut f = File::create(&path).unwrap();
        writeln!(f, "x").unwrap();
        assert_eq!(
            tail.refresh().unwrap().unreadable,
            3,
            "both files, from the start"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
