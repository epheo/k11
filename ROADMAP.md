# k11 roadmap

k11 is the black-box recorder for AI coding agents. The moat is kernel-side
attribution: every file, network, and process event stitched to the agent tree
that caused it. Every change below either makes that promise true, makes it
demoable, or gets out of its way.

Status legend: `[ ]` pending, `[x]` done, `[~]` accepted as-is (documented,
no action planned).

---

## Audit findings (2026-07-17)

Full-code audit of probe, daemon, proto, and frontend (~9.4k lines).

### Correctness

- [x] **C1 Events not attributable to agents.** `store::Event` carried
  `root_pid` only on `Execve`; `event_matches_pid` (grpc.rs) matched 2 of 14
  event types, so per-agent streaming dropped nearly everything, and OCSF
  records had no agent context. Fix: `EventMeta { pid, root_pid, uid, comm,
  timestamp_ns }` on every event, mirroring the BPF `EventHeader`; proto
  carries meta on the `Event` wrapper; OCSF gets `metadata.correlation_uid`.
- [x] **C2 Unbounded memory.** Per-agent event `VecDeque` never evicted;
  exited trees never removed; `agent_detail()` rescanned all events per call
  under the mutex shared with the decode loop. Fix: incremental aggregates
  maintained in `push()`, capped event deque with drop accounting, capped
  aggregate maps, TTL eviction of exited trees.
- [x] **C3 Silent forensic loss.** 256KB ring buffer dropped events with no
  counter; OCSF exporter buffered without flushing (tail lost on crash).
  Fix: `DROPS` per-CPU counter in the probe polled and logged by the daemon;
  exporter flushes per line and logs write-failure transitions.
- [x] **C4 Watch-all mode broke both headline features.** Fork lineage was
  only propagated for watched parents, so watch-all produced one fractured
  tree per process; the LSM hook checked only `is_watched`, so deny rules
  with `enforce = true` were a silent no-op. Fix: lineage propagates in
  watch-all; deny rules + watch-all is now a startup error instead of a
  silent no-op; exit events resolve root through the lineage map first.
- [x] **C5 Exposed control plane.** gRPC defaulted to `0.0.0.0:1100` with
  permissive CORS on an unauthenticated API (any webpage could call
  `SetEnforce`). Fix: default `127.0.0.1:1100`. Same-origin serving (M2)
  will remove the permissive CORS layer.
- [x] **C6 Policy validation footguns.** Deny path `/` normalized to the
  empty prefix and matched every file; >127-byte paths silently truncated
  into broader rules; relative paths accepted. Fix: paths must be absolute,
  non-empty after normalization, and fit the BPF map slot.
- [x] **C7 Hygiene batch.** DNS lookup failures left cache entries in-flight
  forever (never retried); `is_external_addr` treated RFC1918 as external
  (both Rust and frontend); `Listen` inflated `bind_count` and failed
  `listen()` set `has_listener`; `exited_count` counted pids with no process
  entry; `rawlog.ts` read a `denied` field absent from execve/connect
  (no typecheck in the build); `export.format` knob was never read; systemd
  unit declared `Type=notify` without sd_notify and set unused
  `K11_LOG_LEVEL`/`RuntimeDirectory`; stale event-type list in the UI
  empty state.

### Design debt

- [x] **D1 Probe repetition.** 9 of 10 sys_exit handlers were identical
  modulo names; now one macro. Enter handlers stay explicit (they differ
  meaningfully). `connect_exit` stays hand-written (dual pending maps).
- [~] **D2 `resolve_path` does synchronous /proc reads on the decode path.**
  Two syscalls per relative-path event, and the cwd may have changed since
  the syscall (inherent race). Acceptable at current rates; revisit if
  watch-all profiling shows it hot.
- [~] **D3 Hand-rolled BTF parser and RFC3339 formatter.** Both tested, both
  serve the zero-dependency goal. aya does not expose struct member offsets
  publicly. Keep.
- [~] **D4 store::Event clones once per broadcast subscriber.** Fine at
  current event rates; consider `Arc<Event>` in the channel if profiling
  says otherwise.

### Dropped

- [x] **X1 MaxMind GeoLite2 databases confirmed out of git.** The 84MB of
  mmdb files exist only on disk; `.gitignore` covers them and history is
  clean (GeoLite2 redistribution requires a signed agreement, so this must
  stay true). README documents bring-your-own.
- [x] **X2 Enforcement expansion frozen.** `file_open` deny is the entire
  enforcement surface. Known gaps below are documented limitations, not a
  work queue.
- [x] **X3 `export.format` config knob** removed until a second format
  exists.
- [x] **X4 Build artifacts confirmed untracked** (`k11-web/dist`, local
  `config/k11.toml`) — gitignored, never committed.
- [x] **X5 LLM classification tier** is out of scope (see non-goals).

---

## M1 — Trustworthy recorder

Goal: every promise the README makes about recording is mechanically true.

- [x] Attribution refactor (C1)
- [x] Bounded store (C2)
- [x] Durable export + drop visibility (C3)
- [x] Safe defaults + config validation (C4, C5, C6)
- [x] Hygiene batch (C7)
- [ ] OCSF heartbeat record carrying drop/health counters (log-only today)
- [ ] Size-based rotation for the OCSF export file
- [ ] CI: fmt + clippy + cargo test + BPF build + web build (svelte-check)
- [x] Runtime smoke test under root (`k11-web/smoke.mts` against a live
  k11d: probe loads, verifier passes, filtered stream carries all event
  kinds with meta, aggregates and external-addr classification verified
  live on 2026-07-17). The OCSF export path is still unit-test-only; fold
  a live assertion into the heartbeat work.

## M2 — One-command MVP (tag v0.1)

Goal: start k11 and you are monitoring. Nothing else to install or configure.

- [ ] Embed `k11-web/dist` in the k11d binary (rust-embed); serve UI and
  gRPC-web same-origin on :1100; drop the permissive CORS layer (closes the
  browser-origin control-plane hole for good)
- [ ] `--open`: auto-launch the UI (xdg-open) when started from a terminal,
  so `sudo k11d --open` feels like starting an app without shipping one
- [ ] `k11 run -- <cmd>`: spawn a command, register its PID as a tree root
  over a local RPC, watch exactly that session; no comm-name config
- [ ] Session summary on agent exit: files touched, sensitive hits, external
  destinations with ASN, denials; printed and/or written next to the OCSF log
- [ ] README quickstart rewritten around the single binary

## Platform strategy

The probe needs a Linux kernel; the UI must reach the user wherever they
sit. That split is the whole strategy: **k11d always runs where the Linux
kernel is, and the UI is served by the daemon over localhost**, because a
browser is the one renderer present on every host.

- **Native Linux**: single binary, `--open`. First-class target.
- **Windows**: k11d runs inside WSL2 (real Linux kernel, eBPF works).
  WSL2 forwards localhost, so the Windows browser reaches :1100 with zero
  configuration. Nothing to package for Windows.
- **macOS**: no eBPF in Darwin. Agents running in containers execute inside
  Docker Desktop's Linux VM; k11d runs there as a privileged container with
  the port published, and the Mac browser connects. Genuinely useful once
  M3 container attribution lands. Native macOS monitoring (Endpoint
  Security framework) is a different product; out of scope.
- **Desktop shell**: rejected Electron — it ships a Chromium per platform,
  does not remove the privileged daemon (BPF needs root; a GUI app cannot
  absorb it), and bakes in host assumptions that the WSL2/Docker layouts
  break. If a first-class app is wanted later, wrap the same `k11-web` dist
  in Tauri (system webview, Rust, megabytes not hundreds) pointing at a
  configurable daemon endpoint; the UI stays a thin gRPC-web client either
  way, so nothing built now is thrown away.

## M3 — Added value (post-feedback; pick by pull, not by plan)

- [ ] `k11 report <jsonl>`: render a past session from the OCSF log
  (doubles as the SIEM integration demo)
- [ ] Risk notifications: desktop notify / webhook on sensitive-write,
  ptrace, first contact with a new ASN
- [ ] SQLite persistence + retention for cross-session history
- [ ] Container/cgroup attribution
- [ ] Correlation id robust across daemon restarts (root_pid + boot id)

---

## Non-goals

- **No sandbox ambitions.** Enforcement stays a minimal opt-in guardrail
  (`file_open` path deny). Landlock, bubblewrap, and containers own real
  containment.
- **No auth/TLS on the API.** The API binds localhost; expose it with a
  reverse proxy if you need remote access.
- **No new syscalls** until a user shows a gap the current 14 cannot answer.
- **No database before M3.** OCSF JSONL is the durable record.
- **No LLM classification tier.** The recorder must stand on its own first.

## Known limitations (accepted, documented)

Enforcement (frozen surface, see X2):

- Metadata operations (`chmod`, `chown`, `rename`, `unlink`) go through
  `inode_*` LSM hooks, not `file_open`; a watched process can modify or
  delete files it cannot open. Recorded, not denied.
- `stat()` does not trigger `file_open`; existence of denied paths can be
  probed.
- Runtime policy changes are not persisted across daemon restarts; only
  `k11.toml` rules survive.
- Deny rules block all of open's modes; no read-only/write-only granularity.
- aya has no CO-RE/kfunc path for `bpf_d_path` yet; the `.rodata` offset
  global stays until aya-rs/aya#432 lands.

Recording:

- Ring buffer overload drops events; drops are now counted and logged, but
  the record is still lossy under extreme burst. Sizing is tunable only by
  rebuild.
- comm-name discovery matches the kernel's 15-char comm; `k11 run` (M2) is
  the precise alternative.
- In watch-all mode, lineage roots at the first ancestor seen after k11d
  starts; pre-existing process trees are not reconstructed from /proc.
