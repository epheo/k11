# k11 roadmap

k11 is the black-box recorder for AI coding agents. The moat is kernel-side
attribution: every file, network, and process event stitched to the agent tree
that caused it. Every change below either makes that promise true, makes it
demoable, or gets out of its way.

Status legend: `[ ]` pending, `[x]` done, `[~]` accepted as-is (documented,
no action planned).

---

## Architecture review (2026-09-02)

Full pass over probe, daemon, proto and dashboard with two goals: no
shortcuts in the record, and low resource use. Everything below landed in
one batch.

### Record correctness

- [x] **Clock.** Probe stamps CLOCK_BOOTTIME (`bpf_ktime_get_boot_ns`); the
  daemon offsets with `clock_gettime(CLOCK_BOOTTIME)`. Timestamps no longer
  drift by the accumulated suspend time.
- [x] **Thread exits.** Only the thread-group leader's exit ends a process;
  worker-thread exits no longer mark node and Go agents as exited (and no
  longer make live trees eligible for eviction).
- [x] **Lossless export.** The OCSF writer is fed by a bounded channel from
  the decode loop with backpressure; the broadcast (lossy by design) serves
  UI streams only. Lines flush on a 100 ms timer and at shutdown.
- [x] **One record per open.** The LSM hook records successful opens with the
  kernel-resolved path and removes the syscall's pending record, so denied
  opens are no longer recorded twice and relative paths and dirfds are
  honoured. Opens that fail before reaching a file are recorded from the
  syscall exit with the requested path, resolved against the right dirfd.
- [x] **Audit vs deny.** A rule match in audit mode is recorded as
  `Audited` (allowed, OCSF disposition Detected), not as a denial.
- [x] **No invented values.** A failed tracepoint or user-memory read drops
  the event and counts it (`read_failed`) instead of writing EPERM or zero.
  Non-UTF-8 paths are kept lossily instead of replaced.
- [x] **Every syscall variant.** `open`, `creat`, `openat2`, `unlink`,
  `rename`, `renameat`, `chmod`, `fchmodat2`, `chown`, `lchown`, `symlink`
  are hooked next to the `*at` forms glibc does not use on x86_64. Missing
  variants are skipped per kernel, not fatal.

### Probe

- [x] One `PENDING` map (tagged union value) instead of one per syscall:
  ~30 MB of preallocated kernel memory down to ~5 MB. Records are built in a
  per-CPU scratch slot, which also removed the stack-driven 192-byte path
  truncation for rename and symlink (both paths are now 256 bytes).
- [x] One `k11_syscall_exit` program attached to every traced `sys_exit_*`;
  the syscall result and record length live in the header.
- [x] Variable-length ring records: a record is a prefix of its struct,
  trimmed after the last string.
- [x] One lineage lookup per event (`resolve_root`), no double
  `bpf_get_current_pid_tgid`.
- [x] `bpf_d_path` skipped when no deny rules are loaded.
- [x] Ring buffer size from config (`probe.ring_buffer_kb`, default 1 MB).
- [x] Per-CPU `STATS` counters (`ring_full`, `pending_full`, `lineage_full`,
  `read_failed`) replace the single drop counter; the daemon logs deltas.
- [x] LSM hook is non-sleepable (5.7+ instead of 5.11+); no `.text`
  subprogram calls remain in any program.

### Daemon

- [x] Syscall tracepoints are read by argument slot (fixed layout on 64-bit
  kernels) and the layout is verified against tracefs at startup; only the
  sched tracepoints keep runtime offset discovery. The 30-field offset
  struct and its three hand-synced copies are gone; one table in
  `k11-common` drives the probe's argument indices and the daemon's attach.
- [x] `probe.rs` owns load, verify, attach and the capability report;
  `k11d --check` prints it and exits. BTF or BPF LSM absence is a reported
  degradation, not a startup failure.
- [x] `PolicyMaps` is the sole writer of the CONFIG map.
- [x] `Enricher` bundles DNS, GeoIP, ASN and passwd; reverse DNS is capped at
  8 concurrent lookups.
- [x] Store: `Arc<Event>` shared between store and subscribers; comms
  interned; errno counters keyed by number; one-lookup aggregate updates;
  peers keyed by address then port; incremental running count; per-tree
  version for cheap unchanged-detail polls; global raw-event budget.
- [x] `Access` composition replaces three copies of the same six fields
  (store, proto, dashboard).
- [x] OCSF records are typed structs serialized directly to the writer.
- [x] clap CLI (`--config`, `--listen`, `--open`, `--check`); `Config`
  derives Default; embedded assets served without a copy.
- [x] Host workspace builds on stable; nightly is scoped to `k11-probe`.
- [x] CI: fmt, probe build, dashboard build, clippy `-D warnings`, tests.

### Dashboard

- [x] Sensitive and external classification comes from the server on every
  wire event; the client copies are deleted, along with the GetConfig RPC.
- [x] Events are parsed at arrival and pushed in place (no per-event array
  copy, no re-parse of the whole log per event); rows keyed by stable id.
- [x] `GetAgentDetail` carries a version; unchanged trees return no payload.

### Follow-up (2026-09-02, same day)

- [x] **Nested opens.** One open syscall has one user-visible file, so the
  first `file_open` inside a traced open records and any further one
  (overlayfs backing file, copy-up) is suppressed unless a deny rule
  matches. `execve`/`execveat` park a marker so the kernel's own opens of
  the image are treated the same way. No kernel constant is involved: the
  `FMODE_*` bits that mark backing files were renumbered around 6.11.
- [~] **Relative paths in the kernel.** Attempted: at syscall exit the probe
  walked the cwd/dirfd dentry chain to rewrite the record with the absolute
  path. It passed the verifier but, once loaded, silently suppressed every
  event that flowed through it (all metadata syscalls and failed opens
  vanished while connect and LSM-recorded opens survived); the runtime cause
  could not be isolated remotely. Reverted to the userspace `/proc` resolver,
  which is dfd-aware and correct, at the cost of racing the process. The
  probe still carries the directory fd on every path record so the resolver
  has what it needs. Revisit with a local BPF debugger.
- [x] **Reproducible dashboard builds.** `package-lock.json` committed; CI
  uses `npm ci`.

### Follow-up (2026-09-02, live-run findings)

- [x] **Lineage-map leak and pid reuse.** `sched_process_fork` fires for
  thread creation, so the probe inserted every new thread's tid into
  `WATCHED_PIDS`, but `resolve_root` only queries by tgid and the exit
  handler removed only leaders. Dead thread tids accumulated until the map
  filled and new process forks could no longer be attributed (a watch-all
  run showed tens of thousands of single-process trees). It was also a
  correctness bug: a stale thread tid could collide with a later process's
  reused tgid and misattribute it. Fix: every task removes its own entry
  (by tid) on exit, bounding the map to live tasks and closing the reuse
  hole.
- [x] **Watch-all map sizing.** `WATCHED_PIDS` must hold every live task in
  watch-all mode; the static 10240 default is a single-tree size. The
  daemon now sizes it from `probe.max_tracked_pids` (default 131072) when
  watch.binaries is empty, and `lineage_full` in the probe stats warns if
  it is still exceeded.
- [x] **Smoke test reads attribution, not a guess.** The old test took the
  first ancestor the daemon happened to list as a root; on a busy watch-all
  desktop that was the wrong tree. It now derives the tree from the
  daemon's own attribution of the test process and asserts every spawned
  child lands in the same tree, printing the ancestor chain either way.

### Known limitations (accepted, documented)

- Watch-all on a whole desktop is inherently heavy: processes that predate
  k11d are each their own root (not reconstructed from /proc), so trees do
  not merge under a common ancestor. Watch specific binaries for a clean
  per-agent view.
- Opens submitted through io_uring have no syscall record to anchor the
  nested-open suppression, so on overlayfs they can still yield two
  records.
- Without BTF, relative paths are resolved against `/proc/<pid>/cwd` or
  `/proc/<pid>/fd/<dfd>` in userspace, which races the process; a failed
  read leaves the path as requested.
- Without BPF LSM every open is recorded as requested (no symlink
  resolution), and deny rules cannot apply.
- A thread-group leader that exits before its threads (`pthread_exit` in
  main) ends the process record early.

---

## Audit findings (2026-07-17)

Full-code audit of probe, daemon, proto, and frontend (~9.4k lines).

### Correctness

- [x] **C1 Events not attributable to agents.** `EventMeta` on every event,
  meta on the proto `Event` wrapper, OCSF `metadata.correlation_uid`.
- [x] **C2 Unbounded memory.** Incremental aggregates, capped event deque
  with drop accounting, capped aggregate maps, TTL eviction of exited trees.
- [x] **C3 Silent forensic loss.** Ring drops counted and logged; exporter
  flushes (now on a timer, lossless channel: see above).
- [x] **C4 Watch-all mode broke both headline features.** Lineage propagates
  in watch-all; deny rules + watch-all is a startup error.
- [x] **C5 Exposed control plane.** Default `127.0.0.1:1100`; same-origin
  serving removed the CORS layer.
- [x] **C6 Policy validation footguns.** Paths must be absolute, non-empty
  after normalization, and fit the BPF map slot.
- [x] **C7 Hygiene batch.** DNS retry, RFC1918 classification, listen vs
  bind counting, exited count, typecheck in the web build, systemd unit.

### Design debt

- [x] **D1 Probe repetition.** Enter handlers are macros; one exit program.
- [x] **D2 `resolve_path` on the decode path.** Successful opens come from
  the LSM hook with the kernel's path; only failures still read /proc.
- [~] **D3 Hand-rolled BTF parser and RFC3339 formatter.** Both tested, both
  serve the zero-dependency goal. Keep.
- [x] **D4 Event clones per subscriber.** `Arc<Event>` everywhere.

### Dropped

- [x] **X1** MaxMind GeoLite2 databases stay out of git (license).
- [x] **X2** Enforcement surface frozen at `file_open` deny.
- [x] **X3** `export.format` knob removed until a second format exists.
- [x] **X4** Build artifacts untracked.
- [x] **X5** LLM classification tier out of scope.

---

## M1: Trustworthy recorder

Goal: every promise the README makes about recording is mechanically true.

- [x] Attribution refactor (C1)
- [x] Bounded store (C2)
- [x] Durable export + drop visibility (C3)
- [x] Safe defaults + config validation (C4, C5, C6)
- [x] Hygiene batch (C7)
- [x] Lossless export, correct clock, one record per open (2026-09-02)
- [ ] OCSF heartbeat record carrying the probe counters (log-only today)
- [ ] Size-based rotation for the OCSF export file
- [x] CI: fmt + clippy + cargo test + BPF build + web build
- [x] Runtime smoke test under root (`k11-web/smoke.mts` against a live
  k11d). Re-run after the 2026-09-02 probe rewrite: `k11d --check`, then the
  smoke test, on a host with BPF LSM and on one without.

## M2: One-command MVP (tag v0.1)

Goal: start k11 and you are monitoring. Nothing else to install or configure.

- [x] Embed `k11-web/dist` in the k11d binary; UI and gRPC-web same-origin
- [x] `--open`: launches the UI in the sudo-invoking user's session
- [x] `--check`: kernel capability report
- [ ] `k11 run -- <cmd>`: spawn a command, register its PID as a tree root
  over a local RPC, watch exactly that session; no comm-name config
- [ ] Session summary on agent exit: files touched, sensitive hits, external
  destinations with ASN, denials; printed and/or written next to the OCSF log
- [x] README quickstart rewritten around the single binary

## Platform strategy

The probe needs a Linux kernel; the UI must reach the user wherever they
sit. That split is the whole strategy: **k11d always runs where the Linux
kernel is, and the UI is served by the daemon over localhost**, because a
browser is the one renderer present on every host.

- **Native Linux**: single binary, `--open`. First-class target. Any 64-bit
  kernel from 5.8; canonical paths and enforcement from 5.10 with BTF and
  BPF LSM.
- **Windows**: k11d runs inside WSL2 (real Linux kernel, eBPF works).
  WSL2 forwards localhost, so the Windows browser reaches :1100 with zero
  configuration. Nothing to package for Windows.
- **macOS**: no eBPF in Darwin. Agents running in containers execute inside
  Docker Desktop's Linux VM; k11d runs there as a privileged container with
  the port published, and the Mac browser connects. Genuinely useful once
  M3 container attribution lands. Native macOS monitoring (Endpoint
  Security framework) is a different product; out of scope.
- **Desktop shell**: rejected Electron. If a first-class app is wanted
  later, wrap the same `k11-web` dist in Tauri pointing at a configurable
  daemon endpoint; the UI stays a thin gRPC-web client either way.

## M3: Added value (post-feedback; pick by pull, not by plan)

- [ ] `k11 report <jsonl>`: render a past session from the OCSF log
  (doubles as the SIEM integration demo)
- [ ] Risk notifications: desktop notify / webhook on sensitive-write,
  ptrace, first contact with a new ASN
- [ ] SQLite persistence + retention for cross-session history
- [ ] Container/cgroup attribution (and de-duplication of overlayfs opens)
- [ ] Correlation id robust across daemon restarts (root_pid + boot id)

---

## Non-goals

- **No sandbox ambitions.** Enforcement stays a minimal opt-in guardrail
  (`file_open` path deny). Landlock, bubblewrap, and containers own real
  containment.
- **No auth/TLS on the API.** The API binds localhost; expose it with a
  reverse proxy if you need remote access.
- **No new syscalls** until a user shows a gap the current set cannot answer.
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
- aya has no CO-RE path for `bpf_d_path` yet; the `.rodata` offset globals
  (from BTF at startup) stay until aya-rs/aya#432 lands.

Recording:

- Ring buffer overload drops events; drops are counted and logged, and the
  buffer size is a config knob. The record is still lossy under extreme
  burst.
- comm-name discovery matches the kernel's 15-char comm; `k11 run` (M2) is
  the precise alternative.
- In watch-all mode, lineage roots at the first ancestor seen after k11d
  starts; pre-existing process trees are not reconstructed from /proc.
- 64-bit kernels only (syscall argument slots are 8 bytes).
