# k11 roadmap

k11 is the black-box recorder for AI coding agents. The moat is kernel-side
attribution: every file, network, and process event stitched to the agent tree
that caused it. Every change below either makes that promise true, makes it
demoable, or gets out of its way.

Status legend: `[ ]` pending, `[x]` done, `[~]` accepted as-is (documented,
no action planned).

---

## Audit (2026-11-02)

Full pass over probe, daemon, proto, dashboard, build and packaging.
At audit time build, clippy and the 74 tests were green and nothing had run on a live kernel; fixes below were checked with `cargo xtask vm`.

### Before anything else

- [x] **Commit the 2026-09-02 rewrite.**
  - 48 files, +5.8k/-4.3k lines, uncommitted for two months.
  - This repo already lost files once (see the `recover:` commits).

### Record correctness

- [x] **Threads are recorded as child processes that never exit.**
  - `sched_process_fork` fires per thread; the store added a running child per thread.
  - Thread exits are gated out, so these never exited: node/Go trees never reached zero running and were never evicted.
  - Fixed: forks come from `task:task_newtask`; `CLONE_THREAD` gets no lineage entry and no event.
  - The per-tid lineage cleanup in `k11_exit` is gone with it.
  - Lifecycle offsets are one table, `TRACEPOINT_FIELDS`, like `KERNEL_FIELDS`.
  - The smoke test asserts no thread id is listed as a process.
- [x] **Process exit by `group_dead`.**
  - Recent kernels pass `group_dead` to `sched_process_exit`; tracefs shows the field.
  - Used when present (optional `TRACEPOINT_FIELDS` entry); `tid == tgid` is the fallback. `--check` reports which.
  - Fixes leader-exits-first and exec from a non-leader thread, which dropped the process from lineage while it lived on.
- [x] **LSM scratch slot is shared under preemption.**
  - BPF LSM programs get no per-CPU recursion guard (`bpf_prog_check_recur` is false for `BPF_PROG_TYPE_LSM`).
  - They run with migration disabled, not preemption: two tasks on one CPU can interleave in `SCRATCH[SLOT_LSM]`.
  - Effect: corrupt records, and a deny decision taken on the other task's path (enforcement bypass).
  - The comment at `k11-probe/src/main.rs:46` stated the opposite.
  - Fixed: the hook writes only its thread's parked record or a ring reservation; SCRATCH serves tracepoints only.
- [x] **LSM-recorded opens always carry `ret = 0`.**
  - The record ships from inside `file_open`, before the syscall returns.
  - Never the fd; a failure after `file_open` (FUSE `open`, `O_TRUNC`) reads as success.
  - Fix for this and the race: the hook writes the canonical path into the thread's own parked `PENDING` record; `sys_exit` ships it with the real result.
  - Opens with no parked record (io_uring) are submitted from the hook via ring reserve.
  - `d_path` fills from the buffer end: on failure the requested path is read again from user memory at sys_exit.
  - Done: `Pending { event, user, flags }` is the per-thread record; the hook rewrites it, sys_exit ships it.
- [x] **Failed execs vanish.** The exec marker has `len == 0`, so `sys_exit` drops it whatever the result.
- [x] **`PENDING` leaked on exec from a non-leader thread** (its pid_tgid changes).
  - `sched_process_exec` now ends the parked record by `old_pid`; no LRU needed.

### Enforcement

- [x] **Deny prefixes are not path-component aware.**
  - `normalize_deny_path` strips the trailing `/`; the matcher compares raw bytes.
  - `/home/u/.ssh/` also denies `/home/u/.ssh-backup`.
  - Fix: after a full prefix match require `path[j]` to be NUL or `/`.
- [x] **An empty deny slot matches every path.**
  - `sync_file_paths` rewrites slots before the count.
  - Removing a rule leaves a window where the count covers a zeroed slot: every open by a watched tree is denied or audited.
  - Fixed: the matcher skips empty slots, and rules are double-buffered: the daemon writes the idle set and publishes it in one store, so no set is written while live.
- [~] **`d_path` failure skips the deny rules** (canonical path over 255 bytes): fail-open, documented. The record keeps the requested path.
- [x] **`UpdateDenyRules` applies partially** when one path in the batch is invalid. Now all or nothing.
- [x] **Watch-all messages are wrong.**
  - README, config errors and `policy.rs` say "no processes are watched"; watch-all watches every process.
  - The real reason to refuse rules there: host-wide enforcement.

### Security

- [x] **DNS rebinding.**
  - The API is unauthenticated, can toggle enforcement, and accepts any `Host`.
  - Any web page can rebind a name to 127.0.0.1, read the trail and disable enforcement.
  - Fixed: bound to loopback, only loopback `Host` names are served (403 otherwise).
- [x] **Any local user can disable enforcement** or remove rules over the TCP port.
  - Worse: the recorded agent itself could, with one HTTP request.
  - Fixed: policy changes need a per-run token, kept in root-only `/run/k11/dashboard` and handed to the browser by `sudo k11 dashboard`; reads stay open.
- [x] **Dashboard loads fonts from `fonts.bunny.net`** (`k11-web/index.html:8`).
  - A phone-home from a local-only security tool; fails offline.
  - Bundle the font or use the system monospace.

### Operations

- [x] **SIGTERM is not handled.**
  - Only Ctrl-C reaches the shutdown path; `systemctl stop` loses the export buffer and queue.
  - README promises a flush at shutdown.
- [x] **`RLIMIT_MEMLOCK` is never raised.**
  - Kernels 5.8 to 5.10 charge maps to memlock; `PENDING` alone is ~5.9 MB.
  - Raised at startup now; the unit item below adds `LimitMEMLOCK=infinity`.
- [x] **systemd unit (`dist/k11d.service`):**
  - `CapabilityBoundingSet` drops `CAP_SYS_PTRACE`: `/proc/<pid>/cwd` readlinks fail for other users, relative paths stay relative.
  - `ProtectSystem=strict` with no writable path: file export cannot open. Add `LogsDirectory=k11`.
  - `ExecStart=/usr/bin/k11d`: nothing installs there.
  - Fixed: `CAP_SYS_PTRACE`, `LimitMEMLOCK=infinity`, `LogsDirectory=k11`, `RuntimeDirectory=k11`, `/usr/local/bin/k11d`.
- [x] **Watch-all log spam:** every pre-existing process warns "possible orphan" on its first event.
- [x] **Probe debug counters left in** (`enter_stash`, `exit_orphan`, `exit_submit`).
  - Leftovers from the reverted in-kernel resolver.
  - `exit_orphan` costs a map update on every traced syscall exit of every unwatched process.
  - Remove them; `.take(4)` in `main.rs` goes with them.

### Classification

- [x] **Non-blocking connects read as failures.**
  - Node, Go, tokio and asyncio connect non-blocking; the exit result is `-EINPROGRESS`.
  - `is_error` marks it failed: OCSF status Failure, risk +1, "failed [EINPROGRESS]" in every view.
  - Fix: EINPROGRESS is success; ECONNREFUSED maps to activity Refuse.
- [x] **Sensitive paths are substring matches.**
  - `/root/` matches `/home/u/proj/root/x`; `.ssh/` matches `x.ssh/`; `~/.ssh` itself is missed.
  - Fix: prefix match for absolute entries, component match for dot-dirs.
- [x] **The list is noisy and misses what agents leak.**
  - Reading `/etc/passwd` is routine (every username lookup), so most trees are flagged.
  - Missing: `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `.config/gh`, `.config/gcloud`, `.azure`, `.env`, agent credential files.
- [x] **v4-mapped IPv6 (`::ffff:10.0.0.1`) is external** and skips the loopback check before reverse DNS.
  - Fix: `parse_ip` returns `ip.to_canonical()`: classification, DNS and GeoIP at once.
- [x] CGNAT (100.64/10, Tailscale), multicast and broadcast count as external. Low.

### OCSF export

Checked against schema.ocsf.io 1.1.0.

- [x] **Logs and export share stdout.** `tracing_subscriber::fmt()` writes to stdout; `output = "-"` too. Log lines land inside records.
  - Fix: logs to stderr.
- [x] **A failed write corrupts the next line:** the fragment stays buffered and the next record is glued on.
  - Fix: serialize into a reused buffer, one `write_all` per line. Count dropped writes; nothing does today.
- [x] **Export file is created 0644**; it holds every path the agent touched. Use 0600.
- [x] **Sync writes on a tokio worker:** a stalled pipe or disk blocks it. Dedicated thread with `blocking_recv`.
- [x] **IPv6 addresses keep their brackets** in `dst_endpoint.ip` (type `ip_t`): invalid. Carry an `IpAddr`; bracket only in messages.
- [x] **Wrong ids:** observable 20 is Endpoint (Process Name is 9); file type 5 is Local Socket (Symbolic Link is 7).
- [x] **Missing required fields:** `file.type_id` (0 when unknown), `device.type_id`, `dst_endpoint` on Listen.
- [x] **Fields 1.1.0 does not define:**
  - `autonomous_system`, `file.mode`, `file.target`; `src_endpoint` on 1001 and 1007.
  - `enrichment.value` must be a string with `data`: the risk score belongs in `unmapped`; enrichments should carry GeoIP/ASN.
- [x] **Undeclared profiles:** `disposition_id` (security_control, which then requires `action_id`), `time_dt` (datetime), `device`/`actor` (host).
- [x] **Smaller:**
  - execve observable named `file.path`, but the file is at `process.file.path`.
  - `cmd_line` holds the executable path, not argv. Drop until argv is captured.
  - unix socket path sits in `domain`.
  - unlinkat with `AT_REMOVEDIR` should be a Folder.
- [x] **Simplify:**
  - `category_uid = class_uid / 1000`: the three `record()` wrappers go.
  - 14 `let Payload::X .. else { unreachable!() }` re-match what `ocsf::record` already matched: destructure once.
  - A `Record::file(path)` helper sets file and observable together (would have prevented the execve bug).
  - `WRITE_FLAGS` (store) duplicates `MODIFY_FLAGS | O_CREAT` (ocsf): one constant in `classify.rs`.
  - Tests: default the 6-arg `ev()`, one table for class/activity, one required-fields conformance test.
- [~] **For `k11 report` and the session summary:**
  - [x] `correlation_uid` is now `<boot id>:<root pid>`: stable across daemon restarts.
  - [x] Typed `unmapped` fields (`root_pid`, `risk_score`, mode, gid, backlog, ptrace request, symlink target) and `access_mask` for open flags.
  - [x] `metadata.sequence` from the decoder's per-event `seq`.
  - [ ] Record types are serialize-only; `Cow` plus `Deserialize` gives one set of types both ways. Do it with `k11 report`.
  - [x] Loss markers: when probe counters grow, the export gets a Base Event ("k11 lost N records") with the deltas.

### DNS and GeoIP

- [x] **DNS cache has no cap**: with 10k fresh entries it grows unbounded, and every new IP runs an O(n) `retain` under the mutex.
- [x] A failed refresh overwrites a known hostname with None.
- [x] `tokio::spawn` around `spawn_blocking` is redundant.
- [x] Bind addresses are enriched and the result discarded.

### Found while fixing

- [x] **Tests run on a real kernel now: `cargo xtask vm`.** The kernel boots under qemu with an initramfs holding `k11` and `vmtest` as /init; it checks the OCSF record in audit, enforce, session and loss modes, and with `--smoke` runs the dashboard smoke test inside. CI runs it on the runner's kernel with and without the BPF LSM.
- [x] **User strings not yet paged in are lost.** `bpf_probe_read_user_str` at sys_enter returns EFAULT for a path in a page the process never touched; the kernel faults it in, k11 drops the record (`read_failed`). A process can hide a metadata syscall this way. Fixed: the record keeps the user pointers and sys_exit reads again; `read_failed` went from 1-4 per VM run to 0.
- [x] **GeoIP databases were read into the heap** (~77 MB for City and ASN); now mmap'd.
- [x] **ptrace and failed execs are `ptrace_request` names and errno names** in summaries; the dashboard renders the server's one-line `summary`.
- [x] **Footprint defaults.** `PENDING` is 4096 entries (2.4 MB) unless watch.all; the raw-event budget is 5000 per agent and 50000 total, what the dashboard can show (the export keeps everything).
- [x] **A tracer floods ptrace records.** strace issues PTRACE_SYSCALL and PEEK* per syscall; the probe now records only requests that take a tracee or write into one.
- [~] **Node renames its main thread to `MainThread`**, so events from node agents carry that comm. Discovery uses the exec-time comm and the process list keeps the exec name; per-access comms show `MainThread`.

### Scale

- [x] **`GetAgentDetail` rebuilds everything under the store lock.**
  - Up to 3 x 20k aggregates cloned, sorted, errno-named, every 750 ms per open tab while the agent is active.
  - Ingestion waits on the lock, the ring overflows.
  - `if_version_ne` never hits: a refresh only follows an event, which bumped the version.
  - Fix: per-aggregate `updated_version`, a `since_version` request, client merges.
- [x] **Unfiltered stream before selection** ships every event (the whole host in watch-all) only to trigger refreshes.
  - Fix: a summary stream, or version-gated polling of `GetAgents`.
- [x] **Dashboard reactivity:** deep `$state` proxies on snapshots and the 5000-row log; `splice(0, 1)` per event.
  - Fix: `$state.raw`, batch pushes per frame.

### Simplification (daemon, proto)

- [x] **Store views mirror proto messages one to one** (summary, process, access, file, connection, unix, detail).
  - `grpc.rs` converts field by field. Build `k11_proto` types in the store: ~250 lines go.
  - `AgentTree` can hold a proto `AgentSummary` instead of 20 scalars copied in `summary()`.
- [x] **`ret` belongs in `EventMeta`**, as in the wire header.
  - Removes it from 11 payload variants, `Event::ret()`, and 11 proto messages.
- [x] **`sensitive` / `external` repeated in 9 payload messages:** two fields on proto `Event`.
- [x] **Proto duplicates:** `AgentDetail.root_pid/root_comm/version` repeat the summary and the response.
- [x] **`PathPairEvent.first_len`** is written by the probe and ignored by decode. Use it or drop it.
- [x] **`insert_process` counts a running process even when the pid exists.** Callers pre-check today; move the increment into the vacant branch.
- [x] **Stale text:**
  - `probe.rs` module doc still mentioned in-kernel path resolution.
  - `--check` printed the canonical-paths line when the LSM is off.
- [x] **Build:**
  - `build.rs` panics without the probe object: a fresh clone cannot `cargo check`, clippy or rust-analyzer.
  - Use a placeholder object, fail at load with the build hint.
  - `cargo xtask run` starts k11d unprivileged, so it can never work.
  - `protoc` is a system dependency; `protox` would remove it.
  - Fixed: placeholder object with a clear error at start, `xtask run` uses sudo, protox.

### Dashboard

Correctness:

- [x] **The sidebar goes stale once an agent is selected.**
  - The stream is filtered to the selection and is the only refresh trigger.
  - No initial `GetAgents`: "waiting for events" until something happens.
- [x] **The raw log loads the oldest 5000 events**, not the newest (offset 0 from the front of the ring).
  - `GetAgentEvents` needs tail semantics and an event sequence number to merge with the stream.
- [x] **`selectAgent` races:**
  - The previous stream keeps pushing; `pushEvent` never checks `rootPid`.
  - Events between snapshot and resubscribe are lost; late responses overwrite another agent's view.
- [x] **`connected` turns true before any response arrives:** flickers "live" with the daemon down.
- [x] **Any `loadDetail` error blanks the view**, including a network blip. On NOT_FOUND clear the selection.
- [x] **Undeny on an inherited rule does nothing:** `isPathDenied` means "covered by", not "is a rule".
- [x] **Process tree ancestor walks have no cycle guard**; pid reuse can hang the tab.
- [x] **"Xs ago" never updates** while an agent is quiet.
- [x] **Network counts disagree** between sidebar, summary and process tab (binds, listens counted differently).
- [x] **Sidebar order follows HashMap iteration** and jumps. Sort server-side; add `last_seen_ms` to the summary.
- [x] **Bind to 0.0.0.0 or :: is not flagged external**, the most exposed case.

Simplification:

- [x] One `FilterRow` and one `textFilter()` instead of four copies (File, Network, Unix, Process tabs).
- [x] One status cell, one connection table snippet, one activity string (built 3 times).
- [x] `SortMode` defined twice; `ALL_TAGS` restates `RawTag`; `riskLevel` and `riskReasons` repeat conditions.
- [x] `exportJson` hand-rolls a bigint replacer: use `toJson(AgentDetailSchema, ...)`.
- [x] Risk is computed in the client; classify on the server like sensitive/external. Send errno names, not numbers.

Dead code:

- [x] `stopStream`, `undismissAll` (dismissed agents cannot come back), `TreeStats.failed/lastSeenMs`.
- [x] Unread proto fields: `exited_count`, `fs_mod_count`, `events_dropped`, `Event.uid`, `StreamEventsRequest.format`, `ocsf_json`, `GetAgentEvents.offset/total`.
- [x] CSS:
  - Unused: `.filter-toggles`, `.fname.expanded`.
  - Never match: `.proc-node .exited` (the class sits on `.proc-node` itself), the `.tab-panel` toggle.
  - Duplicated: `.raw-line .fail-tag`, `.raw-header .toggle`; `.sort-btn` equals `.view-btn`.
  - `cursor: pointer` with no handler: `.fname`, network and unix table rows.

First-time use:

- [x] Policy errors only reach `console.warn`; deny and enforce controls fail silently in watch-all.
- [x] The enforce switch is one click, styled as a label, no confirmation.
- [x] No legend for `f/n/u/x`, `R/W/D/X/MV/P/L` or risk badges. Legends on the process and file tabs; risk reasons in the badge tooltip.
- [x] Clicking a process filters a collapsed raw log: nothing visible happens.
- [x] No warning when events were dropped or the aggregate cap was hit.

### Ease of use

Today: build needs nightly, bpf-linker, protoc and npm; every run is `sudo k11d`;
what to watch is a list of 15-char comm names, and `node` matches every node process.

Target:

```sh
cargo xtask build          # rootless: one static binary
sudo .../k11 daemon        # the recorder, run as root by hand (no service)
k11 run -- claude          # every session, unprivileged, own env and tty
```

- [x] **`k11 run -- <cmd>` over a unix socket** (`/run/k11/k11.sock`).
  - One connection is one session.
  - The daemon reads the caller's pid from `SO_PEERCRED` and makes it a tree root: a caller can only register itself.
  - `k11 run` registers itself, then spawns the command: lineage covers it from its first fork, no race, no change to the agent.
  - It ignores SIGINT while waiting, so Ctrl-C reaches the agent.
  - On exit it half-closes; the daemon answers with the session summary and writes it next to the OCSF log.
  - Exit code is the command's.
  - Rejected: `sudo k11 run`. sudo resets the environment (API keys, PATH) and puts root above the agent.
- [x] **Session summary** (M2), rendered by the daemon from the agent detail.
  - Duration, processes, processes left running, files read/written/deleted, sensitive hits, external hosts with ASN, denials.
- [x] **Default watch mode: sessions plus optional `watch.binaries`.**
  - Watch-all becomes explicit (`watch.all = true`).
  - The default gets light, and deny rules work with no extra config.
- [x] ~~Same socket carries the policy mutations~~: the dashboard needs them, and a browser cannot reach a unix socket. A control token does it instead (see Security).
- [x] **One binary, subcommands:** `k11 daemon`, `k11 check`, `k11 run`, `k11 dashboard`; later `k11 report`.
- [x] **A release artifact**: the binary already embeds probe and dashboard.
  - [x] Builds are static (musl): the binary built rootless anywhere runs as root on any distribution.
  - [x] The example config records to `/var/log/k11/ocsf.jsonl`, rotated by size.
  - [x] CI uploads the binary; a `v*` tag publishes it as a release.
  - [~] `cargo xtask install` (service setup) was tried and dropped: k11 is run by hand; `dist/k11.service` stays for those who want a service.

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
- On kernels without `group_dead`, a thread-group leader that exits before
  its threads (`pthread_exit` in main) ends the process record early.

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
- [x] OCSF loss record carrying the probe counters that grew (Base Event, class 0)
- [x] Size-based rotation for the OCSF export file (`export.max_mb`, one previous file)
- [x] CI: fmt + clippy + cargo test + BPF build + web build
- [x] Runtime smoke test under root (`k11-web/smoke.mts` against a live
  daemon), and `cargo xtask vm` on a real kernel with and without the BPF LSM.

## M2: One-command MVP (tag v0.1)

Goal: start k11 and you are monitoring. Nothing else to install or configure.

- [x] Embed `k11-web/dist` in the k11d binary; UI and gRPC-web same-origin
- [x] `--open`: launches the UI in the sudo-invoking user's session
- [x] `--check`: kernel capability report
- [x] `k11 run -- <cmd>`: spawn a command, register its PID as a tree root
  over a local RPC, watch exactly that session; no comm-name config
- [x] Session summary on agent exit: files touched, sensitive hits, external
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
- [x] Correlation id robust across daemon restarts (root_pid + boot id)

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
