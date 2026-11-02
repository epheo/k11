# k11

**k11 is the black-box recorder for AI coding agents.** It observes every file,
network, and socket interaction at the kernel level, structures it as OCSF, and
gives you a forensic trail. What you do with that trail (alert, audit, export
to SIEM, feed into your own policy engine) is up to you.

Zero cloud dependency. All data stays on the host.

---

## What it records

k11 hooks syscalls via eBPF tracepoints and stitches events into per-agent
process trees (fork lineage tracked in-kernel). The daemon emits structured
events; the dashboard renders them live.

| Class        | Syscalls                                                                                                                              |
|--------------|---------------------------------------------------------------------------------------------------------------------------------------|
| Process      | `execve`, `fork`, `exit`, `ptrace`                                                                                                    |
| File         | `open`, `openat`, `openat2`, `creat`, `unlink[at]`, `rename[at][2]`, `chmod`, `fchmodat[2]`, `chown`, `lchown`, `fchownat`, `symlink[at]` |
| Network      | `connect`, `bind`, `listen`                                                                                                           |
| Unix sockets | `connect`                                                                                                                             |

Every variant is hooked because libc picks different ones per architecture:
glibc on x86_64 uses `rename`, `unlink`, `chmod`; arm64 only has the `*at`
forms. Variants the running kernel lacks are skipped at startup.

Events include PID, TGID, UID, comm, a CLOCK_BOOTTIME timestamp (correct
across suspend), and syscall-specific arguments. Errno is preserved. Opens
retain flags so read/write intent is recoverable.

When the BPF LSM is available, every open that reaches a file is recorded
from the kernel's `file_open` hook with the fully resolved path (directory
fds honoured, symlinks followed, no user-memory race), whatever syscall made
it. One open syscall yields one record: backing-file opens a filesystem
makes underneath (overlayfs, copy-up) and the kernel's own opens during
exec are not reported as the process's activity. Opens that fail before
reaching a file (lookup errors, permission denials) and every metadata
syscall are recorded from the syscall; the record keeps the directory fd,
and a relative path is made absolute best-effort in the daemon by reading
the process's working directory or that fd from `/proc`.

---

## Output

- **OCSF 1.1.0 JSON Lines**: stdout or a file path. Process Activity (1007),
  File System Activity (1001), Network Activity (4001). Risk score and
  severity are computed per event. The export is lossless: when the writer
  falls behind, the daemon waits and the kernel ring absorbs the burst, and
  anything the ring cannot absorb is counted and logged.
- **Live dashboard + gRPC API** on `http://127.0.0.1:1100`, served by the
  daemon itself (the web UI is embedded in the binary; gRPC-web is enabled
  for it, same-origin, no CORS). Per-agent process trees, file/network/unix
  tabs, filtering, raw event log.
- **Enrichment**: reverse-DNS, GeoIP + ASN (bring your own MaxMind GeoLite2
  databases, their license forbids bundling), uid to username via
  `/etc/passwd`. Each degrades gracefully when unavailable.

---

## Minimal enforcement

Off by default. When enabled, **file-path deny rules** return `-EPERM` on
open via the LSM `file_open` hook, for watched process trees. Deny rules
require an explicit `watch.binaries` list; with an empty watch list nothing
is watched, so k11d refuses the combination at startup rather than silently
enforcing nothing.

Rules have two outcomes, both recorded distinctly: in audit mode
(`enforce = false`) a matching open is **audited** (allowed, logged, OCSF
disposition Detected); when enforcing it is **denied** (EPERM, disposition
Blocked).

This is opt-in hygiene, not a sandbox, and it is deliberately frozen at this
surface. Known gaps a determined, compromised process can work around:

- Metadata operations (`chmod`, `chown`, `rename`, `unlink`) use different LSM
  hooks and are **not** denied. They are recorded.
- `stat()` / `lstat()` do not trigger `file_open`, so file existence can be
  probed.
- Runtime rule changes are not persisted across daemon restarts.

See [ROADMAP.md](ROADMAP.md) for the full list of accepted limitations. Use
enforcement for guardrails you control, not for containment of hostile code.

---

## Kernel support

k11d probes the running kernel at startup and uses what it finds; the same
binary runs on any 64-bit Linux from 5.8 up. `k11d --check` loads and
verifies the probe and prints the result without recording anything.

| Layer                                  | Needs                                      | Without it                                              |
|----------------------------------------|--------------------------------------------|---------------------------------------------------------|
| Recording (all syscalls above)         | Linux 5.8+, tracefs, root or CAP_BPF+PERFMON | nothing works: this is the baseline                   |
| Canonical paths for successful opens   | Linux 5.10+, BTF, BPF LSM (`lsm=...,bpf`)  | opens recorded as requested; relative ones resolved via /proc |
| Deny rules and enforcement             | same as above                              | rules refused at startup, enforcement cannot be enabled  |

Fedora enables the BPF LSM by default. Ubuntu and Debian do not: add `bpf`
to the `lsm=` kernel command line to get canonical paths and enforcement.

---

## Local-only

No cloud, no telemetry, no phone-home. Events stay on the host unless you
choose to export them. The gRPC API binds `127.0.0.1:1100` by default; it is
unauthenticated, so if you rebind it to expose it, front it with a reverse
proxy that adds auth.

---

## Architecture

```
 eBPF (kernel)                          userspace
 -------------                          ---------
 sched_process_*    -+
 sys_enter_*  -+     |
 sys_exit_*   -+-----+--> ring buffer --> k11d --+--> gRPC / web dashboard
 file_open (LSM) ----+   (variable-length records) |
                                                   +--> OCSF JSONL (stdout/file)
```

One pending record per thread carries a syscall from enter to exit; one exit
program serves every syscall. The LSM hook consumes the pending record when
it records an open, so the two never double-count.

Crates:

- `k11-probe`: eBPF programs (aya-ebpf); its own workspace, needs nightly
- `k11-common`: wire format, syscall table, constants (no dependencies)
- `k11-proto`: gRPC service + messages (tonic)
- `k11d`: userspace daemon (Tokio); embeds and serves the dashboard; stable Rust
- `k11-web`: Svelte dashboard (talks gRPC-web, same origin)
- `xtask`: build orchestration

---

## Running it

```sh
# build probe + web assets + daemon (web UI is embedded into k11d)
cargo xtask build

# what can this kernel do?
sudo ./target/debug/k11d --check

# start recording: dashboard + gRPC API on http://127.0.0.1:1100
sudo ./target/debug/k11d --open
```

`--open` launches the dashboard in your browser (it runs xdg-open inside the
sudo-invoking user's session). Without it, open the printed URL yourself.
That is the whole deployment: one binary, one port.

For dashboard development with live reload: `cd k11-web && npm run dev`
serves on `:3000` and proxies API calls to the daemon on `:1100`.

Copy `config/k11.toml.example` to `config/k11.toml` (or pass `--config`) to
set watch lists, deny rules, ring buffer size, or OCSF export.

---

## Non-goals

- **Sandboxing.** Enforcement stays a minimal opt-in guardrail; Landlock,
  bubblewrap, and containers own real containment.
- **API auth/TLS.** The API binds localhost; put a reverse proxy in front if
  you need remote access.
- **An LLM judgment tier.** The recorder stands on its own.

Roadmap and accepted limitations: [ROADMAP.md](ROADMAP.md).

---

## License

[AGPL v3](LICENSE): source stays open, the network can't hide behind it.

Commercial licensing is available. See [CLA.md](CLA.md) for contributor terms.
