# k11

**k11 is the black-box recorder for AI coding agents.** It observes every file,
network, and socket interaction at the kernel level, structures it as OCSF, and
gives you a forensic trail. What you do with that trail — alert, audit, export
to SIEM, feed into your own policy engine — is up to you.

Zero cloud dependency. All data stays on the host.

---

## What it records

k11 hooks syscalls via eBPF tracepoints and stitches events into per-agent
process trees (fork lineage tracked in-kernel). The daemon emits structured
events; the dashboard renders them live.

| Class        | Syscalls                                                  |
|--------------|-----------------------------------------------------------|
| Process      | `execve`, `fork`, `exit`, `ptrace`                        |
| File         | `openat`, `unlink`, `rename`, `chmod`, `chown`, `symlink` |
| Network      | `connect`, `bind`, `listen`                               |
| Unix sockets | `connect`                                                 |

Events include PID, TGID, UID, comm, timestamp, and syscall-specific arguments.
Errno is preserved. `openat` retains flags so read/write intent is recoverable.

---

## Output

- **OCSF 1.1.0 JSON Lines** — stdout or a file path. Configurable per-event
  class (Process Activity 1007, File System Activity 1001, Network Activity
  4001). Risk score and severity are computed per event.
- **Live gRPC API** on `localhost:1100` (gRPC-web enabled) — per-agent process
  trees, file/network/unix tabs, filtering, raw event log.
- **Web dashboard** (`k11-web`, Svelte) served separately on `localhost:3000`,
  proxying gRPC calls to `:1100`.
- **Enrichment**: reverse-DNS, GeoIP + ASN (bring your own MaxMind GeoLite2
  databases — their license forbids bundling), uid → username via
  `/etc/passwd`. Each degrades gracefully when unavailable.

---

## Minimal enforcement

Off by default. When enabled, **file-path deny rules** return `-EPERM` on
`open(2)` via the LSM `file_open` hook, for watched process trees. Deny rules
require an explicit `watch.binaries` list — with an empty watch list nothing
is watched, so k11d refuses the combination at startup rather than silently
enforcing nothing.

This is opt-in hygiene, not a sandbox, and it is deliberately frozen at this
surface. Known gaps — a determined, compromised process can work around them:

- Metadata operations (`chmod`, `chown`, `rename`, `unlink`) use different LSM
  hooks and are **not** denied. They are recorded.
- `stat()` / `lstat()` don't trigger `file_open`, so file existence can be
  probed.
- Runtime rule changes aren't persisted across daemon restarts.

See [ROADMAP.md](ROADMAP.md) for the full list of accepted limitations. Use
enforcement for guardrails you control, not for containment of hostile code.

---

## Local-only

No cloud, no telemetry, no phone-home. Events stay on the host unless you
choose to export them. The gRPC API binds `127.0.0.1:1100` by default; it is
unauthenticated, so if you rebind it to expose it, front it with a reverse
proxy that adds auth.

---

## Architecture

```
 eBPF tracepoints                  userspace
 ─────────────────                 ─────────
 sched_process_*  ─┐
 sys_enter_*       ├──▶ ring buffer ──▶ k11d ──┬──▶ gRPC / web dashboard
 sys_exit_*        │                           │
 file_open (LSM)  ─┘                           └──▶ OCSF JSONL (stdout/file)
```

Crates:

- `k11-probe` — eBPF programs (aya-ebpf)
- `k11-common` — shared event structs, constants
- `k11-proto` — gRPC service + messages (tonic)
- `k11d` — userspace daemon (Tokio)
- `k11-web` — Svelte dashboard (served standalone, talks gRPC-web)
- `xtask` — build orchestration

---

## Running it

Requires Linux with BTF (`CONFIG_DEBUG_INFO_BTF=y`) and BPF-LSM
(`lsm=...,bpf` on the kernel command line) for enforcement.

```sh
# build probe + daemon + web assets
cargo xtask build

# run the daemon (needs CAP_BPF / CAP_SYS_ADMIN) — serves gRPC on :1100
sudo ./target/debug/k11d

# in another shell, run the dashboard (Vite dev server on :3000)
cd k11-web && npm run dev
open http://localhost:3000
```

For a production-style deploy, build once with `cargo xtask build` and serve
`k11-web/dist/` with any static host (nginx, caddy, `python -m http.server`),
keeping `/k11.K11/*` proxied to `k11d` on `:1100`.

Copy `config/k11.toml.example` → `config/k11.toml` to set watch lists, deny
rules, or OCSF export.

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

[AGPL v3](LICENSE) — source stays open, the network can't hide behind it.

Commercial licensing is available. See [CLA.md](CLA.md) for contributor terms.
