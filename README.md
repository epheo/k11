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
- **Live gRPC + web dashboard** at `localhost:1100` — per-agent process trees,
  file/network/unix tabs, filtering, raw event log.
- **Enrichment**: reverse-DNS, GeoIP (MaxMind), ASN, uid → username via
  `/etc/passwd`.

---

## Minimal enforcement

Off by default. When enabled, **file-path deny rules** return `-EPERM` on
`open(2)` via the LSM `file_open` hook, for watched process trees.

This is opt-in hygiene, not a sandbox. Known gaps — a determined, compromised
process can work around them:

- Metadata operations (`chmod`, `chown`, `rename`, `unlink`) use different LSM
  hooks and are **not** currently denied. They are recorded.
- `stat()` / `lstat()` don't trigger `file_open`, so file existence can be
  probed.
- Runtime rule changes aren't persisted across daemon restarts.

See [TODO.md](TODO.md) for the full list. Use enforcement for guardrails you
control, not for containment of hostile code.

---

## Local-only

No cloud, no telemetry, no phone-home. Events stay on the host unless you
choose to export them. gRPC is bound to `0.0.0.0:1100` by default — firewall or
rebind as appropriate.

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

# run (needs CAP_BPF / CAP_SYS_ADMIN)
sudo ./target/debug/k11d

# dashboard
open http://localhost:1100
```

Copy `config/k11.toml.example` → `config/k11.toml` to set watch lists, deny
rules, or OCSF export.

---

## License

[AGPL v3](LICENSE) — source stays open, the network can't hide behind it.

Commercial licensing is available. See [CLA.md](CLA.md) for contributor terms.
