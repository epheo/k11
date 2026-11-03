# k11

**k11 is the black-box recorder for AI coding agents.**
It records every file, process, network and socket action an agent takes, at the kernel level.
The record is OCSF, so a SIEM reads it as is; the dashboard shows it live.

Zero cloud dependency. All data stays on the host.

---

## Quick start

```sh
cargo xtask build                       # rootless: probe, dashboard, one static binary
sudo target/x86_64-unknown-linux-musl/debug/k11 daemon --open
k11 run -- claude                       # another terminal: no sudo, your own environment
```

`k11 run` registers itself with the daemon, then starts the command.
Everything the command starts, at any depth, is recorded from its first fork.
Ctrl-C reaches the command; when it exits, k11 prints what the session did, for example:

```
k11: claude recorded for 12m40s
  processes  41 started, 1 still running: node 88213
  files      812 read, 37 written, 2 deleted, 140 only failed
  sensitive  /home/u/proj/.env (read)
  external   api.example.com 203.0.113.10:443 (AS64500 Example)
  risk       medium: sensitive files, external network
```

The dashboard is at http://127.0.0.1:1100.
`--open` opens it with control over the deny rules; otherwise it is read-only, and `sudo k11 dashboard` opens it with control.

---

## What it records

eBPF tracepoints, and the BPF LSM where available.
Fork lineage is tracked in the kernel, so every event names the tree it belongs to.

| Class        | Syscalls |
|--------------|----------|
| Process      | `execve[at]` (failed ones too), fork, exit, `ptrace` (attach and writes) |
| File         | `open`, `openat`, `openat2`, `creat`, `unlink[at]`, `rename[at][2]`, `chmod`, `fchmodat[2]`, `chown`, `lchown`, `fchownat`, `symlink[at]` |
| Network      | `connect`, `bind`, `listen` |
| Unix sockets | `connect` |

- Every variant is hooked: glibc on x86_64 uses `rename`, `unlink`, `chmod`; arm64 only has the `*at` forms. Missing variants are skipped.
- Each record carries pid, uid, comm, the syscall result (fd or errno), and a CLOCK_BOOTTIME timestamp (correct across suspend).
- One syscall, one record.
- With the BPF LSM, an open that reaches a file is recorded with the kernel-resolved path: dirfd honoured, symlinks followed, no user-memory race.
- A filesystem's backing-file opens (overlayfs) and the kernel's own opens during exec are not reported as the process's activity.
- Relative paths of failed opens and metadata syscalls are made absolute from `/proc`, best effort.
- A path the process passes from a page it never touched is read again when the syscall returns.
- Threads are not processes; a process ends with its last thread where the kernel says so (`group_dead`).

---

## Output

- **OCSF 1.1.0 JSON Lines**, `/var/log/k11/ocsf.jsonl` with the example config.
  - Process Activity (1007), File System Activity (1001), Network Activity (4001), checked against the schema's required fields.
  - `metadata.correlation_uid` is `<boot id>:<root pid>`: one session, across daemon restarts.
  - `metadata.sequence` increases by one per record; a gap is a loss.
  - Risk score and severity per record; the deny-rule outcome as `action_id` and `disposition_id`.
  - Lossless: a slow writer stalls decoding and the kernel ring absorbs it; what the ring cannot is counted and logged.
  - Rotated to `<output>.1` past `export.max_mb` (256 by default).
- **Dashboard and gRPC API** on `http://127.0.0.1:1100`, served by the daemon (the UI is embedded).
  - Per-agent process trees, file, network and unix tabs, a raw event log.
  - Only loopback `Host` names are served, so a web page cannot reach it through DNS rebinding.
- **Enrichment**: reverse DNS, GeoIP and ASN (bring your own MaxMind GeoLite2 databases; their license forbids bundling), uid to username.

---

## Minimal enforcement

Off by default.
**File-path deny rules** make an open fail with EPERM through the LSM `file_open` hook, for recorded trees.

- A rule covers a path and everything under it, by whole components: `/home/u/.ssh` does not cover `/home/u/.ssh-backup`.
- Audit mode (`enforce = false`) records a match as **audited** and lets it through; enforcing records it as **denied**.
- Rules come from `k11.toml`, or from the dashboard opened with control (`k11 daemon --open`, `sudo k11 dashboard`).
- The API refuses policy changes without that dashboard's token, so the recorded agent cannot switch its own guardrail off.
- Refused with `watch.all`: rules would apply to every process on the host.

This is opt-in hygiene, not a sandbox. Known gaps:

- `chmod`, `chown`, `rename`, `unlink` go through other LSM hooks and are recorded, not denied.
- `stat()` does not trigger `file_open`: existence can be probed.
- A file whose resolved path exceeds 255 bytes is not matched.
- Rule changes from the dashboard are not written back to `k11.toml`.

Use it for guardrails you control, not for containing hostile code. See [ROADMAP.md](ROADMAP.md).

---

## What is watched

- `k11 run -- <cmd>` sessions, always.
- `watch.binaries`, or `k11 daemon --watch <name>`: trees started by these names (the kernel's 15-character comm), and those already running at startup.
- `watch.all`: every process on the host. Heavy; deny rules are refused.

---

## Kernel support

The same binary runs on any 64-bit Linux from 5.8; `sudo k11 check` prints what this kernel supports.
Releases attach it: a static x86_64 binary with the probe and dashboard inside.

| Layer                                | Needs                                         | Without it |
|--------------------------------------|-----------------------------------------------|------------|
| Recording                            | Linux 5.8+, tracefs, root or CAP_BPF+PERFMON  | nothing works: the baseline |
| Process ends with its last thread    | Linux 6.16+ (`group_dead`)                    | a leader leaving first ends the record early |
| Canonical paths, deny rules          | Linux 5.15+, BTF, BPF LSM (`lsm=...,bpf`)     | paths as requested; rules refused |

Fedora enables the BPF LSM by default; Ubuntu and Debian need `bpf` added to `lsm=` on the kernel command line.

### Tested kernels

CI boots each of these under KVM on every push, without and with the BPF LSM, and runs the integration test.
They are Fedora's builds from Koji; the list lives in `.github/workflows/ci.yml`.

| Kernel  | Recording | Canonical paths, deny rules               | Last-thread exits |
|---------|-----------|-------------------------------------------|-------------------|
| 5.8.18  | yes       | no: no `bpf_d_path`                       | no                |
| 5.10.23 | yes       | no: `bpf_d_path` not allowed in file_open | no                |
| 5.15.18 | yes       | yes                                       | no                |
| 6.1.18  | yes       | yes                                       | no                |
| 6.6.14  | yes       | yes                                       | no                |
| 6.12.15 | yes       | yes                                       | no                |
| 6.18.16 | yes       | yes                                       | yes               |
| 7.1.13  | yes       | yes                                       | yes               |
| 7.3.1   | yes       | yes                                       | yes               |

Stable kernels from 6.19 to 7.1 skip syscall programs on CPUs without a perf event for the tracepoint.
k11 works around it on its own (`k11d/src/cpu_cover.rs`); 7.1.13 above is one of them.

---

## Architecture

```
 eBPF (kernel)                            userspace
 -------------                            ---------
 task_newtask       -+
 sched_process_*    -+
 sys_enter_*  -+     |
 sys_exit_*   -+-----+--> ring buffer --> k11 daemon --+--> dashboard / gRPC
 file_open (LSM) ----+   (variable-length records)     +--> OCSF JSONL
                                                       +--> session socket <-- k11 run
```

- Each thread's syscall builds one record from enter to exit; one exit program serves every syscall.
- The LSM hook writes the canonical path into that record; exit ships it with the real result.

Crates:

- `k11-probe`: eBPF programs (aya-ebpf); its own workspace, needs nightly.
- `k11-common`: wire format, syscall table, constants (no dependencies).
- `k11-proto`: gRPC service and messages (tonic; compiled with protox, no protoc).
- `k11d`: the `k11` binary: daemon, `check`, `run`, `dashboard`; embeds the dashboard; stable Rust.
- `k11-web`: Svelte dashboard (gRPC-web, same origin).
- `xtask`: build, run, VM test.

---

## Building

Needs Rust stable and nightly (with `rust-src`), `bpf-linker`, Node 22; no root.
Builds are static (`<arch>-unknown-linux-musl`, added with rustup on first use): one file that runs as root on any distribution.

```sh
cargo xtask build [--release]   # probe, dashboard, static binary; prints its path
cargo xtask run -- check        # build, then sudo k11 check
cargo xtask run                 # build, then sudo k11 daemon --open
```

`dist/k11.service` is a systemd unit for running the daemon as a service (`/usr/local/bin/k11`, `/etc/k11/k11.toml`).
For dashboard work with live reload: `cd k11-web && npm run dev` (port 3000, proxies to 1100).
`npm run smoke` in `k11-web` checks a running daemon end to end; run it inside a recorded tree.

`cargo xtask vm [--smoke]` is the integration test on a real kernel: it boots the running kernel under qemu (KVM) with k11 as the init's workload and checks the OCSF record. `--kernel` and `--append "lsm=...,bpf"` pick other kernels and LSM setups; `cargo xtask initramfs` builds the image once for `--initramfs`, as CI does.

---

## Non-goals

- **Sandboxing.** Landlock, bubblewrap and containers own real containment.
- **Remote access.** The API binds localhost; front it with an authenticating proxy if you must expose it.
- **An LLM judgment tier.** The recorder stands on its own.

Roadmap and accepted limitations: [ROADMAP.md](ROADMAP.md).

---

## License

[AGPL v3](LICENSE): source stays open, the network can't hide behind it.

Commercial licensing is available. See [CLA.md](CLA.md) for contributor terms.
