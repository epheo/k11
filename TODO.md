# k11 — TODO

## LSM enforcement gaps

File-path deny via the `file_open` LSM hook is the one enforcement surface. It
is honest hygiene — an opt-in guardrail — not a sandbox. The gaps below mean a
determined, compromised process can still work around it. Close them before
relying on enforcement as a real boundary.

- [ ] **Metadata operations bypass file deny rules**: `chmod`, `chown`, `rename`, `unlink` go through `inode_setattr`/`inode_setxattr`/`inode_rename`/`inode_unlink` — not `file_open`. A watched process can modify permissions or delete denied files. Fix: hook `inode_setattr`, `inode_setxattr`, `inode_unlink`, `inode_rename`.

- [ ] **`stat()` reveals file existence on denied paths**: `lstat`/`fstat` don't trigger `file_open`, so a watched process can probe whether denied files exist. Fix: hook `inode_getattr` (more aggressive, may break tooling).

## Policy persistence

- [ ] **Runtime policy not persisted**: Rules added via API/dashboard are lost on daemon restart. Only `k11.toml` rules survive. Fix: write policy state to a file on change, reload on startup.

## Future enforcement

- [ ] **Granular file deny modes**: Currently deny rules block all `open()` (read, write, list). Could add per-rule flags for read-only deny, write-only deny, etc.

- [ ] **aya CO-RE / kfunc support**: When aya-ebpf gains CO-RE or kfunc support, replace the `.rodata` global workaround for `bpf_d_path` with a proper `bpf_path_d_path` kfunc call. Track: https://github.com/aya-rs/aya/issues/432
