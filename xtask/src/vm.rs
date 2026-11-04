//! `cargo xtask vm`: the integration test on a real kernel. The kernel boots
//! under qemu (KVM) with an initramfs holding `k11`, the `vmtest` binary as
//! /init and /agent, and their shared libraries; the test prints its checks
//! on the serial console and its verdict last. `cargo xtask initramfs` builds
//! the image alone, so CI boots one image on many kernels. It holds the
//! release build: the image lives in the VM's memory, and a debug build alone
//! is over 100 MB.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const INITRAMFS: &str = "target/vmtest/initramfs.cpio";
const TIMEOUT: Duration = Duration::from_secs(300);

/// Write the test image around `k11`; returns its path.
pub fn initramfs(smoke: bool, k11: PathBuf) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release", "--package", "vmtest"]);
    crate::run(cmd, "vmtest build")?;

    let mut files = vec![
        ("/init", PathBuf::from("target/release/vmtest")),
        ("/agent", PathBuf::from("target/release/vmtest")),
        ("/k11", k11),
    ];
    if smoke {
        files.extend([
            ("/usr/bin/node", find("node")?),
            ("/usr/bin/bash", PathBuf::from("/usr/bin/bash")),
            ("/bin/bash", PathBuf::from("/usr/bin/bash")),
            ("/usr/bin/mv", PathBuf::from("/usr/bin/mv")),
            ("/usr/bin/chmod", PathBuf::from("/usr/bin/chmod")),
            ("/usr/bin/ln", PathBuf::from("/usr/bin/ln")),
            ("/usr/bin/cat", PathBuf::from("/usr/bin/cat")),
            ("/usr/bin/rm", PathBuf::from("/usr/bin/rm")),
            ("/smoke/smoke.mts", PathBuf::from("k11-web/smoke.mts")),
            ("/smoke/package.json", PathBuf::from("k11-web/package.json")),
            ("/smoke/src/gen", PathBuf::from("k11-web/src/gen")),
            (
                "/smoke/node_modules/@bufbuild/protobuf",
                PathBuf::from("k11-web/node_modules/@bufbuild/protobuf"),
            ),
            (
                "/smoke/node_modules/@connectrpc",
                PathBuf::from("k11-web/node_modules/@connectrpc"),
            ),
        ]);
    }
    write_initramfs(Path::new(INITRAMFS), &files)?;
    Ok(PathBuf::from(INITRAMFS))
}

/// Boot `kernel` (default: the running one) on `initramfs`; Ok when the
/// test passes.
pub fn boot(
    kernel: Option<PathBuf>,
    initramfs: &Path,
    extra: Option<String>,
    check: bool,
) -> Result<()> {
    let kernel = match kernel {
        Some(k) => k,
        None => running_kernel()?,
    };
    let mut append = String::from("console=ttyS0 panic=-1 quiet loglevel=3");
    if check {
        append.push_str(" k11.check");
    }
    if let Some(extra) = extra {
        append.push(' ');
        append.push_str(&extra);
    }
    let mut qemu = Command::new("qemu-system-x86_64")
        .args(["-enable-kvm", "-cpu", "host", "-m", "2048", "-smp", "2"])
        .arg("-kernel")
        .arg(&kernel)
        .arg("-initrd")
        .arg(initramfs)
        .args(["-append", &append])
        .args(["-display", "none", "-serial", "stdio", "-no-reboot"])
        .stdout(Stdio::piped())
        .spawn()
        .context("starting qemu-system-x86_64")?;
    let pid = qemu.id();
    std::thread::spawn(move || {
        std::thread::sleep(TIMEOUT);
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });
    let mut verdict = None;
    for line in BufReader::new(qemu.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
    {
        println!("{line}");
        if let Some(v) = line.trim().strip_prefix("VMTEST: ") {
            verdict = Some(v.to_string());
        }
    }
    qemu.wait()?;
    match verdict.as_deref() {
        Some("PASS") => Ok(()),
        _ if check => Ok(()),
        Some(v) => bail!("vm test: {v}"),
        None => bail!("vm test: no verdict (timeout or boot failure)"),
    }
}

/// The running kernel's image, where distributions put it readable.
fn running_kernel() -> Result<PathBuf> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_string();
    [
        format!("/lib/modules/{release}/vmlinuz"),
        format!("/usr/lib/modules/{release}/vmlinuz"),
        format!("/boot/vmlinuz-{release}"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| fs::File::open(p).is_ok())
    .with_context(|| format!("no readable kernel image for {release}; pass --kernel"))
}

/// A newc archive of `files` (directories are walked), their shared
/// libraries, and the few /etc files k11 reads.
fn write_initramfs(out: &Path, files: &[(&str, PathBuf)]) -> Result<()> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    entries.insert(
        "/etc/passwd".into(),
        b"root:x:0:0:root:/:/bin/sh\n".to_vec(),
    );
    entries.insert("/etc/hostname".into(), b"k11vm\n".to_vec());
    // Names resolve from files alone: the VM has no network. Two answers
    // (glibc returns more than the first only with `multi on`), so libc
    // sorts them, connecting to each.
    entries.insert(
        "/etc/hosts".into(),
        b"127.0.0.1 localhost\n::1 localhost\n".to_vec(),
    );
    entries.insert("/etc/host.conf".into(), b"multi on\n".to_vec());
    for (dest, src) in files {
        add(&mut entries, dest, src)?;
    }
    let mut dirs: Vec<String> = ["/proc", "/sys", "/dev", "/tmp", "/run", "/etc"]
        .map(String::from)
        .to_vec();
    for path in entries.keys() {
        let mut dir = Path::new(path).parent();
        while let Some(d) = dir.filter(|d| *d != Path::new("/")) {
            dirs.push(d.to_string_lossy().into_owned());
            dir = d.parent();
        }
    }
    dirs.sort_by_key(|d| (d.matches('/').count(), d.clone()));
    dirs.dedup();

    fs::create_dir_all(out.parent().unwrap())?;
    let mut cpio = Vec::new();
    let mut ino = 1;
    let mut entry = |name: &str, mode: u32, data: &[u8]| {
        let name = format!("{}\0", name.trim_start_matches('/'));
        let header = format!(
            "070701{ino:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            0, 0, 1, 0, data.len(), 0, 0, 0, 0, name.len(), 0
        );
        ino += 1;
        cpio.extend_from_slice(header.as_bytes());
        cpio.extend_from_slice(name.as_bytes());
        cpio.resize(cpio.len().next_multiple_of(4), 0);
        cpio.extend_from_slice(data);
        cpio.resize(cpio.len().next_multiple_of(4), 0);
    };
    for dir in &dirs {
        entry(dir, 0o040755, &[]);
    }
    for (path, data) in &entries {
        let exec = data.starts_with(b"\x7fELF");
        entry(path, if exec { 0o100755 } else { 0o100644 }, data);
    }
    entry("TRAILER!!!", 0, &[]);
    fs::File::create(out)?.write_all(&cpio)?;
    Ok(())
}

fn add(entries: &mut BTreeMap<String, Vec<u8>>, dest: &str, src: &Path) -> Result<()> {
    if src.is_dir() {
        for item in fs::read_dir(src)? {
            let item = item?;
            let name = item.file_name().to_string_lossy().into_owned();
            add(entries, &format!("{dest}/{name}"), &item.path())?;
        }
        return Ok(());
    }
    let data = fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    if data.starts_with(b"\x7fELF") {
        let ldd = Command::new("ldd").arg(src).output()?;
        for line in String::from_utf8_lossy(&ldd.stdout).lines() {
            let lib = match line.split_once("=>") {
                Some((_, rest)) => rest.split_whitespace().next(),
                None => line.split_whitespace().next(),
            };
            if let Some(lib) = lib.filter(|l| l.starts_with('/')) {
                if !entries.contains_key(lib) {
                    entries.insert(lib.to_string(), fs::read(fs::canonicalize(lib)?)?);
                }
            }
        }
    }
    entries.insert(dest.to_string(), data);
    Ok(())
}

/// A program's path on PATH, resolved (version managers link to it).
fn find(program: &str) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
        .map(|p| fs::canonicalize(&p).unwrap_or(p))
        .with_context(|| format!("{program} not found on PATH"))
}
