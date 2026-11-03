//! k11 on a real kernel. `cargo xtask vm` boots one with this binary as
//! /init: it mounts what k11 needs, then for each mode writes a config,
//! starts `k11 daemon`, runs the agent scenarios, stops the daemon and
//! checks the OCSF record. As /agent (comm "agent") it is those scenarios.
//! The verdict is the last console line: `VMTEST: PASS` or `VMTEST: FAIL`.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[0].ends_with("init") {
        init();
    } else {
        agent(args.get(1).map(String::as_str).unwrap_or("all"));
    }
}

// ---------------------------------------------------------------------------
// /init
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Audit,
    Enforce,
    Session,
    Loss,
    /// An agent already running when the daemon starts, found by --watch.
    Seed,
    Smoke,
}

impl Mode {
    fn config(self) -> String {
        let watch = match self {
            Mode::Session | Mode::Seed => "",
            _ => "binaries = [\"agent\"]",
        };
        let ring = if self == Mode::Loss {
            "[probe]\nring_buffer_kb = 4\n"
        } else {
            ""
        };
        format!(
            "[watch]\n{watch}\n[policy]\nenforce = {}\ndeny_file_paths = [\"/tmp/k11t/secret\"]\n\
             [export]\nenabled = true\noutput = \"/tmp/out.jsonl\"\n{ring}",
            self == Mode::Enforce
        )
    }

    /// The command init runs while the daemon records.
    fn command(self) -> Command {
        match self {
            Mode::Session => {
                let mut c = Command::new("/k11");
                c.args(["run", "--label", "demo", "--", "/agent", "all"]);
                c
            }
            Mode::Loss => agent_command("burst"),
            // The agent under test started before the daemon.
            Mode::Seed => agent_command("noop"),
            Mode::Smoke => agent_command("smoke"),
            Mode::Audit | Mode::Enforce => agent_command("all"),
        }
    }
}

/// The podman container id the "contained" agent poses as.
const CONTAINER_ID: &str = "3f2a1b9c0d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";

fn agent_command(scenario: &str) -> Command {
    let mut c = Command::new("/agent");
    c.arg(scenario);
    c
}

fn init() {
    mount("proc", "/proc", "proc");
    mount("sysfs", "/sys", "sysfs");
    mount("devtmpfs", "/dev", "devtmpfs");
    mount("tmpfs", "/tmp", "tmpfs");
    mount("tmpfs", "/run", "tmpfs");
    mount("tracefs", "/sys/kernel/tracing", "tracefs");
    mount("securityfs", "/sys/kernel/security", "securityfs");
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2");
    lo_up();

    if cmdline_has("k11.check") {
        let _ = Command::new("/k11").arg("check").status();
        poweroff();
    }
    // What this kernel supports decides which checks apply.
    let report = Command::new("/k11")
        .arg("check")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    print!("{report}");
    let kernel = Kernel {
        lsm: report.contains("file_open hook loaded"),
        group_dead: report.contains("(group_dead)"),
    };
    let mut modes = vec![Mode::Audit, Mode::Session, Mode::Loss, Mode::Seed];
    if kernel.lsm {
        modes.push(Mode::Enforce);
    }
    if fs::metadata("/usr/bin/node").is_ok() {
        modes.push(Mode::Smoke);
    }
    let mut failures = 0;
    for mode in modes {
        failures += run_mode(mode, kernel);
    }
    println!(
        "VMTEST: {}",
        if failures == 0 {
            "PASS".into()
        } else {
            format!("FAIL {failures}")
        }
    );
    poweroff();
}

#[derive(Clone, Copy)]
struct Kernel {
    lsm: bool,
    group_dead: bool,
}

/// One daemon run; returns the number of failed checks.
fn run_mode(mode: Mode, kernel: Kernel) -> usize {
    let _ = fs::remove_file("/tmp/out.jsonl");
    let _ = fs::remove_file("/tmp/k11t-go");
    let _ = fs::remove_dir_all("/tmp/k11t");
    fs::write("/etc/k11.toml", mode.config()).unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    // Started before the daemon, so only the startup scan can find it.
    let mut early =
        (mode == Mode::Seed).then(|| agent_command("late").spawn().expect("spawn agent"));
    let mut daemon = Command::new("/k11")
        .args(["daemon", "--config", "/etc/k11.toml"])
        .args(if mode == Mode::Seed {
            &["--watch", "agent"][..]
        } else {
            &[]
        })
        .env("RUST_LOG", "info")
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn k11 daemon");
    let (ready_tx, ready_rx) = mpsc::channel();
    let stderr = daemon.stderr.take().unwrap();
    let lines = Arc::clone(&log);
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            println!("k11| {line}");
            if line.contains("recording") {
                let _ = ready_tx.send(());
            }
            lines.lock().unwrap().push(line);
        }
    });
    let mut c = Checks::default();
    if ready_rx.recv_timeout(Duration::from_secs(30)).is_err() {
        let _ = daemon.kill();
        let _ = daemon.wait();
        c.check("daemon starts recording", false, "");
        return c.failed;
    }
    let _ = fs::write("/tmp/k11t-go", "");
    let output = mode.command().output();
    let early_pid = early.as_mut().map(|child| {
        let _ = child.wait();
        child.id()
    });
    let (out, err) = output
        .as_ref()
        .map(|o| {
            (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        })
        .unwrap_or_default();
    print!("{out}{err}");
    thread::sleep(Duration::from_millis(1000));
    unsafe { libc::kill(daemon.id() as i32, libc::SIGINT) };
    let _ = daemon.wait();
    let _ = reader.join();
    let log = log.lock().unwrap().join("\n");
    let records: Vec<Value> = fs::read_to_string("/tmp/out.jsonl")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let r = Record { all: &records };
    println!("== {} records ==", records.len());
    // Reported, not required to be 0: the kernel decides when to skip.
    let skipped = (counter(&log, "skipped"), counter(&log, "skipped_file_open"));
    c.check(
        "runs the kernel skipped are counted",
        matches!(skipped, (Some(_), Some(_))),
        &format!("{skipped:?}"),
    );

    match mode {
        Mode::Audit => {
            c.check(
                "no user-memory read failures",
                log.contains("read_failed=0"),
                "",
            );
            c.check(
                "threads are not processes",
                r.count(|m| m.starts_with("agent fork ")) == 5,
                &format!("{} forks", r.count(|m| m.starts_with("agent fork "))),
            );
            c.check(
                "failed exec recorded",
                r.has("agent exec /nonexistent: ENOENT"),
                "",
            );
            // Without the LSM the dirfd-relative open keeps its `..`.
            let opens_of_a = r.count(|m| m == "agent open /tmp/k11t/a" || m.ends_with("../a"));
            c.check(
                "one record per open",
                opens_of_a == 3,
                &format!("{opens_of_a}"),
            );
            c.check(
                "relative path resolved",
                r.has("agent open /tmp/k11t/missing-relative: ENOENT"),
                "",
            );
            c.check(
                "non-blocking connect is not a failure",
                r.count(|m| m.starts_with("agent connect 127.0.0.1:") && !m.contains(": E")) == 2,
                "",
            );
            c.check(
                "unix connect recorded",
                r.has("agent connect unix:/tmp/k11t/sock"),
                "",
            );
            c.check(
                "a process in a container names it",
                r.find("agent open /tmp/k11t/contained-open: ENOENT")
                    .is_some_and(|v| {
                        v["container"]["uid"] == CONTAINER_ID
                            && v["container"]["runtime"] == "podman"
                    }),
                "",
            );
            c.check(
                "a host process names no container",
                r.find("agent open /tmp/k11t/a")
                    .is_some_and(|v| v.get("container").is_none()),
                "",
            );
            for m in [
                "agent rename /tmp/k11t/a to /tmp/k11t/b",
                "agent chmod 600 /tmp/k11t/b",
                "agent symlink /tmp/k11t/l to b",
                "agent unlink /tmp/k11t/b",
            ] {
                c.check(&format!("metadata syscall: {m}"), r.has(m), "");
            }
            if kernel.lsm {
                c.check(
                    "deny rule matches the directory",
                    r.has("agent open /tmp/k11t/secret/key: deny rule matched (audit)"),
                    "",
                );
                c.check(
                    "deny rule spares the sibling",
                    r.has("agent open /tmp/k11t/secret-sibling"),
                    "",
                );
            }
            if kernel.group_dead {
                let root = r.root_of("agent open /tmp/k11t/a");
                c.check(
                    "exec from a non-leader thread keeps its tree",
                    r.root_of("agent open /tmp/k11t/after-exec-open: ENOENT") == root,
                    "",
                );
                c.check(
                    "a leader leaving first keeps its process",
                    r.root_of("agent open /tmp/k11t/after-leader-open: ENOENT") == root,
                    "",
                );
            }
        }
        Mode::Enforce => {
            let denied = r.find("agent open /tmp/k11t/secret/key: denied by k11");
            c.check(
                "denied open fails with EPERM",
                denied.is_some_and(|v| v["status_code"] == "EPERM" && v["disposition_id"] == 2),
                "",
            );
            c.check(
                "sibling not denied",
                r.has("agent open /tmp/k11t/secret-sibling"),
                "",
            );
        }
        Mode::Session => {
            c.check("the summary names the directory", err.contains(" in /"), "");
            c.check(
                "k11 run prints a summary",
                err.contains("k11: demo recorded for"),
                "",
            );
            c.check(
                "session recorded with no watched binary",
                r.has("agent exec /agent"),
                "",
            );
            let roots: std::collections::BTreeSet<u64> = records
                .iter()
                .filter_map(|v| v["unmapped"]["root_pid"].as_u64())
                .collect();
            c.check(
                "only the session is recorded",
                roots.len() == 1,
                &format!("{roots:?}"),
            );
        }
        Mode::Seed => {
            c.check(
                "a process running before the daemon is found by --watch",
                r.root_of("agent open /tmp/k11t-late-open: ENOENT")
                    .and_then(|v| v.as_u64())
                    == early_pid.map(u64::from),
                "",
            );
        }
        Mode::Loss => {
            c.check(
                "ring overflow leaves a loss record",
                records
                    .iter()
                    .any(|v| v["class_uid"] == 0 && v["count"].as_u64() > Some(0)),
                "",
            );
        }
        Mode::Smoke => {
            c.check(
                "dashboard API smoke test",
                out.contains("all checks passed"),
                "",
            );
            // The smoke test set both with the token, restoring the names.
            let kept = fs::read_to_string("/var/lib/k11/state.toml").unwrap_or_default();
            c.check(
                "dashboard changes are kept for the next start",
                kept.contains("binaries = [\"agent\"]") && kept.contains("[policy]"),
                &kept
                    .lines()
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
    }
    if c.failed > 0 {
        println!("-- what the record holds:");
        for v in records.iter().take(80) {
            println!("   {}", v["message"].as_str().unwrap_or("?"));
        }
        if let Some(line) = log
            .lines()
            .find(|l| l.contains("probe counters at shutdown"))
        {
            println!("-- {line}");
        }
    }
    c.failed
}

#[derive(Default)]
struct Checks {
    failed: usize,
}

impl Checks {
    fn check(&mut self, label: &str, ok: bool, detail: &str) {
        self.failed += usize::from(!ok);
        let detail = if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        };
        println!("{}  {label}{detail}", if ok { "PASS" } else { "FAIL" });
    }
}

struct Record<'a> {
    all: &'a [Value],
}

impl Record<'_> {
    fn find(&self, message: &str) -> Option<&Value> {
        self.all.iter().find(|v| v["message"] == message)
    }

    fn has(&self, message: &str) -> bool {
        self.find(message).is_some()
    }

    fn count(&self, keep: impl Fn(&str) -> bool) -> usize {
        self.all
            .iter()
            .filter(|v| v["message"].as_str().is_some_and(&keep))
            .count()
    }

    fn root_of(&self, message: &str) -> Option<Value> {
        self.find(message)
            .map(|v| v["unmapped"]["root_pid"].clone())
    }
}

/// A probe counter from the daemon's shutdown line.
fn counter(log: &str, name: &str) -> Option<u64> {
    let at = log.find(&format!(" {name}="))? + name.len() + 2;
    log[at..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mount(src: &str, target: &str, fstype: &str) {
    let _ = fs::create_dir_all(target);
    let r = unsafe {
        libc::mount(
            c(src).as_ptr(),
            c(target).as_ptr(),
            c(fstype).as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if r != 0 {
        println!(
            "init: mount {fstype} on {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn lo_up() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr);
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr);
        libc::close(fd);
    }
}

fn cmdline_has(flag: &str) -> bool {
    fs::read_to_string("/proc/cmdline").is_ok_and(|s| s.split_whitespace().any(|w| w == flag))
}

fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

// ---------------------------------------------------------------------------
// /agent scenarios
// ---------------------------------------------------------------------------

fn agent(scenario: &str) {
    match scenario {
        "all" => {
            threads();
            files();
            net();
            for sub in ["failexec", "exec-thread", "leader-exit", "contained"] {
                let _ = Command::new("/agent").arg(sub).status();
            }
        }
        "failexec" => {
            let _ = Command::new("/nonexistent").status();
        }
        // exec from a non-leader thread: the kernel kills the leader and
        // hands its pid to this thread (de_thread).
        "exec-thread" => {
            thread::spawn(|| {
                let _ = Command::new("/agent").arg("after-exec").exec();
            });
            thread::sleep(Duration::from_secs(5));
        }
        // What a runtime does to a container's first process.
        "contained" => {
            let cgroup = format!("/sys/fs/cgroup/libpod-{CONTAINER_ID}.scope");
            let _ = fs::create_dir(&cgroup);
            fs::write(format!("{cgroup}/cgroup.procs"), "0").expect("join the container cgroup");
            let _ = File::open("/tmp/k11t/contained-open");
        }
        "after-exec" => {
            let _ = File::open("/tmp/k11t/after-exec-open");
        }
        // The leader leaves first; the process lives on in its thread.
        "leader-exit" => {
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(200));
                let _ = File::open("/tmp/k11t/after-leader-open");
                unsafe { libc::exit(0) };
            });
            // SYS_exit ends only the calling thread (pthread_exit would unwind).
            unsafe { libc::syscall(libc::SYS_exit, 0) };
        }
        // Waits for init's go: the daemon is recording by then.
        "late" => {
            for _ in 0..600 {
                if fs::metadata("/tmp/k11t-go").is_ok() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = File::open("/tmp/k11t-late-open");
        }
        "noop" => {}
        // Threads, so tasks on one CPU contend for the same programs.
        "burst" => {
            let workers: Vec<_> = (0..8)
                .map(|t| {
                    thread::spawn(move || {
                        for i in 0..2500 {
                            let _ = File::open(format!("/tmp/burst-{t}-{i}"));
                        }
                    })
                })
                .collect();
            for w in workers {
                let _ = w.join();
            }
        }
        "smoke" => {
            let out = Command::new("/usr/bin/node")
                .args(["--experimental-transform-types", "/smoke/smoke.mts"])
                .current_dir("/smoke")
                .env("PATH", "/usr/bin:/bin")
                .output();
            if let Ok(o) = out {
                print!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
        other => println!("agent: unknown scenario {other}"),
    }
}

fn threads() {
    let handles: Vec<_> = (0..3)
        .map(|_| {
            thread::spawn(|| {
                let _ = File::open("/etc/hostname");
                thread::sleep(Duration::from_millis(50));
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
}

fn files() {
    fs::create_dir_all("/tmp/k11t/sub").unwrap();
    fs::create_dir_all("/tmp/k11t/secret").unwrap();
    fs::write("/tmp/k11t/a", "x").unwrap();
    std::env::set_current_dir("/tmp/k11t").unwrap();
    let _ = File::open("a");
    let _ = File::open("missing-relative");
    unsafe {
        let dfd = libc::open(
            c("/tmp/k11t/sub").as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        );
        let fd = libc::openat(dfd, c("../a").as_ptr(), libc::O_RDONLY);
        libc::close(fd);
        libc::openat(dfd, c("missing-at").as_ptr(), libc::O_RDONLY);
        libc::close(dfd);
    }
    fs::rename("a", "b").unwrap();
    fs::set_permissions("b", fs::Permissions::from_mode(0o600)).unwrap();
    symlink("b", "l").unwrap();
    fs::remove_file("l").unwrap();
    fs::remove_file("b").unwrap();
    let _ = fs::write("/tmp/k11t/secret/key", "k");
    let _ = fs::write("/tmp/k11t/secret-sibling", "s");
}

fn net() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _ = TcpStream::connect(addr);
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        libc::connect(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        libc::close(fd);
    }
    let _listener = UnixListener::bind("/tmp/k11t/sock").unwrap();
    let _ = UnixStream::connect("/tmp/k11t/sock");
}
