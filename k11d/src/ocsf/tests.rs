//! OCSF mapping tests. Assertions cover:
//!   - correct class_uid / activity_id per event type (OCSF 1.1.0 authoritative)
//!   - envelope completeness (time_dt, message, observables, enrichments,
//!     src_endpoint, actor, per-agent correlation_uid)
//!   - risk scoring + severity promotion (sensitive path, external addr, denied openat)
//!   - enrichment pass-through (hostname, country, asn, username)

use serde_json::Value;

use super::record;
use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::{Event, EventMeta, Payload, Policy};

const HOST: &str = "testhost";

/// The record as the SIEM sees it.
fn to_ocsf(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    serde_json::to_value(record(event, enriched, hostname)).unwrap()
}

fn ev(pid: u32, root_pid: u32, uid: u32, comm: &str, ts: u64, payload: Payload) -> Event {
    Event {
        meta: EventMeta {
            pid,
            root_pid,
            uid,
            comm: comm.into(),
            timestamp_ns: ts,
        },
        payload,
    }
}

fn plain() -> EnrichedEvent {
    EnrichedEvent::default()
}

fn with_addr(hostname: Option<&str>, country: Option<&str>, asn: Option<&str>) -> EnrichedEvent {
    EnrichedEvent {
        addr: Some(EnrichedAddr {
            hostname: hostname.map(str::to_owned),
            country: country.map(str::to_owned),
            city: None,
            asn: asn.map(str::to_owned),
        }),
        username: None,
    }
}

fn with_username(name: &str) -> EnrichedEvent {
    EnrichedEvent {
        addr: None,
        username: Some(name.to_owned()),
    }
}

fn risk_score(v: &Value) -> u64 {
    v["enrichments"][0]["value"].as_u64().unwrap()
}

fn observable_values(v: &Value) -> Vec<&str> {
    v["observables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["value"].as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// Process Activity
// ---------------------------------------------------------------------------

#[test]
fn execve_launch() {
    let e = ev(
        100,
        1,
        1000,
        "bash",
        1_000_000_000,
        Payload::Execve {
            filename: "/usr/bin/bash".into(),
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 1); // Launch
    assert_eq!(v["type_uid"], 1007 * 100 + 1);
    assert_eq!(v["severity_id"], 1);
    assert_eq!(v["status_id"], 1);
    assert_eq!(v["disposition_id"], 1);
    assert_eq!(v["process"]["pid"], 100);
    assert_eq!(v["process"]["cmd_line"], "/usr/bin/bash");
    assert_eq!(v["actor"]["process"]["pid"], 100);
    assert_eq!(v["metadata"]["correlation_uid"], "k11-agent-1");
    assert_eq!(v["time"], 1000);
    assert_eq!(v["time_dt"], "1970-01-01T00:00:01.000Z");
    assert!(v["message"].as_str().unwrap().contains("bash"));
    assert!(observable_values(&v).contains(&"bash"));
    assert!(observable_values(&v).contains(&"/usr/bin/bash"));
}

#[test]
fn execve_includes_username_when_enriched() {
    let e = ev(
        100,
        1,
        1000,
        "bash",
        1_000_000_000,
        Payload::Execve {
            filename: "/usr/bin/bash".into(),
        },
    );
    let v = to_ocsf(&e, &with_username("alice"), HOST);
    assert_eq!(v["process"]["user"]["name"], "alice");
    assert_eq!(v["process"]["user"]["uid"], "1000");
    assert_eq!(v["actor"]["process"]["user"]["name"], "alice");
    assert!(observable_values(&v).contains(&"alice"));
}

#[test]
fn execve_username_omitted_when_missing() {
    let e = ev(
        100,
        1,
        9999,
        "bash",
        1_000_000_000,
        Payload::Execve {
            filename: "/usr/bin/bash".into(),
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["process"]["user"]["uid"], "9999");
    assert!(v["process"]["user"].get("name").is_none());
}

#[test]
fn fork_is_launch() {
    let e = ev(
        1,
        1,
        1000,
        "bash",
        1_000_000_000,
        Payload::Fork { child_pid: 2 },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 1);
    assert_eq!(v["process"]["pid"], 2);
    assert_eq!(v["actor"]["process"]["pid"], 1);
}

#[test]
fn exit_is_terminate() {
    let e = ev(42, 1, 1000, "node", 1_000_000_000, Payload::Exit);
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 2);
    assert_eq!(v["process"]["pid"], 42);
}

#[test]
fn ptrace_is_inject() {
    let e = ev(
        100,
        1,
        1000,
        "strace",
        1_000_000_000,
        Payload::Ptrace {
            request: 16,
            target_pid: 200,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 4); // Inject (OCSF 1.1.0 authoritative)
    assert_eq!(v["process"]["pid"], 200);
    assert_eq!(v["actor"]["process"]["pid"], 100);
    assert!(v["message"].as_str().unwrap().contains("request=16"));
}

// ---------------------------------------------------------------------------
// File System Activity
// ---------------------------------------------------------------------------

#[test]
fn openat_read() {
    let e = ev(
        10,
        1,
        1000,
        "cat",
        1_000_000_000,
        Payload::Openat {
            filename: "/etc/hosts".into(),
            flags: 0,
            ret: 3,
            policy: Policy::Allowed,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 2); // Read
    assert_eq!(v["file"]["path"], "/etc/hosts");
    assert_eq!(v["file"]["name"], "hosts");
    assert_eq!(v["actor"]["process"]["pid"], 10);
}

#[test]
fn openat_write_is_update() {
    let e = ev(
        10,
        1,
        1000,
        "tee",
        1_000_000_000,
        Payload::Openat {
            filename: "/tmp/out.txt".into(),
            flags: 0x1,
            ret: 4,
            policy: Policy::Allowed,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["activity_id"], 3); // Update (Write)
}

#[test]
fn openat_create_only_is_create() {
    let e = ev(
        10,
        1,
        1000,
        "touch",
        1_000_000_000,
        Payload::Openat {
            filename: "/tmp/new".into(),
            flags: 0x40, // O_CREAT only, no write
            ret: 3,
            policy: Policy::Allowed,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["activity_id"], 1); // Create
}

#[test]
fn openat_denied_sensitive_is_critical() {
    let e = ev(
        10,
        1,
        1000,
        "cat",
        1_000_000_000,
        Payload::Openat {
            filename: "/home/user/.ssh/id_rsa".into(),
            flags: 0,
            ret: -1,
            policy: Policy::Denied,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["disposition_id"], 2);
    assert_eq!(v["severity_id"], 5); // denied (10) + sensitive (3) = 13: CRITICAL
    assert!(risk_score(&v) >= 13);
}

#[test]
fn openat_audited_is_detected_not_blocked() {
    let e = ev(
        10,
        1,
        1000,
        "cat",
        1_000_000_000,
        Payload::Openat {
            filename: "/tmp/watched".into(),
            flags: 0,
            ret: 3,
            policy: Policy::Audited,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["status_id"], 1); // the open succeeded
    assert_eq!(v["disposition_id"], 15); // Detected
    assert_eq!(v["severity_id"], 4); // audited (6): HIGH
    assert_eq!(risk_score(&v), 6);
    assert_eq!(v["unmapped"]["policy"], "audited");
    assert!(v["message"].as_str().unwrap().contains("audit"));
}

#[test]
fn unlink_is_delete() {
    let e = ev(
        50,
        1,
        1000,
        "rm",
        1_000_000_000,
        Payload::Unlink {
            filename: "/tmp/junk".into(),
            flags: 0,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 4); // Delete (OCSF 1.1.0 authoritative)
    assert_eq!(v["file"]["path"], "/tmp/junk");
}

#[test]
fn rename_uses_file_result() {
    let e = ev(
        60,
        1,
        1000,
        "mv",
        1_000_000_000,
        Payload::Rename {
            old_path: "/tmp/a".into(),
            new_path: "/tmp/b".into(),
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 5); // Rename
    assert_eq!(v["file"]["path"], "/tmp/a");
    assert_eq!(v["file_result"]["path"], "/tmp/b");
    // No stuffing in unmapped for fields OCSF models
    assert!(v.get("unmapped").is_none());
}

#[test]
fn chmod_is_set_attributes() {
    let e = ev(
        70,
        1,
        1000,
        "chmod",
        1_000_000_000,
        Payload::Chmod {
            filename: "/tmp/script.sh".into(),
            mode: 0o755,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 6); // Set Attributes (OCSF 1.1.0 authoritative)
    assert_eq!(v["file"]["attributes"], "755");
    assert_eq!(v["file"]["mode"], 0o755);
}

#[test]
fn chown_is_set_security() {
    let e = ev(
        80,
        1,
        1000,
        "chown",
        1_000_000_000,
        Payload::Chown {
            filename: "/tmp/file".into(),
            owner_uid: 1000,
            owner_gid: 1000,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 7); // Set Security
    assert_eq!(v["file"]["owner"]["uid"], "1000");
    // OCSF 1.1.0 has no file.group — gid lives in unmapped (legitimate)
    assert_eq!(v["unmapped"]["owner_gid"], 1000);
}

#[test]
fn symlink_is_create() {
    let e = ev(
        90,
        1,
        1000,
        "ln",
        1_000_000_000,
        Payload::Symlink {
            target: "/usr/bin/python3".into(),
            linkpath: "/usr/local/bin/python".into(),
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 1); // Create
    assert_eq!(v["file"]["path"], "/usr/local/bin/python");
    assert_eq!(v["file"]["target"], "/usr/bin/python3");
}

// ---------------------------------------------------------------------------
// Network Activity
// ---------------------------------------------------------------------------

#[test]
fn connect_is_open_outbound() {
    let e = ev(
        20,
        1,
        1000,
        "curl",
        1_000_000_000,
        Payload::Connect {
            addr: "93.184.216.34".into(),
            port: 443,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1); // Open (OCSF 4001 has no Connect)
    assert_eq!(v["connection_info"]["direction_id"], 2); // Outbound
    assert_eq!(v["dst_endpoint"]["ip"], "93.184.216.34");
    assert_eq!(v["dst_endpoint"]["port"], 443);
}

#[test]
fn connect_enrichment_propagates() {
    let e = ev(
        20,
        1,
        1000,
        "curl",
        1_000_000_000,
        Payload::Connect {
            addr: "93.184.216.34".into(),
            port: 443,
            ret: 0,
        },
    );
    let enriched = with_addr(Some("example.com"), Some("US"), Some("AS15133 CLOUDFLARE"));
    let v = to_ocsf(&e, &enriched, HOST);
    assert_eq!(v["dst_endpoint"]["hostname"], "example.com");
    assert_eq!(v["dst_endpoint"]["location"]["country"], "US");
    assert_eq!(
        v["dst_endpoint"]["autonomous_system"]["name"],
        "AS15133 CLOUDFLARE"
    );
    assert!(observable_values(&v).contains(&"example.com"));
    assert!(observable_values(&v).contains(&"93.184.216.34"));
    assert!(v["message"].as_str().unwrap().contains("example.com"));
}

#[test]
fn connect_external_bumps_risk() {
    let e = ev(
        20,
        1,
        1000,
        "curl",
        1_000_000_000,
        Payload::Connect {
            addr: "8.8.8.8".into(),
            port: 443,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(risk_score(&v), 2); // external contributes 2
    assert_eq!(v["severity_id"], 2); // LOW
}

#[test]
fn unix_connect_has_domain() {
    let e = ev(
        30,
        1,
        1000,
        "node",
        1_000_000_000,
        Payload::UnixConnect {
            path: "/run/dbus/system_bus_socket".into(),
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1); // Open
    assert_eq!(v["dst_endpoint"]["domain"], "/run/dbus/system_bus_socket");
    assert_eq!(v["connection_info"]["protocol_name"], "unix");
}

#[test]
fn bind_is_open_inbound() {
    let e = ev(
        40,
        1,
        1000,
        "nginx",
        1_000_000_000,
        Payload::Bind {
            addr: "0.0.0.0".into(),
            port: 8080,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1);
    assert_eq!(v["connection_info"]["direction_id"], 1); // Inbound
    assert_eq!(v["dst_endpoint"]["port"], 8080);
}

#[test]
fn listen_is_open_inbound() {
    let e = ev(
        40,
        1,
        1000,
        "nginx",
        1_000_000_000,
        Payload::Listen {
            backlog: 128,
            ret: 0,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1);
    assert_eq!(v["connection_info"]["direction_id"], 1);
    assert_eq!(v["unmapped"]["backlog"], 128);
}

// ---------------------------------------------------------------------------
// Envelope / risk / observables
// ---------------------------------------------------------------------------

#[test]
fn envelope_has_expected_fields() {
    let e = ev(1, 7, 0, "init", 5_500_000_000, Payload::Exit);
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(v["metadata"]["version"], "1.1.0");
    assert_eq!(v["metadata"]["product"]["name"], "k11");
    assert_eq!(
        v["metadata"]["product"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(v["metadata"]["correlation_uid"], "k11-agent-7");
    assert_eq!(v["device"]["hostname"], HOST);
    assert_eq!(v["src_endpoint"]["hostname"], HOST);
    assert_eq!(v["actor"]["process"]["pid"], 1);
    assert_eq!(v["actor"]["process"]["name"], "init");
    assert_eq!(v["actor"]["process"]["user"]["uid"], "0");
    assert_eq!(v["time"], 5500);
    assert!(v["time_dt"].as_str().unwrap().ends_with("Z"));
    assert!(!v["message"].as_str().unwrap().is_empty());
    assert!(v["observables"].is_array());
    assert_eq!(v["enrichments"][0]["name"], "k11.risk_score");
    assert_eq!(v["enrichments"][0]["provider"], "k11");
}

#[test]
fn risk_zero_for_benign_event() {
    let e = ev(
        10,
        1,
        1000,
        "cat",
        1_000_000_000,
        Payload::Openat {
            filename: "/tmp/harmless.txt".into(),
            flags: 0,
            ret: 3,
            policy: Policy::Allowed,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(risk_score(&v), 0);
    assert_eq!(v["severity_id"], 1);
}

#[test]
fn risk_sensitive_path_is_medium() {
    let e = ev(
        10,
        1,
        1000,
        "cat",
        1_000_000_000,
        Payload::Openat {
            filename: "/etc/shadow".into(),
            flags: 0,
            ret: 3,
            policy: Policy::Allowed,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    assert_eq!(risk_score(&v), 3);
    assert_eq!(v["severity_id"], 3); // MEDIUM
}

#[test]
fn error_without_deny_scores_low() {
    let e = ev(
        20,
        1,
        1000,
        "curl",
        1_000_000_000,
        Payload::Connect {
            addr: "127.0.0.1".into(),
            port: 80,
            ret: -111,
        },
    );
    let v = to_ocsf(&e, &plain(), HOST);
    // error (1) + no sensitive + loopback (not external) = 1: LOW
    assert_eq!(risk_score(&v), 1);
    assert_eq!(v["severity_id"], 2);
    assert_eq!(v["status_id"], 2);
    assert_eq!(v["disposition_id"], 1); // allowed (not denied, just failed)
}

/// Dumps a pretty-printed sample of every event type. Useful for eyeballing
/// what the SIEM receives. Run with: `cargo test -p k11d ocsf::tests::print_samples -- --ignored --nocapture`
#[test]
#[ignore]
fn print_samples() {
    let ts: u64 = 1_745_000_000_000_000_000;
    let enriched_conn = EnrichedEvent {
        addr: Some(EnrichedAddr {
            hostname: Some("one.one.one.one".into()),
            country: Some("US".into()),
            city: None,
            asn: Some("AS13335 CLOUDFLARENET".into()),
        }),
        username: None,
    };
    let enriched_user = EnrichedEvent {
        addr: None,
        username: Some("alice".into()),
    };

    let samples: Vec<(&str, EnrichedEvent, Event)> = vec![
        (
            "execve (sensitive binary)",
            enriched_user.clone(),
            ev(
                1234,
                1234,
                1000,
                "wget",
                ts,
                Payload::Execve {
                    filename: "/usr/bin/wget".into(),
                },
            ),
        ),
        (
            "openat (read sensitive file)",
            EnrichedEvent::default(),
            ev(
                1234,
                1234,
                1000,
                "cat",
                ts + 1_000_000,
                Payload::Openat {
                    filename: "/etc/shadow".into(),
                    flags: 0,
                    ret: 3,
                    policy: Policy::Allowed,
                },
            ),
        ),
        (
            "connect (external, enriched)",
            enriched_conn,
            ev(
                1234,
                1234,
                1000,
                "curl",
                ts + 2_000_000,
                Payload::Connect {
                    addr: "1.1.1.1".into(),
                    port: 443,
                    ret: 0,
                },
            ),
        ),
        (
            "ptrace",
            EnrichedEvent::default(),
            ev(
                1234,
                1234,
                1000,
                "strace",
                ts + 3_000_000,
                Payload::Ptrace {
                    request: 16,
                    target_pid: 9999,
                    ret: 0,
                },
            ),
        ),
    ];

    for (label, enriched, event) in samples {
        let v = to_ocsf(&event, &enriched, "dev-laptop");
        println!("\n=== {label} ===");
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    }
}

#[test]
fn unmapped_absent_for_events_that_dont_need_it() {
    // Regression: execve, openat, unlink, rename, symlink should have no 'unmapped' key
    // (their fields are all natively modeled by OCSF).
    let events = [
        ev(
            1,
            1,
            0,
            "x",
            1_000_000_000,
            Payload::Execve {
                filename: "/x".into(),
            },
        ),
        ev(
            1,
            1,
            0,
            "x",
            1_000_000_000,
            Payload::Openat {
                filename: "/x".into(),
                flags: 0,
                ret: 3,
                policy: Policy::Allowed,
            },
        ),
        ev(
            1,
            1,
            0,
            "x",
            1_000_000_000,
            Payload::Unlink {
                filename: "/x".into(),
                flags: 0,
                ret: 0,
            },
        ),
        ev(
            1,
            1,
            0,
            "x",
            1_000_000_000,
            Payload::Rename {
                old_path: "/a".into(),
                new_path: "/b".into(),
                ret: 0,
            },
        ),
        ev(
            1,
            1,
            0,
            "x",
            1_000_000_000,
            Payload::Symlink {
                target: "/t".into(),
                linkpath: "/l".into(),
                ret: 0,
            },
        ),
    ];
    for e in &events {
        let v = to_ocsf(e, &plain(), HOST);
        assert!(
            v.get("unmapped").is_none(),
            "unexpected unmapped on {}",
            v["message"]
        );
    }
}
