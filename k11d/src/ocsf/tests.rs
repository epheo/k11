//! OCSF mapping tests. Assertions cover:
//!   - correct class_uid / activity_id per event type (OCSF 1.1.0 authoritative)
//!   - envelope completeness (time_dt, message, observables, enrichments, src_endpoint)
//!   - risk scoring + severity promotion (sensitive path, external addr, denied openat)
//!   - enrichment pass-through (hostname, country, asn, username)

use serde_json::Value;

use super::to_ocsf;
use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::Event;

const HOST: &str = "testhost";

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
    let ev = Event::Execve {
        pid: 100, root_pid: 1, uid: 1000,
        comm: "bash".into(), filename: "/usr/bin/bash".into(),
        timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 1); // Launch
    assert_eq!(v["type_uid"], 1007 * 100 + 1);
    assert_eq!(v["severity_id"], 1);
    assert_eq!(v["status_id"], 1);
    assert_eq!(v["disposition_id"], 1);
    assert_eq!(v["process"]["pid"], 100);
    assert_eq!(v["process"]["cmd_line"], "/usr/bin/bash");
    assert_eq!(v["actor"]["process"]["pid"], 1);
    assert_eq!(v["time"], 1000);
    assert_eq!(v["time_dt"], "1970-01-01T00:00:01.000Z");
    assert!(v["message"].as_str().unwrap().contains("bash"));
    assert!(observable_values(&v).contains(&"bash"));
    assert!(observable_values(&v).contains(&"/usr/bin/bash"));
}

#[test]
fn execve_includes_username_when_enriched() {
    let ev = Event::Execve {
        pid: 100, root_pid: 1, uid: 1000,
        comm: "bash".into(), filename: "/usr/bin/bash".into(),
        timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &with_username("alice"), HOST);
    assert_eq!(v["process"]["user"]["name"], "alice");
    assert_eq!(v["process"]["user"]["uid"], "1000");
    assert!(observable_values(&v).contains(&"alice"));
}

#[test]
fn execve_username_omitted_when_missing() {
    let ev = Event::Execve {
        pid: 100, root_pid: 1, uid: 9999,
        comm: "bash".into(), filename: "/usr/bin/bash".into(),
        timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["process"]["user"]["uid"], "9999");
    assert!(v["process"]["user"].get("name").is_none());
}

#[test]
fn fork_is_launch() {
    let ev = Event::Fork {
        parent_pid: 1, child_pid: 2,
        comm: "bash".into(), timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 1);
    assert_eq!(v["process"]["pid"], 2);
    assert_eq!(v["actor"]["process"]["pid"], 1);
}

#[test]
fn exit_is_terminate() {
    let ev = Event::Exit {
        pid: 42, comm: "node".into(), timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1007);
    assert_eq!(v["activity_id"], 2);
    assert_eq!(v["process"]["pid"], 42);
}

#[test]
fn ptrace_is_inject() {
    let ev = Event::Ptrace {
        pid: 100, comm: "strace".into(),
        request: 16, target_pid: 200, ret: 0,
        timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
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
    let ev = Event::Openat {
        pid: 10, comm: "cat".into(),
        filename: "/etc/hosts".into(),
        flags: 0, ret: 3,
        timestamp_ns: 1_000_000_000, denied: false,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 2); // Read
    assert_eq!(v["file"]["path"], "/etc/hosts");
    assert_eq!(v["file"]["name"], "hosts");
}

#[test]
fn openat_write_is_update() {
    let ev = Event::Openat {
        pid: 10, comm: "tee".into(),
        filename: "/tmp/out.txt".into(),
        flags: 0x1, ret: 4,
        timestamp_ns: 1_000_000_000, denied: false,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["activity_id"], 3); // Update (Write)
}

#[test]
fn openat_create_only_is_create() {
    let ev = Event::Openat {
        pid: 10, comm: "touch".into(),
        filename: "/tmp/new".into(),
        flags: 0x40, // O_CREAT only, no write
        ret: 3,
        timestamp_ns: 1_000_000_000, denied: false,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["activity_id"], 1); // Create
}

#[test]
fn openat_denied_sensitive_is_critical() {
    let ev = Event::Openat {
        pid: 10, comm: "cat".into(),
        filename: "/home/user/.ssh/id_rsa".into(),
        flags: 0, ret: -1,
        timestamp_ns: 1_000_000_000, denied: true,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["disposition_id"], 2);
    assert_eq!(v["severity_id"], 5); // denied (10) + sensitive (3) = 13 → CRITICAL
    assert!(risk_score(&v) >= 13);
}

#[test]
fn unlink_is_delete() {
    let ev = Event::Unlink {
        pid: 50, comm: "rm".into(),
        filename: "/tmp/junk".into(),
        flags: 0, ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 4); // Delete (OCSF 1.1.0 authoritative)
    assert_eq!(v["file"]["path"], "/tmp/junk");
}

#[test]
fn rename_uses_file_result() {
    let ev = Event::Rename {
        pid: 60, comm: "mv".into(),
        old_path: "/tmp/a".into(), new_path: "/tmp/b".into(),
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 5); // Rename
    assert_eq!(v["file"]["path"], "/tmp/a");
    assert_eq!(v["file_result"]["path"], "/tmp/b");
    // No stuffing in unmapped for fields OCSF models
    assert!(v.get("unmapped").is_none());
}

#[test]
fn chmod_is_set_attributes() {
    let ev = Event::Chmod {
        pid: 70, comm: "chmod".into(),
        filename: "/tmp/script.sh".into(),
        mode: 0o755, ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 6); // Set Attributes (OCSF 1.1.0 authoritative)
    assert_eq!(v["file"]["attributes"], "755");
    assert_eq!(v["file"]["mode"], 0o755);
}

#[test]
fn chown_is_set_security() {
    let ev = Event::Chown {
        pid: 80, comm: "chown".into(),
        filename: "/tmp/file".into(),
        owner_uid: 1000, owner_gid: 1000,
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 1001);
    assert_eq!(v["activity_id"], 7); // Set Security
    assert_eq!(v["file"]["owner"]["uid"], "1000");
    // OCSF 1.1.0 has no file.group — gid lives in unmapped (legitimate)
    assert_eq!(v["unmapped"]["owner_gid"], 1000);
}

#[test]
fn symlink_is_create() {
    let ev = Event::Symlink {
        pid: 90, comm: "ln".into(),
        target: "/usr/bin/python3".into(),
        linkpath: "/usr/local/bin/python".into(),
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
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
    let ev = Event::Connect {
        pid: 20, comm: "curl".into(),
        addr: "93.184.216.34".into(), port: 443,
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1); // Open (OCSF 4001 has no Connect)
    assert_eq!(v["connection_info"]["direction_id"], 2); // Outbound
    assert_eq!(v["dst_endpoint"]["ip"], "93.184.216.34");
    assert_eq!(v["dst_endpoint"]["port"], 443);
}

#[test]
fn connect_enrichment_propagates() {
    let ev = Event::Connect {
        pid: 20, comm: "curl".into(),
        addr: "93.184.216.34".into(), port: 443,
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let enriched = with_addr(Some("example.com"), Some("US"), Some("AS15133 CLOUDFLARE"));
    let v = to_ocsf(&ev, &enriched, HOST);
    assert_eq!(v["dst_endpoint"]["hostname"], "example.com");
    assert_eq!(v["dst_endpoint"]["location"]["country"], "US");
    assert_eq!(v["dst_endpoint"]["autonomous_system"]["name"], "AS15133 CLOUDFLARE");
    assert!(observable_values(&v).contains(&"example.com"));
    assert!(observable_values(&v).contains(&"93.184.216.34"));
    assert!(v["message"].as_str().unwrap().contains("example.com"));
}

#[test]
fn connect_external_bumps_risk() {
    let ev = Event::Connect {
        pid: 20, comm: "curl".into(),
        addr: "8.8.8.8".into(), port: 443,
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(risk_score(&v), 2); // external contributes 2
    assert_eq!(v["severity_id"], 2); // LOW
}

#[test]
fn unix_connect_has_domain() {
    let ev = Event::UnixConnect {
        pid: 30, comm: "node".into(),
        path: "/run/dbus/system_bus_socket".into(),
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1); // Open
    assert_eq!(v["dst_endpoint"]["domain"], "/run/dbus/system_bus_socket");
    assert_eq!(v["connection_info"]["protocol_name"], "unix");
}

#[test]
fn bind_is_open_inbound() {
    let ev = Event::Bind {
        pid: 40, comm: "nginx".into(),
        addr: "0.0.0.0".into(), port: 8080,
        ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["class_uid"], 4001);
    assert_eq!(v["activity_id"], 1);
    assert_eq!(v["connection_info"]["direction_id"], 1); // Inbound
    assert_eq!(v["dst_endpoint"]["port"], 8080);
}

#[test]
fn listen_is_open_inbound() {
    let ev = Event::Listen {
        pid: 40, comm: "nginx".into(),
        backlog: 128, ret: 0, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
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
    let ev = Event::Exit {
        pid: 1, comm: "init".into(), timestamp_ns: 5_500_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(v["metadata"]["version"], "1.1.0");
    assert_eq!(v["metadata"]["product"]["name"], "k11");
    assert_eq!(v["metadata"]["product"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["device"]["hostname"], HOST);
    assert_eq!(v["src_endpoint"]["hostname"], HOST);
    assert_eq!(v["time"], 5500);
    assert!(v["time_dt"].as_str().unwrap().ends_with("Z"));
    assert!(!v["message"].as_str().unwrap().is_empty());
    assert!(v["observables"].is_array());
    assert_eq!(v["enrichments"][0]["name"], "k11.risk_score");
    assert_eq!(v["enrichments"][0]["provider"], "k11");
}

#[test]
fn risk_zero_for_benign_event() {
    let ev = Event::Openat {
        pid: 10, comm: "cat".into(),
        filename: "/tmp/harmless.txt".into(),
        flags: 0, ret: 3, timestamp_ns: 1_000_000_000, denied: false,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(risk_score(&v), 0);
    assert_eq!(v["severity_id"], 1);
}

#[test]
fn risk_sensitive_path_is_medium() {
    let ev = Event::Openat {
        pid: 10, comm: "cat".into(),
        filename: "/etc/shadow".into(),
        flags: 0, ret: 3, timestamp_ns: 1_000_000_000, denied: false,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    assert_eq!(risk_score(&v), 3);
    assert_eq!(v["severity_id"], 3); // MEDIUM
}

#[test]
fn error_without_deny_scores_low() {
    let ev = Event::Connect {
        pid: 20, comm: "curl".into(),
        addr: "127.0.0.1".into(), port: 80,
        ret: -111, timestamp_ns: 1_000_000_000,
    };
    let v = to_ocsf(&ev, &plain(), HOST);
    // error (1) + no sensitive + loopback (not external) = 1 → LOW
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
        ("execve (sensitive binary)", enriched_user.clone(), Event::Execve {
            pid: 1234, root_pid: 1234, uid: 1000,
            comm: "wget".into(), filename: "/usr/bin/wget".into(),
            timestamp_ns: ts,
        }),
        ("openat (read sensitive file)", EnrichedEvent::default(), Event::Openat {
            pid: 1234, comm: "cat".into(),
            filename: "/etc/shadow".into(),
            flags: 0, ret: 3, timestamp_ns: ts + 1_000_000, denied: false,
        }),
        ("connect (external, enriched)", enriched_conn, Event::Connect {
            pid: 1234, comm: "curl".into(),
            addr: "1.1.1.1".into(), port: 443,
            ret: 0, timestamp_ns: ts + 2_000_000,
        }),
        ("ptrace", EnrichedEvent::default(), Event::Ptrace {
            pid: 1234, comm: "strace".into(),
            request: 16, target_pid: 9999, ret: 0,
            timestamp_ns: ts + 3_000_000,
        }),
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
        Event::Execve {
            pid: 1, root_pid: 1, uid: 0, comm: "x".into(), filename: "/x".into(),
            timestamp_ns: 1_000_000_000,
        },
        Event::Openat {
            pid: 1, comm: "x".into(), filename: "/x".into(),
            flags: 0, ret: 3, timestamp_ns: 1_000_000_000, denied: false,
        },
        Event::Unlink {
            pid: 1, comm: "x".into(), filename: "/x".into(),
            flags: 0, ret: 0, timestamp_ns: 1_000_000_000,
        },
        Event::Rename {
            pid: 1, comm: "x".into(),
            old_path: "/a".into(), new_path: "/b".into(),
            ret: 0, timestamp_ns: 1_000_000_000,
        },
        Event::Symlink {
            pid: 1, comm: "x".into(),
            target: "/t".into(), linkpath: "/l".into(),
            ret: 0, timestamp_ns: 1_000_000_000,
        },
    ];
    for ev in &events {
        let v = to_ocsf(ev, &plain(), HOST);
        assert!(v.get("unmapped").is_none(), "unexpected unmapped on {ev:?}", ev = v["message"]);
    }
}
