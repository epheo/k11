//! OCSF mapping tests: class and activity per event, the fields OCSF 1.1.0
//! requires for each class, status and risk, enrichment pass-through.

use std::net::SocketAddr;

use serde_json::Value;

use super::{record, Host};
use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::{Event, EventMeta, Payload, Policy};

fn host() -> Host {
    Host {
        hostname: "testhost".into(),
        boot_id: "boot".into(),
    }
}

fn event(ret: i32, payload: Payload) -> Event {
    Event {
        meta: EventMeta {
            seq: 7,
            pid: 100,
            root_pid: 1,
            uid: 1000,
            comm: "agent".into(),
            timestamp_ns: 1_000_000_000,
            ret,
            container: None,
        },
        payload,
    }
}

fn ocsf(e: &Event, enriched: &EnrichedEvent) -> Value {
    serde_json::to_value(record(e, enriched, &host())).unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn open(path: &str, policy: Policy) -> Payload {
    Payload::Open {
        filename: path.into(),
        flags: 0,
        policy,
    }
}

/// One of every payload, with the (class, activity) it must map to.
fn samples() -> Vec<(Payload, u64, u64)> {
    vec![
        (
            Payload::Resolve {
                name: "api.example.com".into(),
                addrs: vec![
                    "203.0.113.10".parse().unwrap(),
                    "2001:db8::1".parse().unwrap(),
                ],
            },
            4003,
            6,
        ),
        (
            Payload::Resolve {
                name: "nowhere.invalid".into(),
                addrs: vec![],
            },
            4003,
            6,
        ),
        (
            Payload::Execve {
                filename: "/usr/bin/git".into(),
                cmd_line: None,
            },
            1007,
            1,
        ),
        (Payload::Fork { child_pid: 101 }, 1007, 1),
        (Payload::Exit, 1007, 2),
        (
            Payload::Ptrace {
                request: 16,
                target_pid: 200,
            },
            1007,
            4,
        ),
        (open("/etc/hosts", Policy::Allowed), 1001, 14),
        (
            Payload::Unlink {
                filename: "/tmp/x".into(),
                flags: 0,
            },
            1001,
            4,
        ),
        (
            Payload::Rename {
                old_path: "/tmp/a".into(),
                new_path: "/tmp/b".into(),
            },
            1001,
            5,
        ),
        (
            Payload::Chmod {
                filename: "/tmp/b".into(),
                mode: 0o600,
            },
            1001,
            7,
        ),
        (
            Payload::Chown {
                filename: "/tmp/b".into(),
                owner_uid: 0,
                owner_gid: 0,
            },
            1001,
            7,
        ),
        (
            Payload::Symlink {
                target: "b".into(),
                linkpath: "/tmp/l".into(),
            },
            1001,
            1,
        ),
        (
            Payload::Connect {
                addr: addr("[2606:4700::1111]:443"),
            },
            4001,
            1,
        ),
        (
            Payload::ResolverConnect {
                addr: addr("104.18.32.47:0"),
            },
            4001,
            1,
        ),
        (
            Payload::UnixConnect {
                path: "/run/dbus".into(),
            },
            4001,
            1,
        ),
        (
            Payload::Bind {
                addr: addr("0.0.0.0:8080"),
            },
            4001,
            99,
        ),
        (Payload::Listen { backlog: 128 }, 4001, 99),
    ]
}

fn has(v: &Value, path: &str) -> bool {
    path.split('.')
        .try_fold(v, |v, key| v.get(key))
        .is_some_and(|v| !v.is_null())
}

#[test]
fn class_and_activity_per_event() {
    for (payload, class, activity) in samples() {
        let v = ocsf(&event(0, payload), &EnrichedEvent::default());
        assert_eq!(v["class_uid"], class, "{}", v["message"]);
        assert_eq!(v["activity_id"], activity, "{}", v["message"]);
        assert_eq!(v["category_uid"], class / 1000);
        assert_eq!(v["type_uid"], class * 100 + activity);
    }
}

#[test]
fn required_fields_per_class() {
    for (payload, class, _) in samples() {
        let v = ocsf(&event(0, payload), &EnrichedEvent::default());
        let msg = v["message"].clone();
        for field in [
            "activity_id",
            "category_uid",
            "class_uid",
            "type_uid",
            "severity_id",
            "time",
            "metadata.version",
            "metadata.product.vendor_name",
            "device.type_id",
            "actor.process.pid",
        ] {
            assert!(has(&v, field), "{field} missing: {msg}");
        }
        let class_fields: &[&str] = match class {
            1001 => &["file.name", "file.type_id"],
            1007 => &["process.pid"],
            4003 => &["src_endpoint", "query.hostname", "rcode_id"],
            _ => &[
                "src_endpoint",
                "dst_endpoint",
                "connection_info.direction_id",
            ],
        };
        for field in class_fields {
            assert!(has(&v, field), "{field} missing: {msg}");
        }
        let profiles = v["metadata"]["profiles"].as_array().unwrap();
        if profiles.iter().any(|p| p == "security_control") {
            assert!(
                has(&v, "action_id"),
                "security_control needs action_id: {msg}"
            );
        }
        for o in v["observables"].as_array().unwrap() {
            assert!(o["name"].is_string() && o["type_id"].is_u64(), "{o}");
        }
        if let Some(ip) = v["dst_endpoint"]["ip"].as_str() {
            assert!(!ip.contains('['), "ip_t has no brackets: {ip}");
        }
    }
}

#[test]
fn envelope() {
    let v = ocsf(
        &event(0, open("/etc/hosts", Policy::Allowed)),
        &EnrichedEvent::default(),
    );
    assert_eq!(v["metadata"]["version"], "1.1.0");
    assert_eq!(v["metadata"]["correlation_uid"], "boot:1");
    assert_eq!(v["metadata"]["sequence"], 7);
    assert_eq!(v["time"], 1000);
    assert_eq!(v["time_dt"], "1970-01-01T00:00:01.000Z");
    assert_eq!(v["message"], "agent open /etc/hosts");
    assert_eq!(v["device"]["hostname"], "testhost");
    assert_eq!(v["actor"]["process"]["pid"], 100);
    assert_eq!(v["actor"]["process"]["user"]["uid"], "1000");
    assert_eq!(v["unmapped"]["root_pid"], 1);
    assert_eq!(v["file"]["name"], "hosts");
}

#[test]
fn status_and_policy() {
    let none = EnrichedEvent::default();
    let failed = ocsf(&event(-2, open("/nope", Policy::Allowed)), &none);
    assert_eq!(failed["status_id"], 2);
    assert_eq!(failed["status_code"], "ENOENT");
    assert_eq!(failed["action_id"], 1);
    assert_eq!(failed["disposition_id"], 1);

    let denied = ocsf(&event(-1, open("/secret", Policy::Denied)), &none);
    assert_eq!(denied["status_id"], 2);
    assert_eq!(denied["action_id"], 2);
    assert_eq!(denied["disposition_id"], 2);
    assert_eq!(denied["severity_id"], 5);

    let audited = ocsf(&event(3, open("/secret", Policy::Audited)), &none);
    assert_eq!(audited["status_id"], 1);
    assert_eq!(audited["action_id"], 1);
    assert_eq!(audited["disposition_id"], 15);
    assert_eq!(audited["severity_id"], 4);

    let exec = ocsf(
        &event(
            0,
            Payload::Execve {
                filename: "/bin/true".into(),
                cmd_line: None,
            },
        ),
        &none,
    );
    assert!(exec.get("action_id").is_none() && exec.get("disposition_id").is_none());
    assert!(exec["process"].get("cmd_line").is_none());

    let argv = b"git\0push\0--force\0";
    let exec = ocsf(
        &event(
            0,
            Payload::Execve {
                filename: "/usr/bin/git".into(),
                cmd_line: crate::cmdline::CommandLine::parse(argv, argv.len())
                    .map(std::sync::Arc::new),
            },
        ),
        &none,
    );
    assert_eq!(exec["process"]["cmd_line"], "git push --force");
}

#[test]
fn container_profile_only_in_a_container() {
    let none = EnrichedEvent::default();
    let mut e = event(0, open("/etc/hostname", Policy::Allowed));
    let on_host = ocsf(&e, &none);
    assert!(on_host.get("container").is_none());
    let profiles = |v: &Value| v["metadata"]["profiles"].as_array().unwrap().clone();
    assert!(!profiles(&on_host).iter().any(|p| p == "container"));
    e.meta.container = Some(std::sync::Arc::new(crate::container::Container {
        runtime: "podman",
        id: "a".repeat(64),
        name: None,
        image: None,
    }));
    let inside = ocsf(&e, &none);
    assert_eq!(inside["container"]["uid"], "a".repeat(64));
    assert_eq!(inside["container"]["runtime"], "podman");
    assert!(profiles(&inside).iter().any(|p| p == "container"));
}

#[test]
fn connect_outcomes() {
    let none = EnrichedEvent::default();
    let connect = |ret| {
        ocsf(
            &event(
                ret,
                Payload::Connect {
                    addr: addr("93.184.216.34:443"),
                },
            ),
            &none,
        )
    };
    let started = connect(-115);
    assert_eq!(started["activity_id"], 1);
    assert_eq!(started["status_id"], 1);
    assert_eq!(connect(-111)["activity_id"], 5);
    assert_eq!(connect(-101)["activity_id"], 4);
    assert_eq!(started["severity_id"], 2, "external address");
}

#[test]
fn risk_from_sensitive_paths() {
    let v = ocsf(
        &event(0, open("/home/u/.ssh/id_ed25519", Policy::Allowed)),
        &EnrichedEvent::default(),
    );
    assert_eq!(v["unmapped"]["risk_score"], 3);
    assert_eq!(v["severity_id"], 3);
}

#[test]
fn enrichment_pass_through() {
    let enriched = EnrichedEvent {
        addr: Some(EnrichedAddr {
            hostname: Some("one.one.one.one".into()),
            country: Some("US".into()),
            city: None,
            asn: Some("AS13335 Cloudflare".into()),
        }),
        username: Some("alice".into()),
    };
    let v = ocsf(
        &event(
            0,
            Payload::Connect {
                addr: addr("[::ffff:1.1.1.1]:443"),
            },
        ),
        &enriched,
    );
    assert_eq!(v["dst_endpoint"]["ip"], "1.1.1.1");
    assert_eq!(v["dst_endpoint"]["hostname"], "one.one.one.one");
    assert_eq!(v["dst_endpoint"]["location"]["country"], "US");
    assert_eq!(v["enrichments"][0]["name"], "dst_endpoint.ip");
    assert_eq!(v["enrichments"][0]["value"], "1.1.1.1");
    assert_eq!(v["enrichments"][0]["data"]["asn"], "AS13335 Cloudflare");
    assert_eq!(v["actor"]["process"]["user"]["name"], "alice");
    let observed: Vec<_> = v["observables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["value"].as_str().unwrap())
        .collect();
    for value in ["agent", "alice", "1.1.1.1", "one.one.one.one"] {
        assert!(observed.contains(&value), "{value} not observed");
    }
}

#[test]
fn rfc3339() {
    use super::schema::rfc3339_millis;
    assert_eq!(rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
    let days: u64 = 20_561; // 2026-04-18
    assert_eq!(
        rfc3339_millis((days * 86400 + 12 * 3600) * 1_000_000_000),
        "2026-04-18T12:00:00.000Z"
    );
    assert_eq!(
        rfc3339_millis(1_234_567_890_123_000_000),
        "2009-02-13T23:31:30.123Z"
    );
}

#[test]
fn loss_record_is_a_base_event() {
    let host = host();
    let v = serde_json::to_value(super::LossRecord::new(
        &[("ring_full", 12), ("read_failed", 1)],
        1_000_000_000,
        &host,
    ))
    .unwrap();
    assert_eq!(
        (v["class_uid"].as_u64(), v["type_uid"].as_u64()),
        (Some(0), Some(99))
    );
    assert_eq!(v["count"], 13);
    assert_eq!(v["unmapped"]["ring_full"], 12);
    assert_eq!(
        v["message"],
        "k11 lost 13 records (12 ring_full, 1 read_failed)"
    );
    assert!(v["metadata"].get("correlation_uid").is_none());
}

#[test]
fn every_record_reads_back_as_its_event() {
    use super::{replay, Line};
    let argv = b"git\0commit\0-m\0it's done\0";
    let mut cases: Vec<(i32, Payload)> = samples().into_iter().map(|(p, _, _)| (0, p)).collect();
    cases.extend([
        (-2, open("/home/u/.aws/credentials", Policy::Allowed)),
        (-1, open("/home/u/.ssh/id_ed25519", Policy::Denied)),
        (3, open("/home/u/.ssh/config", Policy::Audited)),
        (
            0,
            Payload::Execve {
                filename: "/usr/bin/git".into(),
                cmd_line: crate::cmdline::CommandLine::parse(argv, 4096).map(std::sync::Arc::new),
            },
        ),
    ]);
    for (ret, payload) in cases {
        let e = event(ret, payload);
        let line = serde_json::to_string(&record(&e, &EnrichedEvent::default(), &host())).unwrap();
        let Ok(Some(Line::Event(back))) = replay(&line) else {
            panic!("not read back: {line}");
        };
        let m = &back.event.meta;
        assert_eq!(back.event.describe(), e.describe(), "{line}");
        assert_eq!(back.session, "boot:1");
        assert_eq!(
            (m.pid, m.root_pid, m.uid, &*m.comm, m.timestamp_ns),
            (100, 1, 1000, "agent", 1_000_000_000)
        );
        assert_eq!(super::super::classify::failed(m.ret), ret < 0, "{line}");
    }
    let lost =
        serde_json::to_string(&super::LossRecord::new(&[("ring_full", 3)], 0, &host())).unwrap();
    assert!(matches!(replay(&lost), Ok(Some(Line::Lost(3)))));
}
