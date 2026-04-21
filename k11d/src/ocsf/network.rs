//! OCSF Network Activity (4001) mappings: Connect, UnixConnect, Bind, Listen.
//!
//! OCSF 1.1.0 Network Activity has no dedicated Connect/Bind/Listen activity_ids
//! (only Open=1, Close=2, Reset=3, Fail=4, Refuse=5, Traffic=6). All socket
//! lifecycle events therefore map to Open (1), distinguished via
//! `connection_info.direction_id` (1=Inbound, 2=Outbound) and a free-form
//! `connection_info.direction` hint.

use serde_json::{json, Value};

use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::{errno_name, Event};

use super::envelope::{
    envelope, push_observable, CATEGORY_NETWORK, CLASS_NETWORK_ACTIVITY, OBS_HOSTNAME, OBS_IP,
    OBS_PROCESS_NAME,
};

const DIR_INBOUND: u32 = 1;
const DIR_OUTBOUND: u32 = 2;

pub(super) fn connect(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Connect { pid, comm, addr, port, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let empty = EnrichedAddr::default();
    let addr_enrich = enriched.addr.as_ref().unwrap_or(&empty);

    let message = if *ret < 0 {
        format!(
            "{comm} connect({addr}:{port}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        let host_hint = addr_enrich
            .hostname
            .as_deref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();
        let asn_hint = addr_enrich
            .asn
            .as_deref()
            .map(|a| format!(" [{a}]"))
            .unwrap_or_default();
        format!("{comm} connected to {addr}:{port}{host_hint}{asn_hint}")
    };

    let mut v = envelope(
        CLASS_NETWORK_ACTIVITY,
        CATEGORY_NETWORK,
        1, // Open
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    let mut dst = json!({
        "ip": addr,
        "port": port,
    });
    if let Some(h) = addr_enrich.hostname.as_deref() {
        dst.as_object_mut().unwrap().insert("hostname".into(), json!(h));
    }
    if let Some(country) = addr_enrich.country.as_deref() {
        let mut loc = json!({ "country": country });
        if let Some(city) = addr_enrich.city.as_deref() {
            loc.as_object_mut().unwrap().insert("city".into(), json!(city));
        }
        dst.as_object_mut().unwrap().insert("location".into(), loc);
    }
    if let Some(asn) = addr_enrich.asn.as_deref() {
        dst.as_object_mut().unwrap().insert("autonomous_system".into(), json!({ "name": asn }));
    }
    m.insert("dst_endpoint".into(), dst);
    m.insert("connection_info".into(), json!({
        "direction_id": DIR_OUTBOUND,
        "direction": "Outbound",
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "dst_endpoint.ip", OBS_IP, addr);
    if let Some(h) = addr_enrich.hostname.as_deref() {
        push_observable(&mut v, "dst_endpoint.hostname", OBS_HOSTNAME, h);
    }
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn unix_connect(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::UnixConnect { pid, comm, path, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} unix connect({path}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} connected to unix socket {path}")
    };

    let mut v = envelope(
        CLASS_NETWORK_ACTIVITY,
        CATEGORY_NETWORK,
        1, // Open
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("dst_endpoint".into(), json!({
        "domain": path,
    }));
    m.insert("connection_info".into(), json!({
        "direction_id": DIR_OUTBOUND,
        "direction": "Outbound",
        "protocol_name": "unix",
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn bind(event: &Event, enriched: &EnrichedEvent, hostname_str: &str) -> Value {
    let Event::Bind { pid, comm, addr, port, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} bind({addr}:{port}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} bound to {addr}:{port}")
    };

    let mut v = envelope(
        CLASS_NETWORK_ACTIVITY,
        CATEGORY_NETWORK,
        1, // Open
        *timestamp_ns,
        hostname_str,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("dst_endpoint".into(), json!({
        "ip": addr,
        "port": port,
    }));
    m.insert("connection_info".into(), json!({
        "direction_id": DIR_INBOUND,
        "direction": "Inbound",
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));

    push_observable(&mut v, "dst_endpoint.ip", OBS_IP, addr);
    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}

pub(super) fn listen(event: &Event, enriched: &EnrichedEvent, hostname: &str) -> Value {
    let Event::Listen { pid, comm, backlog, ret, timestamp_ns } = event else {
        unreachable!()
    };

    let message = if *ret < 0 {
        format!("{comm} listen(backlog={backlog}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} started listening (backlog={backlog})")
    };

    let mut v = envelope(
        CLASS_NETWORK_ACTIVITY,
        CATEGORY_NETWORK,
        1, // Open
        *timestamp_ns,
        hostname,
        event,
        enriched,
        message,
    );
    let m = v.as_object_mut().unwrap();
    m.insert("connection_info".into(), json!({
        "direction_id": DIR_INBOUND,
        "direction": "Inbound",
    }));
    m.insert("actor".into(), json!({
        "process": { "pid": pid, "name": comm }
    }));
    // OCSF has no native socket-backlog field — legitimate unmapped use.
    m.insert("unmapped".into(), json!({ "backlog": backlog }));

    push_observable(&mut v, "process.name", OBS_PROCESS_NAME, comm);
    v
}
