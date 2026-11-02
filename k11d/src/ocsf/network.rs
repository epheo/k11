//! OCSF Network Activity (4001): Connect, UnixConnect, Bind, Listen.
//!
//! OCSF 1.1.0 has no Connect/Bind/Listen activity ids (only Open, Close,
//! Reset, Fail, Refuse, Traffic), so every socket lifecycle event maps to
//! Open and is distinguished by `connection_info.direction_id`.

use crate::classify::errno_name;
use crate::enrich::{EnrichedAddr, EnrichedEvent};
use crate::store::{Event, Payload};

use super::envelope::{
    AutonomousSystem, ConnectionInfo, DstEndpoint, Location, Record, Unmapped, CATEGORY_NETWORK,
    CLASS_NETWORK_ACTIVITY, OBS_HOSTNAME, OBS_IP,
};

const OPEN: u32 = 1;
const DIR_INBOUND: u32 = 1;
const DIR_OUTBOUND: u32 = 2;

fn record<'a>(
    hostname: &'a str,
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    message: String,
) -> Record<'a> {
    Record::new(
        CLASS_NETWORK_ACTIVITY,
        CATEGORY_NETWORK,
        OPEN,
        hostname,
        event,
        enriched,
        message,
    )
}

fn direction(direction_id: u32) -> ConnectionInfo {
    ConnectionInfo {
        direction_id,
        direction: if direction_id == DIR_INBOUND {
            "Inbound"
        } else {
            "Outbound"
        },
        protocol_name: None,
    }
}

pub(super) fn connect<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Connect { addr, port, ret } = &event.payload else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let peer = enriched.addr.as_ref();

    let message = if *ret < 0 {
        format!(
            "{comm} connect({addr}:{port}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        let host = peer
            .and_then(|p| p.hostname.as_deref())
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();
        let asn = peer
            .and_then(|p| p.asn.as_deref())
            .map(|a| format!(" [{a}]"))
            .unwrap_or_default();
        format!("{comm} connected to {addr}:{port}{host}{asn}")
    };

    let mut r = record(hostname, event, enriched, message);
    r.dst_endpoint = Some(endpoint(addr, *port, peer));
    r.connection_info = Some(direction(DIR_OUTBOUND));
    r.observe("dst_endpoint.ip", OBS_IP, addr);
    if let Some(h) = peer.and_then(|p| p.hostname.as_deref()) {
        r.observe("dst_endpoint.hostname", OBS_HOSTNAME, h);
    }
    r
}

fn endpoint<'a>(addr: &'a str, port: u16, peer: Option<&'a EnrichedAddr>) -> DstEndpoint<'a> {
    DstEndpoint {
        ip: Some(addr),
        port: Some(port),
        hostname: peer.and_then(|p| p.hostname.as_deref()),
        location: peer
            .and_then(|p| p.country.as_deref())
            .map(|country| Location {
                country,
                city: peer.and_then(|p| p.city.as_deref()),
            }),
        autonomous_system: peer
            .and_then(|p| p.asn.as_deref())
            .map(|name| AutonomousSystem { name }),
        ..Default::default()
    }
}

pub(super) fn unix_connect<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::UnixConnect { path, ret } = &event.payload else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!("{comm} unix connect({path}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} connected to unix socket {path}")
    };
    let mut r = record(hostname, event, enriched, message);
    r.dst_endpoint = Some(DstEndpoint {
        domain: Some(path),
        ..Default::default()
    });
    let mut info = direction(DIR_OUTBOUND);
    info.protocol_name = Some("unix");
    r.connection_info = Some(info);
    r
}

pub(super) fn bind<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Bind { addr, port, ret } = &event.payload else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!("{comm} bind({addr}:{port}) failed [{}]", errno_name(*ret))
    } else {
        format!("{comm} bound to {addr}:{port}")
    };
    let mut r = record(hostname, event, enriched, message);
    r.dst_endpoint = Some(DstEndpoint {
        ip: Some(addr),
        port: Some(*port),
        ..Default::default()
    });
    r.connection_info = Some(direction(DIR_INBOUND));
    r.observe("dst_endpoint.ip", OBS_IP, addr);
    r
}

pub(super) fn listen<'a>(
    event: &'a Event,
    enriched: &'a EnrichedEvent,
    hostname: &'a str,
) -> Record<'a> {
    let Payload::Listen { backlog, ret } = &event.payload else {
        unreachable!()
    };
    let comm = &event.meta.comm;
    let message = if *ret < 0 {
        format!(
            "{comm} listen(backlog={backlog}) failed [{}]",
            errno_name(*ret)
        )
    } else {
        format!("{comm} started listening (backlog={backlog})")
    };
    let mut r = record(hostname, event, enriched, message);
    r.connection_info = Some(direction(DIR_INBOUND));
    // OCSF has no socket-backlog field.
    r.unmapped = Some(Unmapped {
        backlog: Some(*backlog),
        ..Default::default()
    });
    r
}
