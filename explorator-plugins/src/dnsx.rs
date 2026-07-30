use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use explorator_core::{Entity, EntityType, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::net::UdpSocket;

use crate::dns_wire::{self, RData, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_TXT};

/// Native DNS resolution and record lookup — no external `dnsx` binary
/// required. Talks RFC 1035 UDP directly to the system's configured
/// resolvers (falling back to public resolvers if none are configured).
pub struct DnsxPlugin;

impl ReconPlugin for DnsxPlugin {
    fn name(&self) -> &str {
        "dnsx"
    }

    fn required_binary(&self) -> &str {
        "none (native DNS resolver)"
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain, EntityType::Subdomain]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::IpAddress]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_dnsx(input, config).await })
    }
}

async fn run_dnsx(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    let hosts: Vec<&Entity> = input
        .iter()
        .filter(|e| matches!(e.entity_type, EntityType::Domain | EntityType::Subdomain))
        .collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    let record_types: Vec<u16> = config
        .get_array("record_types")
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(record_type_from_str)
                .collect()
        })
        .filter(|v: &Vec<u16>| !v.is_empty())
        .unwrap_or_else(|| vec![TYPE_A]);

    let resolvers = system_resolvers();

    let mut results = Vec::new();
    for host in hosts {
        let mut ip_relations = Vec::new();
        let mut cnames = Vec::new();
        let mut mxs = Vec::new();
        let mut nss = Vec::new();
        let mut txts = Vec::new();

        for &qtype in &record_types {
            let records = resolve(&host.value, qtype, &resolvers).await;
            for record in records {
                match record.rdata {
                    RData::A(ip) => {
                        let entity = Entity::new(EntityType::IpAddress, ip.to_string(), "dnsx");
                        ip_relations.push((entity.id, RelationKind::ResolvesTo));
                        results.push(entity);
                    }
                    RData::Aaaa(ip) => {
                        let entity = Entity::new(EntityType::IpAddress, ip.to_string(), "dnsx");
                        ip_relations.push((entity.id, RelationKind::ResolvesTo));
                        results.push(entity);
                    }
                    RData::Cname(name) => cnames.push(name),
                    RData::Mx { preference, exchange } => mxs.push(format!("{preference} {exchange}")),
                    RData::Ns(name) => nss.push(name),
                    RData::Txt(text) => txts.push(text),
                    RData::Other => {}
                }
            }
        }

        if ip_relations.is_empty() && cnames.is_empty() && mxs.is_empty() && nss.is_empty() && txts.is_empty() {
            continue;
        }

        // Re-emit the input host carrying the new relations/records;
        // EntityGraph dedups this against the existing node by
        // (entity_type, value), merging the records onto it rather than
        // creating a duplicate.
        let mut updated_host = Entity::new(host.entity_type, host.value.clone(), "dnsx").with_metadata(
            serde_json::json!({
                "cname": cnames,
                "mx": mxs,
                "ns": nss,
                "txt": txts,
            }),
        );
        for (target, kind) in ip_relations {
            updated_host = updated_host.with_relation(target, kind);
        }
        results.push(updated_host);
    }

    Ok(results)
}

fn record_type_from_str(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "AAAA" => Some(TYPE_AAAA),
        "CNAME" => Some(TYPE_CNAME),
        "MX" => Some(TYPE_MX),
        "TXT" => Some(TYPE_TXT),
        "NS" => Some(TYPE_NS),
        _ => None,
    }
}

async fn resolve(name: &str, qtype: u16, resolvers: &[IpAddr]) -> Vec<dns_wire::Record> {
    for &server in resolvers {
        if let Ok(records) = query(server, name, qtype, Duration::from_secs(3)).await {
            return records;
        }
    }
    Vec::new()
}

static QUERY_ID: AtomicU16 = AtomicU16::new(0);

fn next_query_id() -> u16 {
    QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

async fn query(server: IpAddr, name: &str, qtype: u16, timeout: Duration) -> std::io::Result<Vec<dns_wire::Record>> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
    socket.connect(SocketAddr::new(server, 53)).await?;

    let id = next_query_id();
    let packet = dns_wire::build_query(id, name, qtype);
    socket.send(&packet).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns query timed out"))??;

    dns_wire::parse_response(&buf[..n], id)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed dns response"))
}

/// Read nameservers from `/etc/resolv.conf`; fall back to public
/// resolvers if the file is missing, empty, or unparsable (e.g. non-Unix,
/// or a systemd-resolved stub with no real entries).
fn system_resolvers() -> Vec<IpAddr> {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        let servers: Vec<IpAddr> = contents
            .lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix("nameserver"))
            .filter_map(|rest| rest.trim().parse::<IpAddr>().ok())
            .collect();
        if !servers.is_empty() {
            return servers;
        }
    }
    vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]
}
