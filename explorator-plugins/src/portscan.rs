use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use explorator_core::{Entity, EntityType, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Native TCP-connect port scan — no external `nmap` binary required.
/// Attempts a full TCP handshake against each configured port on each
/// input IP, concurrently and with a per-connection timeout, and records
/// whichever ports actually complete a connection as open. This is a
/// connect scan, not a SYN scan: slower and more visible to the target
/// than `nmap -sS`, but it needs no raw sockets or root privileges, which
/// SYN scanning fundamentally requires — that's the real reason `nmap`
/// itself stays a shell-out rather than a native reimplementation.
pub struct PortscanPlugin;

impl ReconPlugin for PortscanPlugin {
    fn name(&self) -> &str {
        "portscan"
    }

    fn required_binary(&self) -> &str {
        "none (native TCP connect scanner)"
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::IpAddress]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Port]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_portscan(input, config).await })
    }
}

/// A reasonably broad "top ports" list covering common web, mail,
/// database, and remote-access services, used when the pipeline config
/// doesn't specify its own `ports` list.
const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1723, 3306, 3389, 5432,
    5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
];

async fn run_portscan(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    let hosts: Vec<&Entity> = input.iter().filter(|e| e.entity_type == EntityType::IpAddress).collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    let ports: Vec<u16> = config
        .get_array("ports")
        .map(|arr| arr.iter().filter_map(|v| v.as_u64()).filter_map(|n| u16::try_from(n).ok()).collect())
        .filter(|v: &Vec<u16>| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_PORTS.to_vec());

    let timeout_ms = config.get("timeout_ms").and_then(|v| v.as_u64()).unwrap_or(800);
    let concurrency =
        config.get("concurrency").and_then(|v| v.as_u64()).unwrap_or(200).max(1) as usize;

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks: JoinSet<Option<(String, u16)>> = JoinSet::new();

    for host in &hosts {
        let Ok(ip) = host.value.parse::<IpAddr>() else { continue };
        for &port in &ports {
            let sem = semaphore.clone();
            let host_value = host.value.clone();
            tasks.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let addr = SocketAddr::new(ip, port);
                match tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
                    Ok(Ok(_stream)) => Some((host_value, port)),
                    _ => None,
                }
            });
        }
    }

    let mut open_by_host: HashMap<String, Vec<u16>> = HashMap::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some((host_value, port))) = joined {
            open_by_host.entry(host_value).or_default().push(port);
        }
    }

    let host_by_value: HashMap<&str, &Entity> = hosts.iter().map(|h| (h.value.as_str(), *h)).collect();

    let mut results = Vec::new();
    for (host_value, mut open_ports) in open_by_host {
        let Some(&host) = host_by_value.get(host_value.as_str()) else { continue };
        open_ports.sort_unstable();

        let mut port_relations = Vec::new();
        for port in open_ports {
            let entity = Entity::new(EntityType::Port, format!("{host_value}:{port}"), "portscan")
                .with_metadata(serde_json::json!({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "likely_service": likely_service(port),
                }));
            port_relations.push((entity.id, RelationKind::HasPort));
            results.push(entity);
        }

        // Re-emit the input IP carrying `HasPort` relations to the newly
        // found ports; EntityGraph dedups this against the existing node
        // by (entity_type, value), merging the relations onto it rather
        // than creating a duplicate IP node.
        let mut updated_host = Entity::new(host.entity_type, host.value.clone(), "portscan");
        for (target, kind) in port_relations {
            updated_host = updated_host.with_relation(target, kind);
        }
        results.push(updated_host);
    }

    Ok(results)
}

fn likely_service(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        135 => Some("msrpc"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        587 => Some("submission"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1723 => Some("pptp"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        8000 | 8080 | 8888 => Some("http-alt"),
        8443 => Some("https-alt"),
        9200 => Some("elasticsearch"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use explorator_core::EntityGraph;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn finds_the_one_open_port_among_several_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((_stream, _)) = listener.accept().await {}
        });

        // Pick two ports that are almost certainly closed on a CI/dev
        // box: 1 (needs root, never bound in tests) is safe to assume shut.
        let closed_ports = serde_json::json!([1u16, open_port]);
        let config = PluginConfig(serde_json::json!({
            "ports": closed_ports,
            "timeout_ms": 300,
        }));

        let ip = Entity::new(EntityType::IpAddress, "127.0.0.1", "seed");
        let input = vec![ip.clone()];

        let results = run_portscan(&input, &config).await.unwrap();

        let mut graph = EntityGraph::new();
        graph.add_entities(results);

        let port_entities = graph.entities_by_type(EntityType::Port);
        assert_eq!(port_entities.len(), 1, "only the bound port should show as open");
        assert_eq!(port_entities[0].value, format!("127.0.0.1:{open_port}"));
        assert_eq!(port_entities[0].metadata["state"], serde_json::json!("open"));

        let merged_ip = graph.find_by_value(EntityType::IpAddress, "127.0.0.1").unwrap();
        let relations = graph.relations_of(merged_ip.id);
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].1.value, format!("127.0.0.1:{open_port}"));
    }

    #[tokio::test]
    async fn non_ip_input_is_ignored() {
        let domain = Entity::new(EntityType::Domain, "example.com", "seed");
        let config = PluginConfig::default();
        let results = run_portscan(&[domain], &config).await.unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn maps_well_known_ports_to_service_names() {
        assert_eq!(likely_service(443), Some("https"));
        assert_eq!(likely_service(65000), None);
    }
}
