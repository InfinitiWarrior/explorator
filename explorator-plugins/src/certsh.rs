use std::time::Duration;

use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use serde::Deserialize;

/// Certificate transparency log search. There's no standard `certsh` CLI
/// binary in the wild — the usual way to query CT logs is crt.sh's own
/// JSON API — so this talks to it (and a fallback source) directly over
/// HTTP rather than shelling out to anything.
pub struct CertshPlugin;

impl ReconPlugin for CertshPlugin {
    fn name(&self) -> &str {
        "certsh"
    }

    fn required_binary(&self) -> &str {
        "none (native HTTPS client)"
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Subdomain, EntityType::Certificate]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_certsh(input, config).await })
    }
}

#[derive(Deserialize)]
struct CrtShRecord {
    id: u64,
    name_value: String,
    issuer_name: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Deserialize)]
struct CertSpotterIssuer {
    name: Option<String>,
}

#[derive(Deserialize)]
struct CertSpotterRecord {
    id: String,
    dns_names: Vec<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    issuer: Option<CertSpotterIssuer>,
}

async fn run_certsh(input: &[Entity], _config: &PluginConfig) -> Result<Vec<Entity>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("explorator/0.1 (+recon orchestration)")
        .build()
        .map_err(|e| Error::PluginExecution {
            plugin: "certsh".into(),
            message: e.to_string(),
        })?;

    let mut results = Vec::new();
    for domain in input.iter().filter(|e| e.entity_type == EntityType::Domain) {
        match fetch_crtsh(&client, domain).await {
            Ok(entities) => results.extend(entities),
            Err(primary_err) => {
                log::warn!(
                    "certsh: crt.sh lookup failed for '{}' ({primary_err}); falling back to certspotter",
                    domain.value
                );
                match fetch_certspotter(&client, domain).await {
                    Ok(entities) => results.extend(entities),
                    Err(fallback_err) => {
                        return Err(Error::PluginExecution {
                            plugin: "certsh".into(),
                            message: format!(
                                "crt.sh failed ({primary_err}); certspotter fallback also failed ({fallback_err})"
                            ),
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Build the entity for one hostname found in a certificate's SAN list,
/// linked to its certificate. Only links `DiscoveredFrom` the queried
/// domain when the host is actually a *different* entity — the queried
/// domain itself commonly appears in its own SAN list, and linking it to
/// itself would create a meaningless self-loop.
fn host_entity(host: &str, domain: &Entity, cert_id: uuid::Uuid) -> Entity {
    let is_root_domain = host.eq_ignore_ascii_case(&domain.value);
    let entity_type = if is_root_domain { EntityType::Domain } else { EntityType::Subdomain };
    let wildcard = host.starts_with("*.");

    let mut entity = Entity::new(entity_type, host, "certsh")
        .with_metadata(serde_json::json!({ "wildcard": wildcard }))
        .with_relation(cert_id, RelationKind::HasCertificate);
    if !is_root_domain {
        entity = entity.with_relation(domain.id, RelationKind::DiscoveredFrom);
    }
    entity
}

async fn fetch_crtsh(client: &reqwest::Client, domain: &Entity) -> std::result::Result<Vec<Entity>, String> {
    let resp = client
        .get("https://crt.sh/")
        .query(&[("q", domain.value.as_str()), ("output", "json")])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    // crt.sh occasionally serves an HTML maintenance page with a 200
    // status during outages, so validate the body is actually JSON rather
    // than trusting the status code alone.
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let records: Vec<CrtShRecord> =
        serde_json::from_str(&text).map_err(|e| format!("response was not valid JSON ({e})"))?;

    let mut entities = Vec::new();
    for rec in records {
        let cert = Entity::new(EntityType::Certificate, rec.id.to_string(), "certsh").with_metadata(
            serde_json::json!({
                "issuer": rec.issuer_name,
                "not_before": rec.not_before,
                "not_after": rec.not_after,
            }),
        );
        let cert_id = cert.id;
        entities.push(cert);

        for host in rec.name_value.lines().map(str::trim).filter(|h| !h.is_empty()) {
            entities.push(host_entity(host, domain, cert_id));
        }
    }

    Ok(entities)
}

async fn fetch_certspotter(client: &reqwest::Client, domain: &Entity) -> std::result::Result<Vec<Entity>, String> {
    let resp = client
        .get("https://api.certspotter.com/v1/issuances")
        .query(&[
            ("domain", domain.value.as_str()),
            ("include_subdomains", "true"),
            ("expand", "dns_names"),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let records: Vec<CertSpotterRecord> = resp.json().await.map_err(|e| e.to_string())?;

    let mut entities = Vec::new();
    for rec in records {
        let issuer_name = rec.issuer.and_then(|i| i.name);
        let cert = Entity::new(EntityType::Certificate, rec.id, "certsh").with_metadata(serde_json::json!({
            "issuer": issuer_name,
            "not_before": rec.not_before,
            "not_after": rec.not_after,
            "fallback_source": "certspotter",
        }));
        let cert_id = cert.id;
        entities.push(cert);

        for host in &rec.dns_names {
            entities.push(host_entity(host, domain, cert_id));
        }
    }

    Ok(entities)
}
