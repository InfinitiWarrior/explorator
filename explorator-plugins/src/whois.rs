use std::time::Duration;

use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const IANA_WHOIS: &str = "whois.iana.org";
const ARIN_WHOIS: &str = "whois.arin.net";
const MAX_REFERRALS: u8 = 3;
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Native WHOIS lookups over raw TCP (port 43) — no external `whois`
/// binary. Follows referrals (e.g. IANA -> the registry's own server) up
/// to a small hop limit, same as the real protocol expects clients to do.
pub struct WhoisPlugin;

impl ReconPlugin for WhoisPlugin {
    fn name(&self) -> &str {
        "whois"
    }

    fn required_binary(&self) -> &str {
        "none (native TCP client)"
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain, EntityType::IpAddress]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain, EntityType::IpAddress, EntityType::Asn, EntityType::Cidr]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_whois(input, config).await })
    }
}

async fn run_whois(input: &[Entity], _config: &PluginConfig) -> Result<Vec<Entity>> {
    let mut results = Vec::new();

    for entity in input
        .iter()
        .filter(|e| matches!(e.entity_type, EntityType::Domain | EntityType::Subdomain | EntityType::IpAddress))
    {
        let text = resolve_whois_text(entity).await?;

        let registrar = extract_field(&text, &["Registrar:", "OrgName:", "Organization:", "org-name:"]);
        let created = extract_field(&text, &["Creation Date:", "Registered:", "created:"]);
        let expires = extract_field(&text, &["Registry Expiry Date:", "Expiry Date:", "Expires:", "expires:"]);
        let cidr = extract_field(&text, &["CIDR:", "inetnum:"]);
        let asn = extract_field(&text, &["OriginAS:", "origin:"]);

        let mut updated = Entity::new(entity.entity_type, entity.value.clone(), "whois").with_metadata(
            serde_json::json!({
                "registrar": registrar,
                "created": created,
                "expires": expires,
            }),
        );

        if let Some(cidr_value) = cidr {
            let cidr_entity = Entity::new(EntityType::Cidr, cidr_value, "whois");
            updated = updated.with_relation(cidr_entity.id, RelationKind::BelongsToCidr);
            results.push(cidr_entity);
        }
        if let Some(asn_value) = asn {
            let asn_entity = Entity::new(EntityType::Asn, asn_value, "whois");
            updated = updated.with_relation(asn_entity.id, RelationKind::BelongsToAsn);
            results.push(asn_entity);
        }

        results.push(updated);
    }

    Ok(results)
}

async fn resolve_whois_text(entity: &Entity) -> Result<String> {
    let mut server = match entity.entity_type {
        EntityType::IpAddress => ARIN_WHOIS.to_string(),
        _ => IANA_WHOIS.to_string(),
    };

    let mut last_text = String::new();
    for _ in 0..=MAX_REFERRALS {
        let text = whois_query(&server, &entity.value).await.map_err(|e| Error::PluginExecution {
            plugin: "whois".into(),
            message: format!("{server}: {e}"),
        })?;
        last_text = text;
        match find_referral(&last_text) {
            Some(next) if next != server => server = next,
            _ => break,
        }
    }
    Ok(last_text)
}

async fn whois_query(server: &str, query: &str) -> std::io::Result<String> {
    let mut stream = tokio::time::timeout(QUERY_TIMEOUT, TcpStream::connect((server, 43)))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;

    stream.write_all(format!("{query}\r\n").as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::new();
    tokio::time::timeout(QUERY_TIMEOUT, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))??;

    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// Look for a `refer:` / `ReferralServer:` / `whois:` line pointing to a
/// more authoritative server, as IANA and some RIR responses do.
fn find_referral(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        for prefix in ["refer:", "referralserver:", "whois:"] {
            if lower.starts_with(prefix) {
                let value = line[prefix.len()..].trim();
                let server = value.trim_start_matches("whois://").trim_end_matches('/').trim();
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

/// Case-insensitive "does this line start with one of these field
/// labels" extractor. WHOIS output has no consistent schema across
/// registries, so this is deliberately loose rather than a full parser.
fn extract_field(text: &str, keys: &[&str]) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        for key in keys {
            let key_lower = key.to_ascii_lowercase();
            if lower.starts_with(&key_lower) {
                let value = line[key.len()..].trim().trim_start_matches(':').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_known_fields_case_insensitively() {
        let text = "Domain Name: EXAMPLE.COM\nregistrar: Example Registrar Inc.\nCreation Date: 1995-08-14T04:00:00Z\n";
        assert_eq!(extract_field(text, &["Registrar:"]), Some("Example Registrar Inc.".to_string()));
        assert_eq!(
            extract_field(text, &["Creation Date:"]),
            Some("1995-08-14T04:00:00Z".to_string())
        );
        assert_eq!(extract_field(text, &["Registry Expiry Date:"]), None);
    }

    #[test]
    fn finds_referral_server() {
        let text = "refer: whois.verisign-grs.com\nsomething: else\n";
        assert_eq!(find_referral(text), Some("whois.verisign-grs.com".to_string()));
    }

    #[test]
    fn no_referral_returns_none() {
        let text = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar Inc.\n";
        assert_eq!(find_referral(text), None);
    }
}
