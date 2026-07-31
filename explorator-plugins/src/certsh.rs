use std::sync::Arc;
use std::time::Duration;

use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use serde::Deserialize;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::x509;

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
        let mut found_any = false;
        let mut errors = Vec::new();

        match fetch_crtsh(&client, domain).await {
            Ok(entities) => {
                found_any |= !entities.is_empty();
                results.extend(entities);
            }
            Err(e) => {
                log::warn!("certsh: crt.sh lookup failed for '{}' ({e}); trying certspotter", domain.value);
                errors.push(format!("crt.sh: {e}"));
            }
        }

        // certspotter is a real independent aggregator, not just a proxy
        // for crt.sh, so it's only worth the extra request if crt.sh came
        // back empty or failed.
        if !found_any {
            match fetch_certspotter(&client, domain).await {
                Ok(entities) => {
                    found_any |= !entities.is_empty();
                    results.extend(entities);
                }
                Err(e) => {
                    log::warn!("certsh: certspotter fallback failed for '{}' ({e})", domain.value);
                    errors.push(format!("certspotter: {e}"));
                }
            }
        }

        // On-demand third source: connect straight to the target and read
        // whatever certificate it's presenting right now. No third-party
        // aggregator involved, so it's always worth attempting even when
        // the CT log sources above already succeeded — it can surface
        // hosts covered by a cert that hasn't been logged yet, or that the
        // aggregators simply missed.
        match fetch_tls_san(domain).await {
            Ok(entities) => {
                found_any |= !entities.is_empty();
                results.extend(entities);
            }
            Err(e) => {
                log::warn!("certsh: live TLS certificate grab failed for '{}' ({e})", domain.value);
                errors.push(format!("live TLS: {e}"));
            }
        }

        if !found_any {
            return Err(Error::PluginExecution {
                plugin: "certsh".into(),
                message: format!("all sources failed for '{}': {}", domain.value, errors.join("; ")),
            });
        }
    }

    Ok(results)
}

/// Certificate verifier that accepts whatever chain the server presents.
/// This is only ever used to read a certificate's contents for recon
/// purposes, not to establish a trusted channel — we still perform real
/// signature verification (via the crypto provider) so the handshake
/// itself is legitimate, we just don't reject self-signed or expired
/// certs, which are exactly the kind of thing worth noting during recon.
#[derive(Debug)]
struct AcceptAnyCert(Arc<tokio_rustls::rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Connect directly to `domain:443`, perform a TLS handshake, and read the
/// SAN entries off whatever certificate the server presents — on demand,
/// with no crt.sh/certspotter dependency at all. Only reveals hostnames
/// covered by whatever certificate happens to be live right now (unlike
/// CT log search, which is historical), but needs nothing but a TCP
/// connection to the target itself.
async fn fetch_tls_san(domain: &Entity) -> std::result::Result<Vec<Entity>, String> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(domain.value.clone()).map_err(|e| e.to_string())?;

    let tcp = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect((domain.value.as_str(), 443)),
    )
    .await
    .map_err(|_| "connection timed out".to_string())?
    .map_err(|e| e.to_string())?;

    let tls_stream = tokio::time::timeout(Duration::from_secs(8), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;

    let peer_certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| "server presented no certificate".to_string())?;
    let leaf = peer_certs.first().ok_or_else(|| "empty certificate chain".to_string())?;

    let names = x509::extract_san_dns_names(leaf.as_ref());
    if names.is_empty() {
        return Err("certificate had no DNS SAN entries".into());
    }

    let cert = Entity::new(EntityType::Certificate, format!("tls-live:{}", domain.value), "certsh")
        .with_metadata(serde_json::json!({ "source_method": "live_tls_handshake" }));
    let cert_id = cert.id;

    let mut entities = vec![cert];
    for host in names {
        entities.push(host_entity(&host, domain, cert_id));
    }
    Ok(entities)
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
