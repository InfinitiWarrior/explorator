use std::time::Duration;

use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};

/// Native HTTP probing — no external `httpx` binary required. Requests
/// each resolved host over the configured schemes (https then http by
/// default) and records whatever responds: status code, final URL after
/// redirects, page title, and a couple of identifying headers.
pub struct HttpxPlugin;

impl ReconPlugin for HttpxPlugin {
    fn name(&self) -> &str {
        "httpx"
    }

    fn required_binary(&self) -> &str {
        "none (native HTTP client)"
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain, EntityType::Subdomain, EntityType::IpAddress]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Url]
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_httpx(input, config).await })
    }
}

async fn run_httpx(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    let hosts: Vec<&Entity> = input
        .iter()
        .filter(|e| matches!(e.entity_type, EntityType::Domain | EntityType::Subdomain | EntityType::IpAddress))
        .collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    let timeout_secs = config.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(10);
    let schemes: Vec<String> = config
        .get_array("schemes")
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["https".into(), "http".into()]);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("explorator/0.1 (+recon orchestration)")
        .build()
        .map_err(|e| Error::PluginExecution {
            plugin: "httpx".into(),
            message: e.to_string(),
        })?;

    let mut results = Vec::new();
    for host in &hosts {
        for scheme in &schemes {
            let url = format!("{scheme}://{}", host.value);
            if let Some(entity) = probe(&client, &url, host).await {
                results.push(entity);
            }
        }
    }

    Ok(results)
}

/// Issue one GET request and, if the target answered at all, turn the
/// response into a `Url` entity. A connection/TLS/timeout failure just
/// means that scheme isn't live on this host — not a plugin error.
async fn probe(client: &reqwest::Client, url: &str, host: &Entity) -> Option<Entity> {
    let resp = client.get(url).send().await.ok()?;

    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let server = header_str(&resp, reqwest::header::SERVER.as_str());
    let powered_by = header_str(&resp, "x-powered-by");
    let content_length = resp.content_length();
    let body = resp.text().await.unwrap_or_default();
    let title = extract_title(&body);

    Some(
        Entity::new(EntityType::Url, final_url, "httpx")
            .with_metadata(serde_json::json!({
                "requested_url": url,
                "status": status,
                "title": title,
                "server": server,
                "x_powered_by": powered_by,
                "content_length": content_length,
            }))
            .with_relation(host.id, RelationKind::DiscoveredFrom),
    )
}

fn header_str(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Pull the text out of the first `<title>...</title>` in an HTML body.
/// Deliberately not a real HTML parser — recon only needs a best-effort
/// page title, not spec-compliant markup handling.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let tag_start = lower.find("<title")?;
    let open_end = body[tag_start..].find('>')? + tag_start + 1;
    let close_rel = body[open_end..].to_ascii_lowercase().find("</title>")?;
    let text = body[open_end..open_end + close_rel].trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_title() {
        let html = "<html><head><title>Example Domain</title></head><body></body></html>";
        assert_eq!(extract_title(html), Some("Example Domain".to_string()));
    }

    #[test]
    fn extracts_title_with_attributes_and_mixed_case() {
        let html = "<HTML><HEAD><TiTle class=\"x\">  Mixed Case  </TiTle></HEAD></HTML>";
        assert_eq!(extract_title(html), Some("Mixed Case".to_string()));
    }

    #[test]
    fn returns_none_for_missing_title() {
        let html = "<html><body>no title here</body></html>";
        assert_eq!(extract_title(html), None);
    }

    #[test]
    fn returns_none_for_empty_title() {
        let html = "<title>   </title>";
        assert_eq!(extract_title(html), None);
    }
}
