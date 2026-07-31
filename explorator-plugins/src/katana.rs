use std::process::Stdio;

use explorator_core::plugin::which;
use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::process::Command;

const BINARY: &str = "katana";

/// Wraps ProjectDiscovery's `katana` for web crawling / endpoint discovery.
/// Crawling (HTML parsing, JS-aware link extraction, form/script/attribute
/// discovery across an arbitrary depth) is a large protocol surface with an
/// actively maintained implementation already available — a native
/// reimplementation would be a big lift for little benefit, so this stays a
/// shell-out, same reasoning as `subfinder`.
pub struct KatanaPlugin;

impl ReconPlugin for KatanaPlugin {
    fn name(&self) -> &str {
        "katana"
    }

    fn required_binary(&self) -> &str {
        BINARY
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Url]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Endpoint]
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_katana(input, config).await })
    }
}

#[derive(serde::Deserialize)]
struct KatanaRequest {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    method: Option<String>,
}

#[derive(serde::Deserialize)]
struct KatanaResponse {
    #[serde(default)]
    status_code: Option<u16>,
    #[serde(default)]
    technologies: Vec<String>,
}

#[derive(serde::Deserialize)]
struct KatanaLine {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    attribute: Option<String>,
    #[serde(default)]
    request: Option<KatanaRequest>,
    #[serde(default)]
    response: Option<KatanaResponse>,
}

impl KatanaLine {
    fn resolved_endpoint(&self) -> Option<String> {
        self.endpoint
            .clone()
            .or_else(|| self.request.as_ref().and_then(|r| r.endpoint.clone()))
    }
}

async fn run_katana(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    let seeds: Vec<&Entity> = input.iter().filter(|e| e.entity_type == EntityType::Url).collect();
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    if which(BINARY).is_none() {
        return Err(Error::MissingBinary {
            plugin: "katana".into(),
            binary: BINARY.into(),
        });
    }

    let depth = config.get("depth").and_then(|v| v.as_u64()).unwrap_or(3);
    let js_crawl = config.get_bool("js_crawl").unwrap_or(false);

    let mut results = Vec::new();
    for seed in seeds {
        let mut args = vec![
            "-u".to_string(),
            seed.value.clone(),
            "-d".to_string(),
            depth.to_string(),
            "-jsonl".to_string(),
            "-silent".to_string(),
        ];
        if js_crawl {
            args.push("-jc".to_string());
        }

        let output = Command::new(BINARY)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::PluginExecution {
                plugin: "katana".into(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::PluginExecution {
                plugin: "katana".into(),
                message: stderr.trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<KatanaLine>(line) else {
                continue;
            };
            let Some(endpoint_url) = parsed.resolved_endpoint() else {
                continue;
            };

            let status_code = parsed.response.as_ref().and_then(|r| r.status_code);
            let technologies = parsed.response.map(|r| r.technologies).unwrap_or_default();

            let entity = Entity::new(EntityType::Endpoint, endpoint_url, "katana")
                .with_metadata(serde_json::json!({
                    "source": parsed.source,
                    "tag": parsed.tag,
                    "attribute": parsed.attribute,
                    "method": parsed.request.and_then(|r| r.method),
                    "status_code": status_code,
                    "technologies": technologies,
                }))
                .with_relation(seed.id, RelationKind::DiscoveredFrom);
            results.push(entity);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_endpoint_from_top_level_field() {
        let line: KatanaLine = serde_json::from_str(
            r#"{"endpoint":"https://example.com/page","source":"https://example.com","tag":"a"}"#,
        )
        .unwrap();
        assert_eq!(line.resolved_endpoint(), Some("https://example.com/page".to_string()));
    }

    #[test]
    fn resolves_endpoint_from_nested_request_field() {
        let line: KatanaLine = serde_json::from_str(
            r#"{"source":"https://example.com","request":{"endpoint":"https://example.com/nested","method":"GET"}}"#,
        )
        .unwrap();
        assert_eq!(line.resolved_endpoint(), Some("https://example.com/nested".to_string()));
    }

    #[test]
    fn returns_none_when_no_endpoint_present() {
        let line: KatanaLine = serde_json::from_str(r#"{"source":"https://example.com"}"#).unwrap();
        assert_eq!(line.resolved_endpoint(), None);
    }

    #[tokio::test]
    async fn empty_input_produces_no_results() {
        let domain = Entity::new(EntityType::Domain, "example.com", "seed");
        let config = PluginConfig::default();
        let results = run_katana(&[domain], &config).await.unwrap();
        assert!(results.is_empty());
    }
}
