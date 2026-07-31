use std::process::Stdio;

use explorator_core::plugin::which;
use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::process::Command;

const BINARY: &str = "nuclei";

/// Wraps ProjectDiscovery's `nuclei` for template-driven vulnerability
/// scanning. The template engine and the community template library behind
/// it are a huge, actively maintained surface — reimplementing either
/// natively would be a large lift for essentially no benefit, so this stays
/// a shell-out, same reasoning as `subfinder` and `katana`.
pub struct NucleiPlugin;

impl ReconPlugin for NucleiPlugin {
    fn name(&self) -> &str {
        "nuclei"
    }

    fn required_binary(&self) -> &str {
        BINARY
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Url]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Vulnerability]
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_nuclei(input, config).await })
    }
}

#[derive(serde::Deserialize)]
struct NucleiInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(serde::Deserialize)]
struct NucleiLine {
    #[serde(default, rename = "template-id")]
    template_id: Option<String>,
    #[serde(default)]
    info: Option<NucleiInfo>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default, rename = "matched-at")]
    matched_at: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default, rename = "extracted-results")]
    extracted_results: Vec<String>,
}

async fn run_nuclei(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    let seeds: Vec<&Entity> = input.iter().filter(|e| e.entity_type == EntityType::Url).collect();
    if seeds.is_empty() {
        return Ok(Vec::new());
    }

    if which(BINARY).is_none() {
        return Err(Error::MissingBinary {
            plugin: "nuclei".into(),
            binary: BINARY.into(),
        });
    }

    let severity = config.get_array("severity").map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(",")
    });
    let tags = config
        .get_array("tags")
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","));

    let mut results = Vec::new();
    for seed in seeds {
        let mut args = vec!["-u".to_string(), seed.value.clone(), "-jsonl".to_string(), "-silent".to_string()];
        if let Some(sev) = &severity {
            args.push("-severity".to_string());
            args.push(sev.clone());
        }
        if let Some(t) = &tags {
            args.push("-tags".to_string());
            args.push(t.clone());
        }

        let output = Command::new(BINARY)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::PluginExecution {
                plugin: "nuclei".into(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::PluginExecution {
                plugin: "nuclei".into(),
                message: stderr.trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<NucleiLine>(line) else {
                continue;
            };
            let Some(template_id) = parsed.template_id else {
                continue;
            };

            let matched_at = parsed.matched_at.clone().unwrap_or_else(|| seed.value.clone());
            let entity = Entity::new(
                EntityType::Vulnerability,
                format!("{template_id}@{matched_at}"),
                "nuclei",
            )
            .with_metadata(serde_json::json!({
                "template_id": template_id,
                "name": parsed.info.as_ref().and_then(|i| i.name.clone()),
                "severity": parsed.info.as_ref().and_then(|i| i.severity.clone()),
                "tags": parsed.info.as_ref().map(|i| i.tags.clone()).unwrap_or_default(),
                "description": parsed.info.and_then(|i| i.description),
                "host": parsed.host,
                "matched_at": matched_at,
                "ip": parsed.ip,
                "extracted_results": parsed.extracted_results,
            }))
            .with_relation(seed.id, RelationKind::HasVulnerability);
            results.push(entity);
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_finding_line() {
        let line: NucleiLine = serde_json::from_str(
            r#"{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info","tags":["tech"]},"host":"https://example.com","matched-at":"https://example.com","ip":"1.2.3.4"}"#,
        )
        .unwrap();
        assert_eq!(line.template_id.as_deref(), Some("tech-detect"));
        assert_eq!(line.info.unwrap().severity.as_deref(), Some("info"));
    }

    #[test]
    fn missing_template_id_is_tolerated() {
        let line: NucleiLine = serde_json::from_str(r#"{"host":"https://example.com"}"#).unwrap();
        assert!(line.template_id.is_none());
    }

    #[tokio::test]
    async fn empty_input_produces_no_results() {
        let domain = Entity::new(EntityType::Domain, "example.com", "seed");
        let config = PluginConfig::default();
        let results = run_nuclei(&[domain], &config).await.unwrap();
        assert!(results.is_empty());
    }
}
