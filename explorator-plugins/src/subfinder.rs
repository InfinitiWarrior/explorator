use std::process::Stdio;

use explorator_core::plugin::which;
use explorator_core::{Entity, EntityType, Error, PluginConfig, PluginFuture, ReconPlugin, RelationKind, Result};
use tokio::process::Command;

const BINARY: &str = "subfinder";

/// Wraps ProjectDiscovery's `subfinder` for passive subdomain enumeration.
pub struct SubfinderPlugin;

impl ReconPlugin for SubfinderPlugin {
    fn name(&self) -> &str {
        "subfinder"
    }

    fn required_binary(&self) -> &str {
        BINARY
    }

    fn input_types(&self) -> Vec<EntityType> {
        vec![EntityType::Domain]
    }

    fn output_types(&self) -> Vec<EntityType> {
        vec![EntityType::Subdomain]
    }

    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a> {
        Box::pin(async move { run_subfinder(input, config).await })
    }
}

#[derive(serde::Deserialize)]
struct SubfinderLine {
    host: String,
    #[serde(default)]
    source: Option<String>,
}

async fn run_subfinder(input: &[Entity], config: &PluginConfig) -> Result<Vec<Entity>> {
    if which(BINARY).is_none() {
        return Err(Error::MissingBinary {
            plugin: "subfinder".into(),
            binary: BINARY.into(),
        });
    }

    let query_all_sources = config.get_bool("all").unwrap_or(false);
    let domains: Vec<&Entity> = input
        .iter()
        .filter(|e| e.entity_type == EntityType::Domain)
        .collect();

    let mut results = Vec::new();
    for domain in domains {
        let mut args = vec![
            "-d".to_string(),
            domain.value.clone(),
            "-json".to_string(),
            "-silent".to_string(),
        ];
        if query_all_sources {
            args.push("-all".to_string());
        }

        let output = Command::new(BINARY)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::PluginExecution {
                plugin: "subfinder".into(),
                message: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::PluginExecution {
                plugin: "subfinder".into(),
                message: stderr.trim().to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(parsed) = serde_json::from_str::<SubfinderLine>(line) else {
                continue;
            };
            let discovery_source = parsed.source.unwrap_or_else(|| "subfinder".to_string());
            let entity = Entity::new(EntityType::Subdomain, parsed.host, "subfinder")
                .with_metadata(serde_json::json!({ "discovery_source": discovery_source }))
                .with_relation(domain.id, RelationKind::DiscoveredFrom);
            results.push(entity);
        }
    }

    Ok(results)
}
