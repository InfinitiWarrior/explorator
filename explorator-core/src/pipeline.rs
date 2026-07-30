use std::collections::HashSet;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The special `input` value meaning "use the seed entities the pipeline
/// was invoked with", rather than the output of another stage.
pub const SEED_INPUT: &str = "seed";

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineFile {
    pub pipeline: PipelineDef,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Max number of stages allowed to run concurrently. Defaults to 4.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(rename = "stages")]
    pub stages: Vec<StageDef>,
}

fn default_concurrency() -> usize {
    4
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageDef {
    pub name: String,
    pub plugin: String,
    /// Either `"seed"` or the `name` of a preceding stage whose output
    /// entities are fed in as this stage's input.
    pub input: String,
    /// Extra ordering-only dependencies: stages that must complete before
    /// this one starts, but whose output is not used as input.
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub config: toml::value::Table,
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub retries: u32,
}

impl StageDef {
    /// All stages this one must wait for: its `input` stage (if not the
    /// seed) plus any explicit `depends_on` entries.
    pub fn dependencies(&self) -> Vec<&str> {
        let mut deps: Vec<&str> = self.depends_on.iter().map(String::as_str).collect();
        if self.input != SEED_INPUT {
            deps.push(self.input.as_str());
        }
        deps
    }
}

impl PipelineDef {
    pub fn parse(toml_str: &str) -> Result<Self> {
        let file: PipelineFile = toml::from_str(toml_str)?;
        file.pipeline.validate()?;
        Ok(file.pipeline)
    }

    pub fn stage(&self, name: &str) -> Option<&StageDef> {
        self.stages.iter().find(|s| s.name == name)
    }

    /// Structural validation that doesn't require a plugin registry:
    /// unique stage names, and every referenced dependency resolves to
    /// either "seed" or a real stage.
    pub fn validate(&self) -> Result<()> {
        if self.stages.is_empty() {
            return Err(Error::InvalidPipeline("pipeline has no stages".into()));
        }

        let mut seen = HashSet::new();
        for stage in &self.stages {
            if !seen.insert(stage.name.as_str()) {
                return Err(Error::InvalidPipeline(format!(
                    "duplicate stage name '{}'",
                    stage.name
                )));
            }
        }

        for stage in &self.stages {
            for dep in stage.dependencies() {
                if dep != SEED_INPUT && !seen.contains(dep) {
                    return Err(Error::InvalidPipeline(format!(
                        "stage '{}' depends on unknown stage '{}'",
                        stage.name, dep
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
        [pipeline]
        name = "full-domain-recon"
        description = "Complete domain reconnaissance pipeline"
        concurrency = 4

        [[pipeline.stages]]
        name = "subdomains"
        plugin = "subfinder"
        input = "seed"

        [[pipeline.stages]]
        name = "dns-resolve"
        plugin = "dnsx"
        input = "subdomains"
        config = { record_types = ["A", "AAAA", "CNAME", "MX"] }
    "#;

    #[test]
    fn parses_example_pipeline() {
        let pipeline = PipelineDef::parse(EXAMPLE).unwrap();
        assert_eq!(pipeline.name, "full-domain-recon");
        assert_eq!(pipeline.concurrency, 4);
        assert_eq!(pipeline.stages.len(), 2);
        assert_eq!(pipeline.stages[1].dependencies(), vec!["subdomains"]);
    }

    #[test]
    fn rejects_duplicate_stage_names() {
        let toml_str = r#"
            [pipeline]
            name = "bad"
            [[pipeline.stages]]
            name = "dup"
            plugin = "subfinder"
            input = "seed"
            [[pipeline.stages]]
            name = "dup"
            plugin = "dnsx"
            input = "seed"
        "#;
        assert!(PipelineDef::parse(toml_str).is_err());
    }

    #[test]
    fn rejects_unknown_dependency() {
        let toml_str = r#"
            [pipeline]
            name = "bad"
            [[pipeline.stages]]
            name = "only"
            plugin = "subfinder"
            input = "does-not-exist"
        "#;
        assert!(PipelineDef::parse(toml_str).is_err());
    }
}
