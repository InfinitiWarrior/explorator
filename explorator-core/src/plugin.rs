use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::entity::{Entity, EntityType};
use crate::error::{Error, Result};

/// Tool-specific arguments for a single stage, taken verbatim from the
/// pipeline TOML's `config` table and converted to JSON so plugins don't
/// need to depend on the `toml` crate themselves.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig(pub serde_json::Value);

impl PluginConfig {
    pub fn from_toml_table(table: toml::value::Table) -> Self {
        let json = serde_json::to_value(table).unwrap_or(serde_json::Value::Null);
        Self(json)
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn get_array(&self, key: &str) -> Option<&Vec<serde_json::Value>> {
        self.get(key).and_then(|v| v.as_array())
    }
}

/// A boxed, `Send` future — the manual desugaring of an `async fn` in a
/// trait. Written out by hand (rather than via the `async-trait` macro) so
/// `ReconPlugin` stays free of extra dependencies while remaining object
/// safe, i.e. usable as `Box<dyn ReconPlugin>` in the plugin registry.
pub type PluginFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Entity>>> + Send + 'a>>;

/// Implemented by every recon tool wrapper (subfinder, dnsx, httpx, ...).
/// Plugins are compiled in and registered by name at startup; there is no
/// dynamic loading.
pub trait ReconPlugin: Send + Sync {
    /// Stable identifier used in pipeline TOML `plugin = "..."` fields.
    fn name(&self) -> &str;

    /// The external CLI binary this plugin shells out to, e.g. "subfinder".
    fn required_binary(&self) -> &str;

    fn input_types(&self) -> Vec<EntityType>;

    fn output_types(&self) -> Vec<EntityType>;

    /// Run the underlying tool against `input` entities and normalize its
    /// output into the unified `Entity` model.
    fn run<'a>(&'a self, input: &'a [Entity], config: &'a PluginConfig) -> PluginFuture<'a>;

    /// Whether `required_binary()` is discoverable on PATH.
    fn is_available(&self) -> bool {
        which(self.required_binary()).is_some()
    }
}

/// Locate a binary on PATH without shelling out to `which`/`command -v`,
/// so availability checks work the same on every platform.
pub fn which(binary: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Compiled-in lookup table of every available plugin, keyed by name.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn ReconPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: Box<dyn ReconPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }

    pub fn get(&self, name: &str) -> Result<&dyn ReconPlugin> {
        self.plugins
            .get(name)
            .map(|p| p.as_ref())
            .ok_or_else(|| Error::UnknownPlugin(name.to_string()))
    }

    pub fn contains(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn ReconPlugin> {
        self.plugins.values().map(|p| p.as_ref())
    }
}
