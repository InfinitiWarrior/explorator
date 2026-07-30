pub mod engine;
pub mod entity;
pub mod error;
pub mod graph;
pub mod pipeline;
pub mod plugin;

pub use engine::{ExecutionEngine, StageOutcome};
pub use entity::{Entity, EntityType, Relation, RelationKind};
pub use error::{Error, Result};
pub use graph::{EdgeSnapshot, EntityGraph, GraphSnapshot};
pub use pipeline::{PipelineDef, StageDef, SEED_INPUT};
pub use plugin::{PluginConfig, PluginFuture, PluginRegistry, ReconPlugin};
