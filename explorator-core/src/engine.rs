use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use petgraph::algo::toposort;
use petgraph::graph::DiGraph;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::entity::Entity;
use crate::error::{Error, Result};
use crate::graph::EntityGraph;
use crate::pipeline::{PipelineDef, StageDef, SEED_INPUT};
use crate::plugin::{PluginConfig, PluginRegistry};

/// The entities produced by a single completed stage.
pub struct StageOutcome {
    pub stage: String,
    pub entities: Vec<Entity>,
}

/// Broadcast once a stage finishes: `None` while running, `Some(entities)`
/// once done (an empty vec if the stage ultimately errored, so waiting
/// dependents unblock instead of hanging forever).
type StageChannel = (
    watch::Sender<Option<Arc<Vec<Entity>>>>,
    watch::Receiver<Option<Arc<Vec<Entity>>>>,
);

/// Runs a `PipelineDef` to completion: topologically orders stages by
/// dependency, executes independent stages concurrently (bounded by the
/// pipeline's `concurrency` setting) as tokio tasks, and merges every
/// stage's output entities into a single `EntityGraph`.
pub struct ExecutionEngine {
    registry: Arc<PluginRegistry>,
}

impl ExecutionEngine {
    pub fn new(registry: Arc<PluginRegistry>) -> Self {
        Self { registry }
    }

    pub async fn execute(&self, pipeline: &PipelineDef, seed: Vec<Entity>) -> Result<EntityGraph> {
        pipeline.validate()?;
        for stage in &pipeline.stages {
            self.registry.get(&stage.plugin)?;
        }
        assert_acyclic(pipeline)?;

        let semaphore = Arc::new(Semaphore::new(pipeline.concurrency.max(1)));
        let seed = Arc::new(seed);

        let mut channels: HashMap<String, StageChannel> = HashMap::new();
        for stage in &pipeline.stages {
            channels.insert(stage.name.clone(), watch::channel(None));
        }

        let mut join_set: JoinSet<Result<StageOutcome>> = JoinSet::new();

        for stage in pipeline.stages.iter().cloned() {
            let registry = Arc::clone(&self.registry);
            let semaphore = Arc::clone(&semaphore);
            let seed = Arc::clone(&seed);

            let (tx, _) = channels.get(&stage.name).expect("channel exists for every stage");
            let tx = tx.clone();

            let extra_dep_rxs: Vec<watch::Receiver<_>> = stage
                .depends_on
                .iter()
                .filter(|d| d.as_str() != stage.input)
                .map(|d| channels.get(d).expect("validated dependency").1.clone())
                .collect();

            let input_rx = if stage.input == SEED_INPUT {
                None
            } else {
                Some(channels.get(&stage.input).expect("validated input").1.clone())
            };

            join_set.spawn(async move {
                for mut rx in extra_dep_rxs {
                    wait_for_stage(&mut rx).await;
                }

                let input_entities = match input_rx {
                    Some(mut rx) => wait_for_stage(&mut rx).await,
                    None => Arc::clone(&seed),
                };

                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("semaphore is never closed during execution");

                let plugin = registry.get(&stage.plugin)?;
                let config = PluginConfig::from_toml_table(stage.config.clone());

                let result = run_with_retry(plugin, &input_entities, &config, &stage).await;

                let broadcast = match &result {
                    Ok(entities) => Arc::new(entities.clone()),
                    Err(_) => Arc::new(Vec::new()),
                };
                let _ = tx.send(Some(broadcast));

                result.map(|entities| StageOutcome {
                    stage: stage.name.clone(),
                    entities,
                })
            });
        }

        let mut graph = EntityGraph::new();
        graph.add_entities(seed.iter().cloned());

        let mut first_error = None;
        while let Some(joined) = join_set.join_next().await {
            match joined.expect("stage task panicked") {
                Ok(outcome) => graph.add_entities(outcome.entities),
                Err(e) if first_error.is_none() => first_error = Some(e),
                Err(_) => {}
            }
        }

        if let Some(e) = first_error {
            return Err(e);
        }

        Ok(graph)
    }
}

async fn wait_for_stage(rx: &mut watch::Receiver<Option<Arc<Vec<Entity>>>>) -> Arc<Vec<Entity>> {
    if rx.borrow().is_some() {
        return rx.borrow().clone().unwrap();
    }
    match rx.wait_for(|v| v.is_some()).await {
        Ok(guard) => guard.clone().unwrap(),
        Err(_) => Arc::new(Vec::new()),
    }
}

async fn run_with_retry(
    plugin: &dyn crate::plugin::ReconPlugin,
    input: &[Entity],
    config: &PluginConfig,
    stage: &StageDef,
) -> Result<Vec<Entity>> {
    let max_attempts = stage.retries + 1;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        let run_fut = plugin.run(input, config);
        let outcome = match stage.timeout_secs {
            Some(secs) => match tokio::time::timeout(Duration::from_secs(secs), run_fut).await {
                Ok(res) => res,
                Err(_) => Err(Error::Timeout {
                    stage: stage.name.clone(),
                    secs,
                }),
            },
            None => run_fut.await,
        };

        match outcome {
            Ok(entities) => return Ok(entities),
            Err(_e) if attempt < max_attempts => {
                let backoff_ms = 200u64 * 2u64.pow(attempt.min(5) - 1);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Detect cycles in the stage dependency graph up front so a malformed
/// pipeline fails fast instead of deadlocking on unsatisfiable `wait_for`s.
fn assert_acyclic(pipeline: &PipelineDef) -> Result<()> {
    let mut graph = DiGraph::<&str, ()>::new();
    let mut nodes = HashMap::new();
    for stage in &pipeline.stages {
        nodes.insert(stage.name.as_str(), graph.add_node(stage.name.as_str()));
    }
    for stage in &pipeline.stages {
        for dep in stage.dependencies() {
            if let (Some(&from), Some(&to)) = (nodes.get(dep), nodes.get(stage.name.as_str())) {
                graph.add_edge(from, to, ());
            }
        }
    }
    toposort(&graph, None)
        .map(|_| ())
        .map_err(|cycle| {
            let name = graph[cycle.node_id()];
            Error::InvalidPipeline(format!("dependency cycle detected at stage '{name}'"))
        })
}
