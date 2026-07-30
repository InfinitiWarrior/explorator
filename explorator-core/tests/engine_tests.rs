use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use explorator_core::{
    Entity, EntityType, Error, ExecutionEngine, PipelineDef, PluginConfig, PluginFuture,
    PluginRegistry, ReconPlugin, RelationKind,
};

/// A compiled-in test double: runs an arbitrary closure instead of shelling
/// out to a real recon tool, so the execution engine's scheduling,
/// dependency resolution, retry, and timeout behavior can be validated
/// without any external binaries.
type MockBehavior = Arc<dyn Fn(Vec<Entity>) -> Result<Vec<Entity>, Error> + Send + Sync>;

struct MockPlugin {
    name: &'static str,
    input_types: Vec<EntityType>,
    output_types: Vec<EntityType>,
    behavior: MockBehavior,
    delay: Option<Duration>,
}

impl MockPlugin {
    fn new(
        name: &'static str,
        behavior: impl Fn(Vec<Entity>) -> Result<Vec<Entity>, Error> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            input_types: vec![],
            output_types: vec![],
            behavior: Arc::new(behavior),
            delay: None,
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

impl ReconPlugin for MockPlugin {
    fn name(&self) -> &str {
        self.name
    }

    fn required_binary(&self) -> &str {
        "mock"
    }

    fn input_types(&self) -> Vec<EntityType> {
        self.input_types.clone()
    }

    fn output_types(&self) -> Vec<EntityType> {
        self.output_types.clone()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn run<'a>(&'a self, input: &'a [Entity], _config: &'a PluginConfig) -> PluginFuture<'a> {
        let owned_input = input.to_vec();
        let behavior = Arc::clone(&self.behavior);
        let delay = self.delay;
        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            behavior(owned_input)
        })
    }
}

fn registry_with(plugins: Vec<MockPlugin>) -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    for plugin in plugins {
        registry.register(Box::new(plugin));
    }
    registry
}

fn seed_domain(value: &str) -> Vec<Entity> {
    vec![Entity::new(EntityType::Domain, value, "seed")]
}

#[tokio::test]
async fn independent_stages_run_and_merge_into_one_graph() {
    let toml_str = r#"
        [pipeline]
        name = "parallel-test"
        concurrency = 4

        [[pipeline.stages]]
        name = "a"
        plugin = "mock-a"
        input = "seed"

        [[pipeline.stages]]
        name = "b"
        plugin = "mock-b"
        input = "seed"
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let plugin_a = MockPlugin::new("mock-a", |input| {
        let parent = &input[0];
        Ok(vec![Entity::new(EntityType::Subdomain, "from-a.example.com", "mock-a")
            .with_relation(parent.id, RelationKind::DiscoveredFrom)])
    });
    let plugin_b = MockPlugin::new("mock-b", |input| {
        let parent = &input[0];
        Ok(vec![Entity::new(EntityType::Subdomain, "from-b.example.com", "mock-b")
            .with_relation(parent.id, RelationKind::DiscoveredFrom)])
    });

    let registry = registry_with(vec![plugin_a, plugin_b]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let graph = engine
        .execute(&pipeline, seed_domain("example.com"))
        .await
        .expect("execution should succeed");

    // seed + 2 subdomains
    assert_eq!(graph.len(), 3);
    assert!(graph
        .find_by_value(EntityType::Subdomain, "from-a.example.com")
        .is_some());
    assert!(graph
        .find_by_value(EntityType::Subdomain, "from-b.example.com")
        .is_some());
}

#[tokio::test]
async fn dependent_stage_receives_upstream_output_as_input() {
    let toml_str = r#"
        [pipeline]
        name = "dependency-test"

        [[pipeline.stages]]
        name = "subdomains"
        plugin = "mock-subfinder"
        input = "seed"

        [[pipeline.stages]]
        name = "resolve"
        plugin = "mock-dnsx"
        input = "subdomains"
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let subfinder = MockPlugin::new("mock-subfinder", |input| {
        let domain = &input[0];
        Ok(vec![Entity::new(EntityType::Subdomain, "www.example.com", "mock-subfinder")
            .with_relation(domain.id, RelationKind::DiscoveredFrom)])
    });
    let dnsx = MockPlugin::new("mock-dnsx", |input| {
        // Proves dependency resolution actually piped subfinder's output in,
        // not the seed: if it saw the seed we'd get "example.com-ip" instead.
        assert_eq!(input.len(), 1);
        assert_eq!(input[0].value, "www.example.com");
        let sub = &input[0];
        let ip = Entity::new(EntityType::IpAddress, "203.0.113.5", "mock-dnsx");
        // Re-emit the subdomain (dedups against the existing node) carrying
        // the new resolves_to relation, mirroring how the real dnsx plugin
        // links a host to the IPs it resolved.
        let updated_sub = Entity::new(sub.entity_type, sub.value.clone(), "mock-dnsx")
            .with_relation(ip.id, RelationKind::ResolvesTo);
        Ok(vec![ip, updated_sub])
    });

    let registry = registry_with(vec![subfinder, dnsx]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let graph = engine
        .execute(&pipeline, seed_domain("example.com"))
        .await
        .expect("execution should succeed");

    let ip = graph
        .find_by_value(EntityType::IpAddress, "203.0.113.5")
        .expect("ip address entity should exist");
    let subdomain = graph
        .find_by_value(EntityType::Subdomain, "www.example.com")
        .expect("subdomain entity should exist");

    // The subdomain has two outbound relations: DiscoveredFrom -> the seed
    // domain (from subfinder) and ResolvesTo -> the ip (from dnsx).
    let relations = graph.relations_of(subdomain.id);
    assert_eq!(relations.len(), 2);
    let resolves_to = relations
        .iter()
        .find(|(kind, _)| matches!(kind, RelationKind::ResolvesTo))
        .expect("subdomain should have a resolves_to relation");
    assert_eq!(resolves_to.1.id, ip.id);
}

#[tokio::test]
async fn depends_on_enforces_ordering_without_supplying_input() {
    let toml_str = r#"
        [pipeline]
        name = "ordering-test"
        concurrency = 4

        [[pipeline.stages]]
        name = "first"
        plugin = "mock-first"
        input = "seed"

        [[pipeline.stages]]
        name = "second"
        plugin = "mock-second"
        input = "seed"
        depends_on = ["first"]
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));

    let order_first = Arc::clone(&order);
    let first = MockPlugin::new("mock-first", move |_input| {
        order_first.lock().unwrap().push("first");
        Ok(vec![])
    })
    .with_delay(Duration::from_millis(150));

    let order_second = Arc::clone(&order);
    let second = MockPlugin::new("mock-second", move |input| {
        order_second.lock().unwrap().push("second");
        // "second" declares input = "seed", so it must still see the seed
        // entity, not first's (empty) output, even though it waits on it.
        assert_eq!(input.len(), 1);
        Ok(vec![])
    });

    let registry = registry_with(vec![first, second]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    engine
        .execute(&pipeline, seed_domain("example.com"))
        .await
        .expect("execution should succeed");

    assert_eq!(*order.lock().unwrap(), vec!["first", "second"]);
}

#[tokio::test]
async fn cyclic_dependencies_are_rejected() {
    let toml_str = r#"
        [pipeline]
        name = "cycle-test"

        [[pipeline.stages]]
        name = "a"
        plugin = "mock-a"
        input = "seed"
        depends_on = ["b"]

        [[pipeline.stages]]
        name = "b"
        plugin = "mock-b"
        input = "seed"
        depends_on = ["a"]
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let a = MockPlugin::new("mock-a", |_| Ok(vec![]));
    let b = MockPlugin::new("mock-b", |_| Ok(vec![]));
    let registry = registry_with(vec![a, b]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let result = engine.execute(&pipeline, seed_domain("example.com")).await;
    assert!(matches!(result, Err(Error::InvalidPipeline(_))));
}

#[tokio::test]
async fn unknown_plugin_reference_is_rejected() {
    let toml_str = r#"
        [pipeline]
        name = "missing-plugin-test"

        [[pipeline.stages]]
        name = "only"
        plugin = "does-not-exist"
        input = "seed"
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();
    let registry = registry_with(vec![]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let result = engine.execute(&pipeline, seed_domain("example.com")).await;
    assert!(matches!(result, Err(Error::UnknownPlugin(_))));
}

#[tokio::test]
async fn stage_retries_on_failure_and_eventually_succeeds() {
    let toml_str = r#"
        [pipeline]
        name = "retry-test"

        [[pipeline.stages]]
        name = "flaky"
        plugin = "mock-flaky"
        input = "seed"
        retries = 2
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_clone = Arc::clone(&attempts);
    let flaky = MockPlugin::new("mock-flaky", move |_input| {
        let n = attempts_clone.fetch_add(1, Ordering::SeqCst) + 1;
        if n < 3 {
            Err(Error::PluginExecution {
                plugin: "mock-flaky".into(),
                message: format!("attempt {n} failed"),
            })
        } else {
            Ok(vec![Entity::new(EntityType::Subdomain, "recovered.example.com", "mock-flaky")])
        }
    });

    let registry = registry_with(vec![flaky]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let graph = engine
        .execute(&pipeline, seed_domain("example.com"))
        .await
        .expect("should eventually succeed after retries");

    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert!(graph
        .find_by_value(EntityType::Subdomain, "recovered.example.com")
        .is_some());
}

#[tokio::test]
async fn stage_exceeding_timeout_fails_the_pipeline() {
    let toml_str = r#"
        [pipeline]
        name = "timeout-test"

        [[pipeline.stages]]
        name = "slow"
        plugin = "mock-slow"
        input = "seed"
        timeout_secs = 1
    "#;
    let pipeline = PipelineDef::parse(toml_str).unwrap();

    let slow = MockPlugin::new("mock-slow", |_input| Ok(vec![])).with_delay(Duration::from_secs(3));
    let registry = registry_with(vec![slow]);
    let engine = ExecutionEngine::new(Arc::new(registry));

    let result = engine.execute(&pipeline, seed_domain("example.com")).await;
    assert!(matches!(result, Err(Error::Timeout { .. })));
}
