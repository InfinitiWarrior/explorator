use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use explorator_core::{Entity, EntityType, ExecutionEngine, PipelineDef, PluginRegistry, SEED_INPUT};

#[derive(Parser)]
#[command(name = "explorator", version, about = "Full-spectrum recon orchestration framework")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a pipeline from the terminal, streaming results to stdout.
    Run {
        /// Path to a pipeline TOML file.
        pipeline: PathBuf,
        /// Seed target: a domain, IP address, or CIDR range.
        #[arg(long)]
        target: String,
    },
    /// List compiled-in plugins and whether their required binaries are installed.
    Plugins,
    /// Validate a pipeline definition without running it.
    Validate {
        /// Path to a pipeline TOML file.
        pipeline: PathBuf,
    },
    /// Export a completed job's results.
    Export {
        job_id: String,
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },
    /// Start the API server.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
    Markdown,
}

fn build_registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    explorator_plugins::register_all(&mut registry);
    registry
}

/// Guess the entity type of a raw seed string: an IP address, a CIDR
/// range, or (the common case) a domain name.
fn classify_seed(target: &str) -> Entity {
    if target.parse::<std::net::IpAddr>().is_ok() {
        Entity::new(EntityType::IpAddress, target, "seed")
    } else if target.contains('/') {
        Entity::new(EntityType::Cidr, target, "seed")
    } else {
        Entity::new(EntityType::Domain, target, "seed")
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Run { pipeline, target } => run_pipeline(pipeline, target).await,
        Commands::Plugins => list_plugins(),
        Commands::Validate { pipeline } => validate_pipeline(pipeline),
        Commands::Export { job_id, format } => export_job(job_id, format),
        Commands::Serve { addr } => serve(addr),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_pipeline(pipeline_path: PathBuf, target: String) -> Result<(), String> {
    let toml_str = std::fs::read_to_string(&pipeline_path)
        .map_err(|e| format!("failed to read {}: {e}", pipeline_path.display()))?;
    let pipeline = PipelineDef::parse(&toml_str).map_err(|e| e.to_string())?;

    let registry = build_registry();
    for stage in &pipeline.stages {
        if !registry.contains(&stage.plugin) {
            return Err(format!(
                "stage '{}' references unknown plugin '{}'",
                stage.name, stage.plugin
            ));
        }
    }

    let seed = vec![classify_seed(&target)];
    log::info!(
        "running pipeline '{}' ({} stages) against seed '{target}'",
        pipeline.name,
        pipeline.stages.len()
    );

    let engine = ExecutionEngine::new(Arc::new(registry));
    let graph = engine.execute(&pipeline, seed).await.map_err(|e| e.to_string())?;

    let snapshot = graph.to_snapshot();
    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
    println!("{json}");

    log::info!(
        "pipeline complete: {} entities, {} relations",
        snapshot.nodes.len(),
        snapshot.edges.len()
    );

    Ok(())
}

fn list_plugins() -> Result<(), String> {
    let registry = build_registry();
    println!("{:<12} {:<12} {:<10}", "PLUGIN", "BINARY", "AVAILABLE");
    for plugin in registry.iter() {
        println!(
            "{:<12} {:<12} {:<10}",
            plugin.name(),
            plugin.required_binary(),
            if plugin.is_available() { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn validate_pipeline(pipeline_path: PathBuf) -> Result<(), String> {
    let toml_str = std::fs::read_to_string(&pipeline_path)
        .map_err(|e| format!("failed to read {}: {e}", pipeline_path.display()))?;
    let pipeline = PipelineDef::parse(&toml_str).map_err(|e| e.to_string())?;

    let registry = build_registry();
    let mut errors = Vec::new();

    for stage in &pipeline.stages {
        let Ok(plugin) = registry.get(&stage.plugin) else {
            errors.push(format!("stage '{}': unknown plugin '{}'", stage.name, stage.plugin));
            continue;
        };

        if stage.input != SEED_INPUT {
            let Some(upstream) = pipeline.stage(&stage.input) else {
                errors.push(format!(
                    "stage '{}': input '{}' is not a known stage",
                    stage.name, stage.input
                ));
                continue;
            };
            if let Ok(upstream_plugin) = registry.get(&upstream.plugin) {
                let produces = upstream_plugin.output_types();
                let accepts = plugin.input_types();
                if !produces.iter().any(|t| accepts.contains(t)) {
                    errors.push(format!(
                        "stage '{}': plugin '{}' accepts {:?} but upstream stage '{}' (plugin '{}') produces {:?}",
                        stage.name, plugin.name(), accepts, upstream.name, upstream_plugin.name(), produces
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        println!(
            "pipeline '{}' is valid: {} stage(s), plugins and types check out",
            pipeline.name,
            pipeline.stages.len()
        );
        Ok(())
    } else {
        for e in &errors {
            eprintln!("  - {e}");
        }
        Err(format!("pipeline '{}' failed validation ({} issue(s))", pipeline.name, errors.len()))
    }
}

fn export_job(_job_id: String, _format: ExportFormat) -> Result<(), String> {
    Err("export is not yet implemented — it depends on the job store in explorator-api".to_string())
}

fn serve(_addr: String) -> Result<(), String> {
    Err("serve is not yet implemented — explorator-api is currently a scaffold".to_string())
}
