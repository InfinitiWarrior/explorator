use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;

/// Scaffold only: routes are wired up to match the intended API surface,
/// but job execution, SQLite persistence, and the WebSocket stream are not
/// implemented yet. Every handler below returns 501 until that lands.
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/pipeline/run", post(not_implemented))
        .route("/api/job/:id", get(not_implemented))
        .route("/api/job/:id/results", get(not_implemented))
        .route("/api/job/:id/report", get(not_implemented))
        .route("/api/entities", get(not_implemented))
        .route("/ws/job/:id", get(not_implemented));

    let addr = "127.0.0.1:8080";
    log::info!("explorator-api listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("failed to bind address");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "not implemented",
            "detail": "explorator-api is currently a scaffold; job persistence and execution wiring are future work"
        })),
    )
}
