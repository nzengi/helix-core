use helix_chain::{HelixNode, config::Config};
use std::sync::Arc;
use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path},
    response::IntoResponse,
    http::StatusCode,
};
use tower_http::{trace::TraceLayer, cors::CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use anyhow::Result;

#[derive(Clone)]
struct AppState {
    node: Arc<HelixNode>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = Config::load("config/default.toml")?;

    // Create and start node
    let node = Arc::new(HelixNode::new(config.clone()).await?);
    node.start().await?;

    let state = AppState { node: node.clone() };

    // Build API router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/status", get(get_node_status))
        .route("/api/v1/transaction", post(submit_transaction))
        .route("/api/v1/balance/:address", get(get_balance))
        .route("/api/v1/block/:hash", get(get_block))
        .route("/api/v1/tx/:hash", get(get_transaction))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let bind_addr = format!("0.0.0.0:{}", config.api.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    tracing::info!("🚀 HelixChain node running on http://{}", bind_addr);

    // Graceful shutdown
    let server = axum::serve(listener, app);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
            node.stop().await?;
        }
    }

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn get_node_status(State(state): State<AppState>) -> impl IntoResponse {
    match state.node.chain_state.get_status().await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get node status: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

async fn submit_transaction(
    State(state): State<AppState>,
    Json(tx): Json<serde_json::Value>,
) -> impl IntoResponse {
    // TODO: Implement transaction submission with proper validation
    (StatusCode::NOT_IMPLEMENTED, "Not implemented yet").into_response()
}

async fn get_balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_account_balance(&address).await {
        Ok(balance) => (StatusCode::OK, Json(balance)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get balance for {}: {}", address, e);
            (StatusCode::NOT_FOUND, "Account not found").into_response()
        }
    }
}

async fn get_block(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_block(&hash).await {
        Ok(Some(block)) => (StatusCode::OK, Json(block)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Block not found").into_response(),
        Err(e) => {
            tracing::error!("Failed to get block {}: {}", hash, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

async fn get_transaction(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_transaction(&hash).await {
        Ok(Some(tx)) => (StatusCode::OK, Json(tx)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Transaction not found").into_response(),
        Err(e) => {
            tracing::error!("Failed to get transaction {}: {}", hash, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}