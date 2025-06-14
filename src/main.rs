use helix_chain::{HelixNode, config::Config, consensus::Transaction};
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
use serde::{Serialize, Deserialize};
use sha3::Digest;

#[derive(Clone)]
struct AppState {
    node: Arc<HelixNode>,
}

#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TransactionRequest {
    from: String,
    to: String,
    amount: u64,
    gas_price: u64,
    gas_limit: u64,
    data: Option<String>,
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
    let port = config.api.port;
    let bind_addr = format!("0.0.0.0:{}", port);
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
    Json(tx_req): Json<TransactionRequest>,
) -> impl IntoResponse {
    // Create transaction from request
    let transaction = Transaction {
        hash: format!("0x{:x}", sha3::Keccak256::digest(
            format!("{}{}{}", tx_req.from, tx_req.to, tx_req.amount).as_bytes()
        )),
        from: tx_req.from,
        to: tx_req.to,
        amount: tx_req.amount,
        gas_price: tx_req.gas_price,
        gas_limit: tx_req.gas_limit,
        nonce: 0, // Will be set by the node
        data: tx_req.data.unwrap_or_default().into_bytes(),
        signature: String::new(), // Will be signed by the node
        timestamp: chrono::Utc::now(),
    };

    match state.node.submit_transaction(transaction).await {
        Ok(tx_hash) => (StatusCode::OK, Json(ApiResponse::success(tx_hash))).into_response(),
        Err(e) => {
            tracing::error!("Failed to submit transaction: {}", e);
            (StatusCode::BAD_REQUEST, Json(ApiResponse::<String>::error(e.to_string()))).into_response()
        }
    }
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