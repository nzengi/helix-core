use std::sync::Arc;
use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path, Query},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use anyhow::Result;

use crate::HelixNode;
use crate::consensus::{Transaction, Validator};
use crate::state::{Account, ChainStatus, Block};

#[derive(Clone)]
pub struct ApiState {
    pub node: Arc<HelixNode>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub data: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorRequest {
    pub address: String,
    pub stake: u64,
    pub beta_angle: f64,
    pub efficiency: f64,
}

#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u64>,
    pub limit: Option<u64>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/status", get(get_node_status))
        .route("/api/v1/blocks", get(get_blocks))
        .route("/api/v1/blocks/:hash", get(get_block))
        .route("/api/v1/transactions", get(get_transactions))
        .route("/api/v1/transactions/:hash", get(get_transaction))
        .route("/api/v1/transactions", post(submit_transaction))
        .route("/api/v1/accounts/:address", get(get_account))
        .route("/api/v1/accounts/:address/balance", get(get_balance))
        .route("/api/v1/validators", get(get_validators))
        .route("/api/v1/validators", post(add_validator))
        .route("/api/v1/metrics", get(get_metrics))
        .with_state(state)
}

async fn health_check() -> impl IntoResponse {
    Json(ApiResponse::success("HelixChain node is healthy"))
}

async fn get_node_status(State(state): State<ApiState>) -> impl IntoResponse {
    match state.node.chain_state.get_status().await {
        Ok(status) => Json(ApiResponse::success(status)),
        Err(e) => {
            tracing::error!("Failed to get node status: {}", e);
            Json(ApiResponse::<ChainStatus>::error(e.to_string()))
        }
    }
}

async fn get_blocks(
    State(_state): State<ApiState>,
    Query(_pagination): Query<PaginationQuery>,
) -> impl IntoResponse {
    // TODO: Implement pagination logic
    Json(ApiResponse::success(Vec::<Block>::new()))
}

async fn get_block(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_block(&hash).await {
        Ok(Some(block)) => Json(ApiResponse::success(block)),
        Ok(None) => Json(ApiResponse::<Block>::error("Block not found".to_string())),
        Err(e) => {
            tracing::error!("Failed to get block {}: {}", hash, e);
            Json(ApiResponse::<Block>::error(e.to_string()))
        }
    }
}

async fn get_transactions(
    State(_state): State<ApiState>,
    Query(_pagination): Query<PaginationQuery>,
) -> impl IntoResponse {
    // TODO: Implement pagination logic
    Json(ApiResponse::success(Vec::<Transaction>::new()))
}

async fn get_transaction(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_transaction(&hash).await {
        Ok(Some(tx)) => Json(ApiResponse::success(tx)),
        Ok(None) => Json(ApiResponse::<Transaction>::error("Transaction not found".to_string())),
        Err(e) => {
            tracing::error!("Failed to get transaction {}: {}", hash, e);
            Json(ApiResponse::<Transaction>::error(e.to_string()))
        }
    }
}

async fn submit_transaction(
    State(state): State<ApiState>,
    Json(tx_req): Json<TransactionRequest>,
) -> impl IntoResponse {
    let tx = Transaction {
        hash: format!("tx_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        from: tx_req.from,
        to: tx_req.to,
        amount: tx_req.amount,
        gas_price: tx_req.gas_price,
        gas_limit: tx_req.gas_limit,
        nonce: 0, // TODO: Get from account
        data: tx_req.data.unwrap_or_default(),
        signature: String::new(), // TODO: Validate signature
        timestamp: chrono::Utc::now(),
    };

    // TODO: Add transaction to mempool and validate
    Json(ApiResponse::success(tx))
}

async fn get_account(
    State(state): State<ApiState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_account(&address).await {
        Some(account) => Json(ApiResponse::success(account)),
        None => Json(ApiResponse::<Account>::error("Account not found".to_string())),
    }
}

async fn get_balance(
    State(state): State<ApiState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_account_balance(&address).await {
        Ok(balance) => Json(ApiResponse::success(balance)),
        Err(e) => {
            tracing::error!("Failed to get balance for {}: {}", address, e);
            Json(ApiResponse::<u64>::error(e.to_string()))
        }
    }
}

async fn get_validators(State(state): State<ApiState>) -> impl IntoResponse {
    // TODO: Get validators from consensus manager
    Json(ApiResponse::success(Vec::<Validator>::new()))
}

async fn add_validator(
    State(state): State<ApiState>,
    Json(validator_req): Json<ValidatorRequest>,
) -> impl IntoResponse {
    let validator = Validator {
        address: validator_req.address,
        stake: validator_req.stake,
        beta_angle: validator_req.beta_angle,
        efficiency: validator_req.efficiency,
        last_active: chrono::Utc::now(),
        is_active: true,
    };

    let consensus = &state.node.consensus;
    match consensus.add_validator(validator.clone()).await {
        Ok(_) => Json(ApiResponse::success(validator)),
        Err(e) => {
            tracing::error!("Failed to add validator: {}", e);
            Json(ApiResponse::<Validator>::error(e.to_string()))
        }
    }
}

async fn get_metrics(State(state): State<ApiState>) -> impl IntoResponse {
    // TODO: Get system metrics
    let metrics = serde_json::json!({
        "uptime": "1h 30m",
        "memory_usage": "256MB",
        "cpu_usage": "15%",
        "network_peers": 5
    });
    Json(ApiResponse::success(metrics))
}