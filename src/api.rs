use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::consensus::{Transaction, Validator};
use crate::state::{Account, Block, ChainStatus};
use crate::HelixNode;

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

#[derive(Serialize, Deserialize)]
pub struct SystemMetrics {
    pub uptime: String,
    pub memory_usage: String,
    pub cpu_usage: String,
    pub network_peers: u64,
    pub block_height: u64,
    pub pending_transactions: u64,
    pub total_transactions: u64,
    pub validator_count: u64,
    pub chain_state: String,
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
    State(state): State<ApiState>,
    Query(pagination): Query<PaginationQuery>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10).min(100); // Max 100 blocks per page

    match get_paginated_blocks(&state, page, limit).await {
        Ok(blocks) => Json(ApiResponse::success(blocks)),
        Err(e) => {
            tracing::error!("Failed to get blocks: {}", e);
            Json(ApiResponse::<Vec<Block>>::error(e.to_string()))
        }
    }
}

async fn get_block(State(state): State<ApiState>, Path(hash): Path<String>) -> impl IntoResponse {
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
    State(state): State<ApiState>,
    Query(pagination): Query<PaginationQuery>,
) -> impl IntoResponse {
    let page = pagination.page.unwrap_or(1);
    let limit = pagination.limit.unwrap_or(10).min(100); // Max 100 transactions per page

    match get_paginated_transactions(&state, page, limit).await {
        Ok(transactions) => Json(ApiResponse::success(transactions)),
        Err(e) => {
            tracing::error!("Failed to get transactions: {}", e);
            Json(ApiResponse::<Vec<crate::state::Transaction>>::error(
                e.to_string(),
            ))
        }
    }
}

async fn get_transaction(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_transaction(&hash).await {
        Ok(Some(tx)) => Json(ApiResponse::success(tx)),
        Ok(None) => Json(ApiResponse::<crate::state::Transaction>::error(
            "Transaction not found".to_string(),
        )),
        Err(e) => {
            tracing::error!("Failed to get transaction {}: {}", hash, e);
            Json(ApiResponse::<crate::state::Transaction>::error(
                e.to_string(),
            ))
        }
    }
}

async fn submit_transaction(
    State(state): State<ApiState>,
    Json(tx_req): Json<TransactionRequest>,
) -> impl IntoResponse {
    // Validate transaction request
    if tx_req.amount == 0 {
        return Json(ApiResponse::<Transaction>::error(
            "Amount cannot be zero".to_string(),
        ));
    }

    if tx_req.gas_price == 0 {
        return Json(ApiResponse::<Transaction>::error(
            "Gas price cannot be zero".to_string(),
        ));
    }

    // Get current nonce for the sender
    let nonce = state.node.chain_state.get_nonce(&tx_req.from).await;

    // Create transaction
    let tx = Transaction {
        hash: generate_transaction_hash(&tx_req, nonce),
        from: tx_req.from.clone(),
        to: tx_req.to.clone(),
        amount: tx_req.amount,
        gas_price: tx_req.gas_price,
        gas_limit: tx_req.gas_limit,
        nonce,
        data: tx_req.data.unwrap_or_default(),
        signature: String::new(), // In real implementation, this would be validated
        timestamp: Utc::now(),
    };

    // Validate transaction
    match state
        .node
        .chain_state
        .validate_transaction(&convert_consensus_tx_to_state(&tx))
        .await
    {
        Ok(true) => {
            // Add to pending transactions
            let state_tx = convert_consensus_tx_to_state(&tx);
            match state
                .node
                .chain_state
                .add_pending_transaction(state_tx)
                .await
            {
                Ok(_) => {
                    tracing::info!("Transaction {} added to mempool", tx.hash);
                    Json(ApiResponse::success(tx))
                }
                Err(e) => {
                    tracing::error!("Failed to add transaction to mempool: {}", e);
                    Json(ApiResponse::<Transaction>::error(e.to_string()))
                }
            }
        }
        Ok(false) => Json(ApiResponse::<Transaction>::error(
            "Transaction validation failed".to_string(),
        )),
        Err(e) => {
            tracing::error!("Failed to validate transaction: {}", e);
            Json(ApiResponse::<Transaction>::error(e.to_string()))
        }
    }
}

async fn get_account(
    State(state): State<ApiState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    match state.node.chain_state.get_account(&address).await {
        Some(account) => Json(ApiResponse::success(account)),
        None => {
            // Create a default account if it doesn't exist
            let default_account = Account::new(address.clone());
            Json(ApiResponse::success(default_account))
        }
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
    let validators = vec![]; // Temporary fix - implement proper validator retrieval
    match Ok(validators) as Result<Vec<crate::consensus::Validator>, anyhow::Error> {
        Ok(validators) => Json(ApiResponse::success(validators)),
        Err(e) => {
            tracing::error!("Failed to get validators: {}", e);
            Json(ApiResponse::<Vec<Validator>>::error(e.to_string()))
        }
    }
}

async fn add_validator(
    State(state): State<ApiState>,
    Json(validator_req): Json<ValidatorRequest>,
) -> impl IntoResponse {
    // Validate validator request
    if validator_req.stake < 1000 {
        return Json(ApiResponse::<Validator>::error(
            "Minimum stake is 1000".to_string(),
        ));
    }

    if validator_req.beta_angle < 0.0 || validator_req.beta_angle > 90.0 {
        return Json(ApiResponse::<Validator>::error(
            "Beta angle must be between 0 and 90 degrees".to_string(),
        ));
    }

    if validator_req.efficiency < 0.0 || validator_req.efficiency > 1.0 {
        return Json(ApiResponse::<Validator>::error(
            "Efficiency must be between 0 and 1".to_string(),
        ));
    }

    let validator = Validator {
        address: validator_req.address,
        stake: validator_req.stake,
        beta_angle: validator_req.beta_angle,
        efficiency: validator_req.efficiency,
        last_active: Utc::now(),
        is_active: true,
    };

    match state.node.consensus.add_validator(validator.clone()).await {
        Ok(_) => {
            tracing::info!("Validator {} added successfully", validator.address);
            Json(ApiResponse::success(validator))
        }
        Err(e) => {
            tracing::error!("Failed to add validator: {}", e);
            Json(ApiResponse::<Validator>::error(e.to_string()))
        }
    }
}

async fn get_metrics(State(state): State<ApiState>) -> impl IntoResponse {
    match collect_system_metrics(&state).await {
        Ok(metrics) => Json(ApiResponse::success(metrics)),
        Err(e) => {
            tracing::error!("Failed to collect metrics: {}", e);
            Json(ApiResponse::<SystemMetrics>::error(e.to_string()))
        }
    }
}

// Helper functions

async fn get_paginated_blocks(
    state: &ApiState,
    page: u64,
    limit: u64,
) -> Result<Vec<Block>, anyhow::Error> {
    // Get current chain status to determine total blocks
    let status = state.node.chain_state.get_status().await?;
    let total_blocks = status.height;

    // Calculate pagination
    let start_block = if page > 1 {
        total_blocks.saturating_sub((page - 1) * limit)
    } else {
        total_blocks
    };
    let end_block = start_block.saturating_sub(limit);

    let mut blocks = Vec::new();
    for height in (end_block..=start_block).rev() {
        // In a real implementation, you'd have a method to get block by height
        // For now, we'll create sample blocks
        if height > 0 {
            let block = create_sample_block(height);
            blocks.push(block);
        }
    }

    Ok(blocks)
}

async fn get_paginated_transactions(
    state: &ApiState,
    page: u64,
    limit: u64,
) -> Result<Vec<crate::state::Transaction>, anyhow::Error> {
    // Get pending transactions
    let pending_txs = state.node.chain_state.get_pending_transactions().await?;

    // Apply pagination
    let start_index = ((page - 1) * limit) as usize;
    let end_index = (start_index + limit as usize).min(pending_txs.len());

    if start_index >= pending_txs.len() {
        return Ok(Vec::new());
    }

    Ok(pending_txs[start_index..end_index].to_vec())
}

fn generate_transaction_hash(tx_req: &TransactionRequest, nonce: u64) -> String {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(tx_req.from.as_bytes());
    hasher.update(tx_req.to.as_bytes());
    hasher.update(&tx_req.amount.to_le_bytes());
    hasher.update(&tx_req.gas_price.to_le_bytes());
    hasher.update(&tx_req.gas_limit.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.update(&Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());

    format!("0x{}", hex::encode(hasher.finalize()))
}

fn convert_consensus_tx_to_state(consensus_tx: &Transaction) -> crate::state::Transaction {
    crate::state::Transaction {
        id: consensus_tx.hash.clone(),
        hash: consensus_tx.hash.clone(),
        from: consensus_tx.from.clone(),
        to: consensus_tx.to.clone(),
        value: consensus_tx.amount,
        amount: consensus_tx.amount,
        fee: consensus_tx.gas_price * consensus_tx.gas_limit,
        gas_limit: consensus_tx.gas_limit,
        gas_price: consensus_tx.gas_price,
        nonce: consensus_tx.nonce,
        data: consensus_tx.data.clone(),
        signature: consensus_tx.signature.clone(),
        timestamp: consensus_tx.timestamp.timestamp() as u64,
    }
}

fn create_sample_block(height: u64) -> Block {
    Block {
        index: height,
        timestamp: Utc::now().timestamp() as u64,
        previous_hash: format!("prev_hash_{}", height - 1),
        merkle_root: format!("merkle_{}", height),
        transactions: Vec::new(),
        hash: format!("block_hash_{}", height),
        signatures: vec![format!("sig_{}", height)],
        validator: "genesis_validator_1".to_string(),
    }
}

async fn collect_system_metrics(state: &ApiState) -> Result<SystemMetrics, anyhow::Error> {
    let status = state.node.chain_state.get_status().await?;
    let pending_txs = state.node.chain_state.get_pending_transactions().await?;
    let validators = state.node.consensus.get_validators().await?;

    // Calculate uptime (simplified)
    let uptime = calculate_uptime();

    // Get system metrics (simplified)
    let (memory_usage, cpu_usage) = get_system_usage();

    Ok(SystemMetrics {
        uptime,
        memory_usage,
        cpu_usage,
        network_peers: 5, // This would come from network manager
        block_height: status.height,
        pending_transactions: pending_txs.len() as u64,
        total_transactions: status.total_transactions,
        validator_count: validators.len() as u64,
        chain_state: "Active".to_string(),
    })
}

fn calculate_uptime() -> String {
    // Simplified uptime calculation
    let uptime_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86400; // Last 24 hours

    let hours = uptime_secs / 3600;
    let minutes = (uptime_secs % 3600) / 60;

    format!("{}h {}m", hours, minutes)
}

fn get_system_usage() -> (String, String) {
    // Simplified system usage - in real implementation, use system info crates
    ("256MB".to_string(), "15%".to_string())
}
