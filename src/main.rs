// mod address;
// mod consensus;
// mod security;
// mod sharding;
// mod gas;
// mod thermal;
// mod compression;
// mod wallet;
// mod state;
// mod genesis;
// mod network;
// mod database;

use std::sync::Arc;
use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use helix_chain::network::{NodeInfo, Transaction};
use helix_chain::state::Account;
use helix_chain::HelixNode;
use helix_chain::thermal::ThermalBalancer;
use helix_chain::security;

struct AppState {
    node: Arc<HelixNode>,
}

#[derive(Deserialize)]
struct JoinNetworkRequest {
    address: String,
    port: u16,
    wallet_address: String,
}

#[derive(Deserialize)]
struct TransactionRequest {
    from: String,
    to: String,
    amount: f64,
    data: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct NodeStatus {
    wallet_address: String,
    cpu_temp: f64,
    optimal_beta: f64,
    self_lock: bool,
    network_id: String,
    active_shards: Vec<String>,
    gas_price: f64,
    total_supply: f64,
    total_torque: f64,
    total_stake: f64,
    total_validators: u32,
    total_chains: u32,
    total_transactions: u64,
    total_blocks: u64,
    total_accounts: u64,
    total_storage: u64,
    total_contracts: u64,
    total_contract_calls: u64,
    total_contract_creates: u64,
    total_contract_deletes: u64,
    total_contract_updates: u64,
    total_contract_transfers: u64,
    total_contract_approvals: u64,
    total_contract_rejections: u64,
    total_contract_executions: u64,
    total_contract_reverts: u64,
    total_contract_errors: u64,
    total_contract_warnings: u64,
}

#[derive(Serialize)]
struct TransactionResponse {
    tx_hash: String,
    gas_used: f64,
    shard_id: String,
    compressed_size: usize,
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    balance: f64,
    staked_amount: f64,
    total_torque: f64,
}

#[axum::debug_handler]
async fn join_network(
    State(state): State<Arc<AppState>>,
    Json(node_info): Json<NodeInfo>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    node.connect_to_node(&node_info.address, node_info.port, &node_info.wallet_address).await;
    Json(())
}

#[axum::debug_handler]
async fn get_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    let wallet = node.wallet.lock().await;
    let shard_router = node.shard_router.lock().await;
    let gas_calculator = node.gas_calculator.lock().await;
    let genesis_state = node.genesis_state.lock().await;
    
    let status = NodeStatus {
        wallet_address: wallet.generate_address(),
        cpu_temp: ThermalBalancer::get_cpu_temp(),
        optimal_beta: ThermalBalancer::adjust_beta(ThermalBalancer::get_cpu_temp()),
        self_lock: security::validate_self_lock(40.0),
        network_id: "helix-mainnet-1".to_string(),
        active_shards: shard_router.get_active_shards(),
        gas_price: gas_calculator.get_current_price(),
        total_supply: genesis_state.accounts.values().map(|acc| acc.balance).sum(),
    };
    Json(status)
}

#[axum::debug_handler]
async fn send_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<Transaction>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    // Broadcast transaction (returns nothing)
    node.network_state.broadcast_transaction(tx.clone()).await;
    // Calculate gas
    let mut gas_calculator = node.gas_calculator.lock().await;
    let gas_used = gas_calculator.calculate(tx.amount, 0);
    // Route to appropriate shard
    let mut shard_router = node.shard_router.lock().await;
    let shard_id = shard_router.route_tx(gas_used);
    // Compressed size (dummy, since no data field)
    let compressed_size = 0;
    // Use signature as tx_hash
    let tx_hash = tx.signature.clone();
    Json(TransactionResponse {
        tx_hash,
        gas_used,
        shard_id,
        compressed_size,
    })
}

#[axum::debug_handler]
async fn get_balance(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    let account = node.chain_state.get_account(&address).await.unwrap_or_else(|| Account::new());
    Json(BalanceResponse {
        address,
        balance: account.balance,
        staked_amount: account.staked_amount,
        total_torque: account.calculate_torque(),
    })
}

#[axum::debug_handler]
async fn receive_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<Transaction>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    node.network_state.add_transaction(tx).await;
    Json(())
}

#[axum::debug_handler]
async fn get_network_state(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    let transactions = node.network_state.transactions.lock().await;
    Json(transactions.clone())
}

#[tokio::main]
async fn main() {
    // Initialize node
    let node = HelixNode::new(8080, "seed1", None).await.unwrap();
    let state = Arc::new(AppState { node: Arc::new(node) });
    
    // Build router
    let app = Router::new()
        .route("/network/join", post(join_network))
        .route("/status", get(get_status))
        .route("/transaction", post(send_transaction))
        .route("/balance/:address", get(get_balance))
        .route("/network/transaction", post(receive_transaction))
        .route("/network/state", get(get_network_state))
        .with_state(state);
    
    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🚀 Server running on http://127.0.0.1:8080");
    axum::serve(listener, app).await.unwrap();
}