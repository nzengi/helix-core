use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    routing::{get, post},
    Router,
    Json,
    extract::{State, Path, WebSocketUpgrade},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use tower_http::cors::CorsLayer;
use crate::{
    consensus::{Block, Transaction},
    state::State as ChainState,
    network::NetworkState,
    config::ApiConfig,
};

#[derive(Clone)]
pub struct ApiState {
    pub chain_state: Arc<Mutex<ChainState>>,
    pub network_state: Arc<Mutex<NetworkState>>,
    pub config: Arc<ApiConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

pub struct ApiServer {
    state: ApiState,
}

impl ApiServer {
    pub fn new(chain_state: ChainState, network_state: NetworkState, config: ApiConfig) -> Self {
        Self {
            state: ApiState {
                chain_state: Arc::new(Mutex::new(chain_state)),
                network_state: Arc::new(Mutex::new(network_state)),
                config: Arc::new(config),
            },
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        let app = Router::new()
            // Block endpoints
            .route("/api/blocks/latest", get(get_latest_block))
            .route("/api/blocks/:hash", get(get_block))
            .route("/api/blocks", post(submit_block))
            
            // Transaction endpoints
            .route("/api/transactions", post(submit_transaction))
            .route("/api/transactions/:hash", get(get_transaction))
            
            // Account endpoints
            .route("/api/accounts/:address", get(get_account))
            .route("/api/accounts/:address/balance", get(get_balance))
            
            // Network endpoints
            .route("/api/network/peers", get(get_peers))
            .route("/api/network/status", get(get_network_status))
            
            // WebSocket endpoints
            .route("/ws/blocks", get(ws_blocks))
            .route("/ws/transactions", get(ws_transactions))
            
            // CORS ve rate limiting
            .layer(CorsLayer::permissive())
            .with_state(self.state.clone());

        let addr = format!("{}:{}", self.state.config.host, self.state.config.port);
        axum::Server::bind(&addr.parse().unwrap())
            .serve(app.into_make_service())
            .await
            .map_err(|e| e.to_string())
    }
}

// Block endpoints
async fn get_latest_block(
    State(state): State<ApiState>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    if let Some(block) = chain_state.last_block.lock().await.as_ref() {
        Json(ApiResponse::success(block.clone()))
    } else {
        Json(ApiResponse::<Block>::error("No blocks found".to_string()))
    }
}

async fn get_block(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    match chain_state.get_block(&hash).await {
        Ok(Some(block)) => Json(ApiResponse::success(block)),
        Ok(None) => Json(ApiResponse::<Block>::error("Block not found".to_string())),
        Err(e) => Json(ApiResponse::<Block>::error(e)),
    }
}

async fn submit_block(
    State(state): State<ApiState>,
    Json(block): Json<Block>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    match chain_state.save_block(block).await {
        Ok(_) => Json(ApiResponse::success("Block saved".to_string())),
        Err(e) => Json(ApiResponse::<String>::error(e)),
    }
}

// Transaction endpoints
async fn submit_transaction(
    State(state): State<ApiState>,
    Json(transaction): Json<Transaction>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    // TODO: Implement transaction submission
    Json(ApiResponse::success("Transaction submitted".to_string()))
}

async fn get_transaction(
    State(state): State<ApiState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // TODO: Implement transaction retrieval
    Json(ApiResponse::<Transaction>::error("Not implemented".to_string()))
}

// Account endpoints
async fn get_account(
    State(state): State<ApiState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    match chain_state.get_account(&address).await {
        Ok(Some(account)) => Json(ApiResponse::success(account)),
        Ok(None) => Json(ApiResponse::<()>::error("Account not found".to_string())),
        Err(e) => Json(ApiResponse::<()>::error(e)),
    }
}

async fn get_balance(
    State(state): State<ApiState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let chain_state = state.chain_state.lock().await;
    match chain_state.get_account(&address).await {
        Ok(Some(account)) => Json(ApiResponse::success(account.balance)),
        Ok(None) => Json(ApiResponse::<f64>::error("Account not found".to_string())),
        Err(e) => Json(ApiResponse::<f64>::error(e)),
    }
}

// Network endpoints
async fn get_peers(
    State(state): State<ApiState>,
) -> impl IntoResponse {
    let network_state = state.network_state.lock().await;
    let peers = network_state.peers.lock().await;
    Json(ApiResponse::success(peers.clone()))
}

async fn get_network_status(
    State(state): State<ApiState>,
) -> impl IntoResponse {
    let network_state = state.network_state.lock().await;
    let node_info = network_state.node_info.lock().await;
    Json(ApiResponse::success(node_info.clone()))
}

// WebSocket endpoints
async fn ws_blocks(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| async move {
        // TODO: Implement WebSocket handler for blocks
    })
}

async fn ws_transactions(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| async move {
        // TODO: Implement WebSocket handler for transactions
    })
}

// API hata yönetimi
#[derive(Debug)]
pub enum ApiError {
    InvalidRequest(String),
    NotFound(String),
    InternalError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        Json(ApiResponse::<()>::error(error_message)).into_response()
    }
} 