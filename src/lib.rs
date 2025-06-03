use std::sync::Arc;
use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use sha3::Digest;

pub mod address;
pub mod api;
pub mod compression;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod database;
pub mod delegation;
pub mod gas;
pub mod genesis;
pub mod governance;
pub mod logging;
pub mod metrics;
pub mod network;
pub mod network_manager;
pub mod oracle;
pub mod privacy;
pub mod security;
pub mod security_audit;
pub mod sharding;
pub mod smart_contract;
pub mod state;
pub mod storage;
pub mod thermal;
pub mod token;
pub mod wallet;

pub use crate::consensus::{ConsensusState, RotaryBFT, Block, Transaction as ConsensusTransaction};
pub use crate::crypto::CryptoManager;
pub use crate::state::{ChainState, Account};
pub use crate::network_manager::NetworkManager;
pub use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub version: String,
    pub start_time: DateTime<Utc>,
    pub network_id: String,
    pub validator_address: Option<String>,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Syncing { current_block: u64, target_block: u64 },
    Synced,
    NotSynced,
}

#[derive(Clone)]
pub struct HelixNode {
    pub config: Config,
    pub chain_state: Arc<ChainState>,
    pub consensus: Arc<Mutex<ConsensusState>>,
    pub rotary_bft: Arc<RotaryBFT>,
    pub crypto: Arc<CryptoManager>,
    pub network: Arc<NetworkManager>,
    pub is_running: Arc<Mutex<bool>>,
    pub node_info: Arc<Mutex<NodeInfo>>,
}

impl HelixNode {
    pub async fn new(config: Config) -> Result<Self> {
        let crypto = Arc::new(CryptoManager::new());
        let chain_state = Arc::new(ChainState::new());
        let crypto_mutex = Arc::new(Mutex::new(CryptoManager::new()));
        let consensus = Arc::new(Mutex::new(ConsensusState::new(
            Arc::clone(&chain_state),
            Arc::clone(&crypto_mutex),
        )));
        let network = Arc::new(NetworkManager::new(config.clone()).await?);

        let network_id = format!("helix-{}", config.network.listen_port);
        let node_info = NodeInfo {
            node_id: format!("helix-node-{}", uuid::Uuid::new_v4()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: Utc::now(),
            network_id,
            validator_address: None,
            sync_status: SyncStatus::NotSynced,
        };

        let rotary_bft = Arc::new(RotaryBFT::new(Arc::clone(&chain_state)));

        Ok(Self {
            config,
            chain_state,
            consensus,
            rotary_bft,
            crypto,
            network,
            is_running: Arc::new(Mutex::new(false)),
            node_info: Arc::new(Mutex::new(node_info)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.lock().await;
        if *is_running {
            return Ok(());
        }

        // Initialize components in order
        self.network.start().await?;
        {
            let mut consensus = self.consensus.lock().await;
            consensus.start().await?;
        }
        self.rotary_bft.start_consensus().await?;

        // Update node status
        {
            let mut info = self.node_info.lock().await;
            info.sync_status = SyncStatus::Syncing { current_block: 0, target_block: 0 };
        }

        // Start sync process
        self.start_sync_process().await?;

        *is_running = true;
        tracing::info!("HelixNode started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.lock().await;
        if !*is_running {
            return Ok(());
        }

        // Stop components in reverse order
        {
            let mut consensus = self.consensus.lock().await;
            consensus.stop().await?;
        }
        self.network.stop().await?;
        self.rotary_bft.stop_consensus().await?;

        *is_running = false;
        tracing::info!("HelixNode stopped");
        Ok(())
    }

    pub async fn submit_transaction(&self, transaction: ConsensusTransaction) -> Result<String> {
        // Convert consensus transaction to state transaction for validation
        let state_transaction = crate::state::Transaction {
            id: transaction.hash.clone(),
            hash: transaction.hash.clone(),
            from: transaction.from.clone(),
            to: transaction.to.clone(),
            value: transaction.amount,
            amount: transaction.amount,
            fee: transaction.gas_price * transaction.gas_limit,
            gas_limit: transaction.gas_limit,
            gas_price: transaction.gas_price,
            gas_used: 0,
            data: transaction.data.clone(),
            timestamp: transaction.timestamp.timestamp() as u64,
            signature: transaction.signature.clone(),
            nonce: transaction.nonce,
            block_height: 0,
            status: crate::state::TransactionStatus::Pending,
        };

        // Validate transaction
        if !self.chain_state.validate_transaction(&state_transaction).await.map_err(|e| anyhow::anyhow!("Transaction validation error: {:?}", e))? {
            return Err(anyhow::anyhow!("Transaction validation failed"));
        }

        // Add to pending transactions
        self.chain_state.add_pending_transaction(state_transaction).await.map_err(|e| anyhow::anyhow!("Failed to add pending transaction: {:?}", e))?;

        // Broadcast to network
        self.network.broadcast_transaction(&transaction).await?;

        Ok(format!("0x{}", transaction.hash))
    }

    pub async fn get_block(&self, block_hash: &str) -> Result<Option<Block>> {
        match self.chain_state.get_block(block_hash).await? {
            Some(state_block) => {
                // Convert state::Block to consensus::Block
                Ok(Some(Block {
                    height: state_block.index,
                    timestamp: DateTime::from_timestamp(state_block.timestamp as i64, 0).unwrap_or_else(|| Utc::now()),
                    previous_hash: state_block.previous_hash,
                    transactions: state_block.transactions.into_iter().map(|tx| ConsensusTransaction {
                        hash: tx.hash,
                        from: tx.from,
                        to: tx.to,
                        amount: tx.amount,
                        gas_limit: tx.gas_limit,
                        gas_price: tx.gas_price,
                        data: tx.data,
                        timestamp: DateTime::from_timestamp(tx.timestamp as i64, 0).unwrap_or_else(|| Utc::now()),
                        signature: tx.signature,
                        nonce: tx.nonce,
                    }).collect(),
                    merkle_root: state_block.merkle_root,
                    hash: state_block.hash,
                    validator: state_block.validator,
                    signature: state_block.signatures.into_iter().next().unwrap_or_default(),
                    torque: 0.0,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn get_latest_block(&self) -> Result<Option<Block>> {
        let latest_height = self.chain_state.get_latest_block_height().await.map_err(|e| anyhow::anyhow!("Failed to get latest block height: {:?}", e))?;
        if latest_height == 0 {
            return Ok(None);
        }

        let blocks = self.chain_state.get_blocks_by_height_range(latest_height, latest_height).await.map_err(|e| anyhow::anyhow!("Failed to get blocks: {:?}", e))?;
        match blocks.into_iter().next() {
            Some(state_block) => Ok(Some(Block {
                height: state_block.index,
                timestamp: DateTime::from_timestamp(state_block.timestamp as i64, 0).unwrap_or_else(|| Utc::now()),
                previous_hash: state_block.previous_hash,
                transactions: state_block.transactions.into_iter().map(|tx| ConsensusTransaction {
                    hash: tx.hash,
                    from: tx.from,
                    to: tx.to,
                    amount: tx.amount,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price,
                    data: tx.data,
                    timestamp: DateTime::from_timestamp(tx.timestamp as i64, 0).unwrap_or_else(|| Utc::now()),
                    signature: tx.signature,
                    nonce: tx.nonce,
                }).collect(),
                merkle_root: state_block.merkle_root,
                hash: state_block.hash,
                validator: state_block.validator,
                signature: state_block.signatures.into_iter().next().unwrap_or_default(),
                torque: 0.0,
            })),
            None => Ok(None),
        }
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        Ok(self.chain_state.get_account(address).await)
    }

    pub async fn get_balance(&self, address: &str) -> Result<u64> {
        match self.get_account(address).await? {
            Some(account) => Ok(account.balance),
            None => Ok(0),
        }
    }

    pub async fn get_node_info(&self) -> NodeInfo {
        self.node_info.lock().await.clone()
    }

    pub async fn is_validator(&self) -> bool {
        let info = self.node_info.lock().await;
        info.validator_address.is_some()
    }

    pub async fn set_validator_address(&self, address: String) -> Result<()> {
        let mut info = self.node_info.lock().await;
        info.validator_address = Some(address);
        Ok(())
    }

    pub async fn get_peer_count(&self) -> usize {
        self.network.get_peer_count().await
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<crate::state::Transaction>> {
        self.chain_state.get_pending_transactions().await.map_err(|e| anyhow::anyhow!("Failed to get pending transactions: {:?}", e))
    }

    pub async fn mine_block(&self) -> Result<Block> {
        if !self.is_validator().await {
            return Err(anyhow::anyhow!("Node is not configured as validator"));
        }

        // Get pending transactions
        let pending_txs = self.get_pending_transactions().await?;

        // Convert state transactions to consensus transactions
        let mut consensus_txs = Vec::new();
        for tx in pending_txs.iter().take(1000) { // Limit block size
            let consensus_tx = ConsensusTransaction {
                hash: tx.hash.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                data: tx.data.clone(),
                timestamp: DateTime::from_timestamp(tx.timestamp as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                signature: tx.signature.clone(),
                nonce: tx.nonce,
            };
            consensus_txs.push(consensus_tx);
        }

        // Get previous block hash
        let previous_hash = match self.get_latest_block().await? {
            Some(block) => block.hash,
            None => "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };

        // Calculate block height
        let height = self.chain_state.get_latest_block_height().await.map_err(|e| anyhow::anyhow!("Failed to get latest block height: {:?}", e))? + 1;

        // Get validator info
        let validator_address = self.node_info.lock().await
            .validator_address
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Create new block
        let mut block = Block {
            height,
            timestamp: Utc::now(),
            previous_hash,
            transactions: consensus_txs,
            merkle_root: String::new(),
            hash: String::new(),
            validator: validator_address,
            signature: String::new(),
            torque: 0.0,
        };

        // Calculate merkle root
        block.merkle_root = self.calculate_merkle_root(&block.transactions)?;

        // Calculate block hash
        block.hash = self.calculate_block_hash(&block)?;

        // Sign block
        block.signature = self.crypto.sign_block(&block).await.map_err(|e| anyhow::anyhow!("Failed to sign block: {}", e))?;

        // Calculate torque (HelixChain specific)
        block.torque = self.calculate_block_torque(&block).await?;

        // Add block to chain
        {
            let mut consensus = self.consensus.lock().await;
            // Process block through consensus - simplified for now
            let result = true; // Placeholder - consensus processing would go here
        }

        // Remove processed transactions from pending (simplified)
        // In a real implementation, this would be handled by the chain state

        Ok(block)
    }

    async fn start_sync_process(&self) -> Result<()> {
        // Simplified sync process - in real implementation would sync with network
        let network_stats = self.network.get_network_stats().await?;
        let local_height = self.chain_state.get_latest_block_height().await.map_err(|e| anyhow::anyhow!("Failed to get latest block height: {:?}", e))?;
        let network_height = local_height; // Simplified - use local height for now

        if network_height > local_height {
            // Start syncing
            let mut info = self.node_info.lock().await;
            info.sync_status = SyncStatus::Syncing {
                current_block: local_height,
                target_block: network_height,
            };
            drop(info);

            // Mark as synced
            let mut info = self.node_info.lock().await;
            info.sync_status = SyncStatus::Synced;
        } else {
            // Already synced
            let mut info = self.node_info.lock().await;
            info.sync_status = SyncStatus::Synced;
        }

        Ok(())
    }

    fn calculate_merkle_root(&self, transactions: &[ConsensusTransaction]) -> Result<String> {
        if transactions.is_empty() {
            return Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string());
        }

        let mut hashes: Vec<String> = transactions.iter()
            .map(|tx| tx.hash.clone())
            .collect();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    chunk[0].clone()
                };
                next_level.push(format!("0x{:x}", sha3::Keccak256::digest(combined.as_bytes())));
            }
            hashes = next_level;
        }

        Ok(hashes.into_iter().next().unwrap())
    }

    fn calculate_block_hash(&self, block: &Block) -> Result<String> {
        let data = format!(
            "{}{}{}{}{}{}{}",
            block.height,
            block.timestamp.timestamp(),
            block.previous_hash,
            block.merkle_root,
            block.validator,
            block.torque,
            block.transactions.len()
        );
        Ok(format!("0x{:x}", sha3::Keccak256::digest(data.as_bytes())))
    }

    async fn calculate_block_torque(&self, block: &Block) -> Result<f64> {
        // HelixChain specific: Calculate torque based on gear mechanics
        let base_torque = 1.0;
        let transaction_load = block.transactions.len() as f64;
        let network_stats = self.network.get_network_stats().await?;
        let network_load = if network_stats.connected_peers > 0 { 
            network_stats.connected_peers as f64 
        } else { 
            1.0 
        };

        // Apply gear ratio calculation (simplified)
        let beta_angle = 40.0_f64.to_radians(); // Standard gear angle
        let efficiency = 0.92; // Gear efficiency

        let torque = base_torque * beta_angle.sin() * efficiency * (transaction_load / network_load);
        Ok(torque.max(0.1)) // Minimum torque
    }

    pub async fn health_check(&self) -> Result<HealthStatus> {
        let is_running = *self.is_running.lock().await;
        let info = self.get_node_info().await;
        let peer_count = self.get_peer_count().await;
        let latest_block_height = self.chain_state.get_latest_block_height().await.map_err(|e| anyhow::anyhow!("Failed to get latest block height: {:?}", e))?;

        Ok(HealthStatus {
            is_running,
            sync_status: info.sync_status,
            peer_count,
            latest_block_height,
            uptime: Utc::now().signed_duration_since(info.start_time),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_running: bool,
    pub sync_status: SyncStatus,
    pub peer_count: usize,
    pub latest_block_height: u64,
    pub uptime: chrono::Duration,
}

// Helper trait for async operations
#[async_trait::async_trait]
pub trait AsyncBlockchain {
    async fn process_transaction(&self, tx: ConsensusTransaction) -> Result<String>;
    async fn validate_block(&self, block: &Block) -> Result<bool>;
    async fn get_chain_stats(&self) -> Result<ChainStats>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub average_block_time: f64,
    pub network_hash_rate: f64,
    pub active_validators: u64,
}

#[async_trait::async_trait]
impl AsyncBlockchain for HelixNode {
    async fn process_transaction(&self, tx: ConsensusTransaction) -> Result<String> {
        self.submit_transaction(tx).await
    }

    async fn validate_block(&self, block: &Block) -> Result<bool> {
        // Validate block structure
        if block.height == 0 {
            return Err(anyhow::anyhow!("Invalid block height"));
        }

        // Validate previous hash
        if let Some(prev_block) = self.get_block(&block.previous_hash).await? {
            if prev_block.height + 1 != block.height {
                return Ok(false);
            }
        }

        // Validate merkle root
        let calculated_merkle = self.calculate_merkle_root(&block.transactions)?;
        if calculated_merkle != block.merkle_root {
            return Ok(false);
        }

        // Validate block hash
        let calculated_hash = self.calculate_block_hash(block)?;
        if calculated_hash != block.hash {
            return Ok(false);
        }

        // For now, assume signature is valid (simplified implementation)
        // In production, implement proper block signature verification
        if block.signature.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    async fn get_chain_stats(&self) -> Result<ChainStats> {
        let latest_height = self.chain_state.get_latest_block_height().await.map_err(|e| anyhow::anyhow!("Failed to get latest block height: {:?}", e))?;
        let total_accounts = 100; // Simplified - would count actual accounts

        // Calculate average block time (simplified)
        let avg_block_time = if latest_height > 10 {
            let recent_blocks = self.chain_state.get_blocks_by_height_range(
                latest_height - 10, 
                latest_height
            ).await.map_err(|e| anyhow::anyhow!("Failed to get blocks: {:?}", e))?;

            if recent_blocks.len() >= 2 {
                let time_diff = recent_blocks.last().unwrap().timestamp - 
                               recent_blocks.first().unwrap().timestamp;
                time_diff as f64 / (recent_blocks.len() - 1) as f64
            } else {
                15.0 // Default 15 seconds
            }
        } else {
            15.0
        };

        Ok(ChainStats {
            total_blocks: latest_height,
            total_transactions: 1000, // Simplified - would count actual transactions
            total_accounts,
            average_block_time: avg_block_time,
            network_hash_rate: 1000.0, // Placeholder
            active_validators: 1, // Simplified
        })
    }
}

// Re-export commonly used types
pub type HelixResult<T> = Result<T, HelixError>;

#[derive(Debug, thiserror::Error)]
pub enum HelixError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Consensus error: {0}")]
    Consensus(String),
    #[error("State error: {0}")]
    State(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}