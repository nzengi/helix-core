
pub mod address;
pub mod api;
pub mod compression;
pub mod config;
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

use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

use crate::config::Config;
use crate::consensus::RotaryBFT;
use crate::state::ChainState;
use crate::crypto::CryptoManager;
use crate::network_manager::NetworkManager;

#[derive(Clone)]
pub struct HelixNode {
    pub config: Config,
    pub chain_state: Arc<ChainState>,
    pub consensus: Arc<RotaryBFT>,
    pub crypto: Arc<tokio::sync::Mutex<CryptoManager>>,
    pub network: Arc<RwLock<Option<NetworkManager>>>,
    pub is_running: Arc<RwLock<bool>>,
}

impl HelixNode {
    pub async fn new(config: Config) -> Result<Self> {
        let chain_state = Arc::new(ChainState::new());
        let consensus = Arc::new(RotaryBFT::new(chain_state.clone()));
        let crypto = Arc::new(tokio::sync::Mutex::new(CryptoManager::new()));
        
        Ok(Self {
            config,
            chain_state,
            consensus,
            crypto,
            network: Arc::new(RwLock::new(None)),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("🚀 Starting HelixChain node...");
        
        // Initialize genesis validators
        self.consensus.initialize_genesis_validators().await?;
        
        // Initialize network
        let network_manager = NetworkManager::new(self.config.clone()).await?;
        {
            let mut network = self.network.write().await;
            *network = Some(network_manager);
        }
        
        // Mark as running
        {
            let mut running = self.is_running.write().await;
            *running = true;
        }
        
        tracing::info!("✅ HelixChain node started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("🛑 Stopping HelixChain node...");
        
        {
            let mut running = self.is_running.write().await;
            *running = false;
        }
        
        {
            let mut network = self.network.write().await;
            if let Some(net) = network.take() {
                net.stop().await?;
            }
        }
        
        tracing::info!("✅ HelixChain node stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    pub async fn submit_transaction(&self, transaction: consensus::Transaction) -> Result<String> {
        // Validate transaction
        if !self.chain_state.validate_transaction(&transaction).await? {
            anyhow::bail!("Invalid transaction");
        }
        
        // Add to pending pool
        self.chain_state.add_pending_transaction(transaction.clone()).await?;
        
        // Broadcast to network if available
        if let Some(network) = self.network.read().await.as_ref() {
            network.broadcast_transaction(&transaction).await?;
        }
        
        Ok(transaction.hash)
    }

    pub async fn mine_block(&self) -> Result<consensus::Block> {
        let pending_transactions = self.chain_state.get_pending_transactions().await?;
        let block = self.consensus.propose_block(pending_transactions).await?;
        
        if self.consensus.validate_and_commit_block(block.clone()).await? {
            self.chain_state.clear_pending_transactions().await?;
            
            // Broadcast block if network available
            if let Some(network) = self.network.read().await.as_ref() {
                network.broadcast_block(&block).await?;
            }
            
            tracing::info!("📦 Mined block {} with {} transactions", 
                block.height, block.transactions.len());
            
            Ok(block)
        } else {
            anyhow::bail!("Failed to commit block")
        }
    }

    pub async fn get_validators(&self) -> Result<Vec<consensus::Validator>> {
        self.consensus.get_validators().await
    }
}

// Re-export commonly used types
pub use crate::consensus::{Block, Transaction, Validator};
pub use crate::state::{Account, ChainInfo, SyncStatus};
pub use crate::crypto::{KeyPair, MerkleTree};
