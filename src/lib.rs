
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

use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::Result;

use crate::config::Config;
use crate::consensus::ConsensusManager;
use crate::crypto::CryptoManager;
use crate::database::Database;
use crate::network_manager::NetworkManager;
use crate::security_audit::SecurityAuditManager;
use crate::state::ChainState;
use crate::wallet::HelixWallet;

pub struct HelixNode {
    pub config: Config,
    pub crypto_manager: Arc<CryptoManager>,
    pub consensus_manager: Arc<Mutex<ConsensusManager>>,
    pub chain_state: Arc<ChainState>,
    pub network_manager: Arc<NetworkManager>,
    pub security_audit: Arc<SecurityAuditManager>,
    pub database: Arc<Database>,
    pub wallet: Arc<Mutex<HelixWallet>>,
}

impl HelixNode {
    pub async fn new(config: Config) -> Result<Self> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let database = Arc::new(Database::new(&config.database).await?);
        let chain_state = Arc::new(ChainState::new(database.clone()).await?);
        let security_audit = Arc::new(SecurityAuditManager::new());
        let network_manager = Arc::new(NetworkManager::new(config.network.clone()).await?);
        let consensus_manager = Arc::new(Mutex::new(ConsensusManager::new(
            chain_state.clone(),
            crypto_manager.clone(),
        )));
        let wallet = Arc::new(Mutex::new(HelixWallet::new(&config.wallet.seed)?));

        Ok(Self {
            config,
            crypto_manager,
            consensus_manager,
            chain_state,
            network_manager,
            security_audit,
            database,
            wallet,
        })
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting HelixNode");
        
        // Start network manager
        self.network_manager.start().await?;
        
        // Start consensus
        let consensus = self.consensus_manager.lock().await;
        consensus.start().await?;
        
        tracing::info!("HelixNode started successfully");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping HelixNode");
        
        // Stop services in reverse order
        let consensus = self.consensus_manager.lock().await;
        consensus.stop().await?;
        
        self.network_manager.stop().await?;
        
        tracing::info!("HelixNode stopped successfully");
        Ok(())
    }
}
