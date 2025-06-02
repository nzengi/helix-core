pub mod address;
pub mod consensus;
pub mod security;
pub mod sharding;
pub mod gas;
pub mod thermal;
pub mod compression;
pub mod wallet;
pub mod state;
pub mod genesis;
pub mod network;
pub mod database;

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::consensus::{RotaryConsensus, TorqueSystem, TorqueGas};
use crate::thermal::ThermalBalancer;
use crate::sharding::ShardRouter;
use crate::gas::GasCalculator;
use crate::compression::HelixCompression;
use crate::state::State as ChainState;
use crate::genesis::{GenesisBlock, GenesisState};
use crate::network::{NetworkState, NodeInfo};
use crate::database::Database;
use crate::address::HelixWallet;

pub struct HelixNode {
    pub wallet: Arc<Mutex<HelixWallet>>,
    pub consensus: Arc<Mutex<RotaryConsensus>>,
    pub shard_router: Arc<Mutex<ShardRouter>>,
    pub gas_calculator: Arc<Mutex<TorqueGas>>,
    pub compression: Arc<Mutex<HelixCompression>>,
    pub chain_state: ChainState,
    pub genesis_state: Arc<Mutex<GenesisState>>,
    pub network_state: NetworkState,
    pub database: Arc<Database>,
    pub thermal_balancer: Arc<Mutex<ThermalBalancer>>,
}

impl HelixNode {
    pub async fn new(_port: u16, seed: &str, _bootstrap_node: Option<&str>) -> Result<Self, String> {
        // Initialize wallet
        let wallet = Arc::new(Mutex::new(HelixWallet::new(seed)));
        
        // Initialize consensus
        let consensus = Arc::new(Mutex::new(RotaryConsensus::new()));
        
        // Initialize shard router
        let shard_router = Arc::new(Mutex::new(ShardRouter::new()));
        
        // Initialize gas calculator
        let gas_calculator = Arc::new(Mutex::new(TorqueGas::new()));
        
        // Initialize compression
        let compression = Arc::new(Mutex::new(HelixCompression::new()));
        
        // Initialize chain state
        let chain_state = ChainState::new();
        
        // Initialize genesis state
        let genesis_block = GenesisBlock::new(wallet.lock().await.generate_address());
        let genesis_state = Arc::new(Mutex::new(GenesisState::new(&genesis_block)));
        
        // Initialize network state
        let network_state = NetworkState::new();
        
        // Initialize database
        let database = Arc::new(Database::new().await.map_err(|e| e.to_string())?);
        
        // Initialize thermal balancer
        let thermal_balancer = Arc::new(Mutex::new(ThermalBalancer::new()));
        
        Ok(Self {
            wallet,
            consensus,
            shard_router,
            gas_calculator,
            compression,
            chain_state,
            genesis_state,
            network_state,
            database,
            thermal_balancer,
        })
    }
    
    pub async fn connect_to_node(&self, host: &str, port: u16, wallet_address: &str) {
        let node_info = NodeInfo {
            address: host.to_string(),
            port,
            wallet_address: wallet_address.to_string(),
        };
        
        self.network_state.add_node(node_info).await;
    }
}
