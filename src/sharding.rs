
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use crate::consensus::{Block, Transaction};
use anyhow::Result;
use chrono::Utc;

pub type ShardId = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shard {
    pub id: ShardId,
    pub state_root: String,
    pub transactions: Vec<Transaction>,
    pub validators: HashSet<String>,
    pub load: f64,
    pub last_sync: u64,
    pub last_block: Option<Block>,
    pub pending_txs: Vec<Transaction>,
    pub processed_txs: Vec<Transaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub from_shard: u32,
    pub to_shard: u32,
    pub transaction: Transaction,
    pub timestamp: u64,
    pub status: MessageStatus,
    pub retry_count: u32,
    pub proof: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum MessageStatus {
    Pending,
    Processing,
    Processed,
    Failed,
    Expired,
}

#[derive(Clone, Debug)]
pub struct SyncState {
    pub last_sync_time: u64,
    pub pending_syncs: HashSet<u32>,
    pub failed_syncs: HashMap<u32, u32>,
    pub sync_in_progress: bool,
}

pub struct ShardRouter {
    pub shards: Arc<Mutex<HashMap<u32, Shard>>>,
    pub cross_shard_messages: Arc<Mutex<Vec<CrossShardMessage>>>,
    pub shard_loads: Arc<Mutex<HashMap<u32, f64>>>,
    pub sync_state: Arc<Mutex<SyncState>>,
    pub total_shards: u32,
    pub rebalance_threshold: f64,
    pub max_shard_load: f64,
}

impl ShardRouter {
    pub fn new(total_shards: u32) -> Self {
        let mut shards = HashMap::new();
        let mut shard_loads = HashMap::new();
        
        for i in 0..total_shards {
            shards.insert(i, Shard {
                id: i,
                state_root: format!("genesis_state_root_{}", i),
                transactions: Vec::new(),
                validators: HashSet::new(),
                load: 0.0,
                last_sync: Utc::now().timestamp() as u64,
                last_block: None,
                pending_txs: Vec::new(),
                processed_txs: Vec::new(),
            });
            shard_loads.insert(i, 0.0);
        }

        Self {
            shards: Arc::new(Mutex::new(shards)),
            cross_shard_messages: Arc::new(Mutex::new(Vec::new())),
            shard_loads: Arc::new(Mutex::new(shard_loads)),
            sync_state: Arc::new(Mutex::new(SyncState {
                last_sync_time: Utc::now().timestamp() as u64,
                pending_syncs: HashSet::new(),
                failed_syncs: HashMap::new(),
                sync_in_progress: false,
            })),
            total_shards,
            rebalance_threshold: 1.5,
            max_shard_load: 1000.0,
        }
    }

    pub async fn route_transaction(&self, transaction: &Transaction) -> Result<u32, ShardError> {
        let shard_id = self.calculate_shard_id(transaction).await;
        let mut shards = self.shards.lock().await;
        
        if let Some(shard) = shards.get_mut(&shard_id) {
            if self.is_cross_shard_transaction(transaction).await? {
                self.handle_cross_shard_transaction(transaction, shard_id).await?;
            } else {
                shard.pending_txs.push(transaction.clone());
                self.update_shard_load(shard_id, 1.0).await?;
            }
            Ok(shard_id)
        } else {
            Err(ShardError::ShardNotFound)
        }
    }

    pub async fn process_shard_transactions(&self, shard_id: ShardId) -> Result<Vec<Transaction>, ShardError> {
        let mut shards = self.shards.lock().await;
        let shard = shards.get_mut(&shard_id).ok_or(ShardError::ShardNotFound)?;
        
        let mut processed = Vec::new();
        let mut remaining = Vec::new();
        
        for tx in shard.pending_txs.drain(..) {
            if self.validate_transaction(&tx).await? {
                processed.push(tx.clone());
                shard.processed_txs.push(tx);
            } else {
                remaining.push(tx);
            }
        }
        
        shard.pending_txs = remaining;
        self.update_shard_load(shard_id, -(processed.len() as f64)).await?;
        
        Ok(processed)
    }

    pub async fn send_cross_shard_message(&self, message: CrossShardMessage) -> Result<(), ShardError> {
        if message.from_shard >= self.total_shards || message.to_shard >= self.total_shards {
            return Err(ShardError::InvalidShardId);
        }

        let mut messages = self.cross_shard_messages.lock().await;
        messages.push(message);
        Ok(())
    }

    pub async fn process_cross_shard_messages(&self) -> Result<usize, ShardError> {
        let mut messages = self.cross_shard_messages.lock().await;
        let mut processed_count = 0;
        
        for message in messages.iter_mut() {
            if message.status == MessageStatus::Pending {
                match self.process_cross_shard_message(message).await {
                    Ok(()) => {
                        message.status = MessageStatus::Processed;
                        processed_count += 1;
                    }
                    Err(_) => {
                        message.retry_count += 1;
                        if message.retry_count > 3 {
                            message.status = MessageStatus::Failed;
                        }
                    }
                }
            }
        }
        
        messages.retain(|msg| msg.status != MessageStatus::Processed);
        Ok(processed_count)
    }

    pub async fn sync_shards(&self) -> Result<(), ShardError> {
        let mut sync_state = self.sync_state.lock().await;
        
        if sync_state.sync_in_progress {
            return Ok(());
        }
        
        sync_state.sync_in_progress = true;
        drop(sync_state);
        
        let shards = self.shards.lock().await;
        let current_time = Utc::now().timestamp() as u64;
        
        for (shard_id, shard) in shards.iter() {
            if self.needs_sync(shard, current_time).await {
                self.sync_shard_state(*shard_id).await?;
            }
        }
        
        let mut sync_state = self.sync_state.lock().await;
        sync_state.last_sync_time = current_time;
        sync_state.sync_in_progress = false;
        
        Ok(())
    }

    pub async fn rebalance_shards(&self) -> Result<(), ShardError> {
        let shard_loads = self.shard_loads.lock().await;
        let avg_load = self.calculate_average_load(&shard_loads);
        
        let overloaded_shards: Vec<(u32, f64)> = shard_loads
            .iter()
            .filter(|(_, &load)| load > avg_load * self.rebalance_threshold)
            .map(|(&id, &load)| (id, load))
            .collect();
        
        drop(shard_loads);
        
        for (shard_id, load) in overloaded_shards {
            self.redistribute_load(shard_id, load - avg_load).await?;
        }
        
        Ok(())
    }

    pub async fn add_validator_to_shard(&self, shard_id: ShardId, validator: String) -> Result<(), ShardError> {
        let mut shards = self.shards.lock().await;
        let shard = shards.get_mut(&shard_id).ok_or(ShardError::ShardNotFound)?;
        
        if shard.validators.len() >= 100 {
            return Err(ShardError::TooManyValidators);
        }
        
        shard.validators.insert(validator);
        Ok(())
    }

    pub async fn remove_validator_from_shard(&self, shard_id: ShardId, validator: &str) -> Result<(), ShardError> {
        let mut shards = self.shards.lock().await;
        let shard = shards.get_mut(&shard_id).ok_or(ShardError::ShardNotFound)?;
        
        if shard.validators.len() <= 1 {
            return Err(ShardError::InsufficientValidators);
        }
        
        shard.validators.remove(validator);
        Ok(())
    }

    pub async fn get_shard_info(&self, shard_id: ShardId) -> Result<Shard, ShardError> {
        let shards = self.shards.lock().await;
        shards.get(&shard_id)
            .cloned()
            .ok_or(ShardError::ShardNotFound)
    }

    pub async fn get_shard_statistics(&self) -> HashMap<ShardId, ShardStats> {
        let shards = self.shards.lock().await;
        let loads = self.shard_loads.lock().await;
        
        shards.iter().map(|(id, shard)| {
            let stats = ShardStats {
                id: *id,
                validator_count: shard.validators.len(),
                pending_tx_count: shard.pending_txs.len(),
                processed_tx_count: shard.processed_txs.len(),
                load: loads.get(id).copied().unwrap_or(0.0),
                last_sync: shard.last_sync,
            };
            (*id, stats)
        }).collect()
    }

    async fn calculate_shard_id(&self, transaction: &Transaction) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        transaction.from.hash(&mut hasher);
        transaction.to.hash(&mut hasher);
        (hasher.finish() % self.total_shards as u64) as u32
    }

    async fn is_cross_shard_transaction(&self, transaction: &Transaction) -> Result<bool, ShardError> {
        let from_shard = self.calculate_shard_for_address(&transaction.from).await;
        let to_shard = self.calculate_shard_for_address(&transaction.to).await;
        Ok(from_shard != to_shard)
    }

    async fn calculate_shard_for_address(&self, address: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        address.hash(&mut hasher);
        (hasher.finish() % self.total_shards as u64) as u32
    }

    async fn handle_cross_shard_transaction(&self, transaction: &Transaction, from_shard: ShardId) -> Result<(), ShardError> {
        let to_shard = self.calculate_shard_for_address(&transaction.to).await;
        
        let message = CrossShardMessage {
            from_shard,
            to_shard,
            transaction: transaction.clone(),
            timestamp: Utc::now().timestamp() as u64,
            status: MessageStatus::Pending,
            retry_count: 0,
            proof: Some(format!("proof_{}_{}", from_shard, to_shard)),
        };
        
        self.send_cross_shard_message(message).await
    }

    async fn validate_transaction(&self, _transaction: &Transaction) -> Result<bool, ShardError> {
        Ok(true)
    }

    async fn process_cross_shard_message(&self, message: &mut CrossShardMessage) -> Result<(), ShardError> {
        let mut shards = self.shards.lock().await;
        
        let to_shard = shards.get_mut(&message.to_shard)
            .ok_or(ShardError::ShardNotFound)?;
        
        message.status = MessageStatus::Processing;
        to_shard.transactions.push(message.transaction.clone());
        
        Ok(())
    }

    async fn needs_sync(&self, shard: &Shard, current_time: u64) -> bool {
        current_time - shard.last_sync > 300
    }

    async fn sync_shard_state(&self, shard_id: u32) -> Result<(), ShardError> {
        let mut shards = self.shards.lock().await;
        let shard = shards.get_mut(&shard_id).ok_or(ShardError::ShardNotFound)?;
        
        shard.last_sync = Utc::now().timestamp() as u64;
        
        let new_state_root = format!("synced_state_{}_{}", shard_id, shard.last_sync);
        shard.state_root = new_state_root;
        
        Ok(())
    }

    fn calculate_average_load(&self, loads: &HashMap<u32, f64>) -> f64 {
        if loads.is_empty() {
            return 0.0;
        }
        loads.values().sum::<f64>() / loads.len() as f64
    }

    async fn redistribute_load(&self, overloaded_shard: u32, excess_load: f64) -> Result<(), ShardError> {
        let mut shard_loads = self.shard_loads.lock().await;
        let avg_load = self.calculate_average_load(&shard_loads);
        
        let underloaded_shards: Vec<u32> = shard_loads
            .iter()
            .filter(|(&id, &load)| id != overloaded_shard && load < avg_load)
            .map(|(&id, _)| id)
            .collect();
        
        if underloaded_shards.is_empty() {
            return Ok(());
        }
        
        let load_per_shard = excess_load / underloaded_shards.len() as f64;
        
        for shard_id in underloaded_shards {
            if let Some(load) = shard_loads.get_mut(&shard_id) {
                *load += load_per_shard;
            }
        }
        
        if let Some(load) = shard_loads.get_mut(&overloaded_shard) {
            *load -= excess_load;
        }
        
        Ok(())
    }

    async fn update_shard_load(&self, shard_id: ShardId, delta: f64) -> Result<(), ShardError> {
        let mut shard_loads = self.shard_loads.lock().await;
        let load = shard_loads.get_mut(&shard_id).ok_or(ShardError::ShardNotFound)?;
        
        *load = (*load + delta).max(0.0).min(self.max_shard_load);
        Ok(())
    }
}

pub trait IShardManager {
    fn get_shard_info(&self, shard_id: u32) -> Option<Shard>;
    fn update_shard_state(&mut self, shard_id: u32, new_state: String) -> Result<(), String>;
    fn validate_cross_shard_transaction(&self, transaction: &Transaction) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStats {
    pub id: ShardId,
    pub validator_count: usize,
    pub pending_tx_count: usize,
    pub processed_tx_count: usize,
    pub load: f64,
    pub last_sync: u64,
}

pub struct ShardManagerData {
    pub shards: HashMap<ShardId, Shard>,
    pub total_shards: u32,
    pub router: ShardRouter,
}

impl ShardManagerData {
    pub fn new(total_shards: u32) -> Self {
        let router = ShardRouter::new(total_shards);
        let shards = HashMap::new();

        Self {
            shards,
            total_shards,
            router,
        }
    }

    pub fn get_shard(&self, shard_id: ShardId) -> Option<&Shard> {
        self.shards.get(&shard_id)
    }

    pub async fn add_validator(&mut self, shard_id: ShardId, validator: String) -> Result<(), ShardError> {
        self.router.add_validator_to_shard(shard_id, validator).await
    }

    pub async fn remove_validator(&mut self, shard_id: ShardId, validator: &str) -> Result<(), ShardError> {
        self.router.remove_validator_from_shard(shard_id, validator).await
    }

    pub async fn update_shard_state(&mut self, shard_id: ShardId, state_root: String, block: Option<Block>) -> Result<(), ShardError> {
        if let Some(shard) = self.shards.get_mut(&shard_id) {
            shard.state_root = state_root;
            shard.last_block = block;
            shard.last_sync = Utc::now().timestamp() as u64;
            Ok(())
        } else {
            Err(ShardError::ShardNotFound)
        }
    }

    pub async fn process_transactions(&mut self, shard_id: ShardId) -> Result<Vec<Transaction>, ShardError> {
        self.router.process_shard_transactions(shard_id).await
    }

    pub async fn get_statistics(&self) -> HashMap<ShardId, ShardStats> {
        self.router.get_shard_statistics().await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardError {
    ShardNotFound,
    InvalidShardId,
    ValidatorNotFound,
    StateUpdateFailed,
    TooManyValidators,
    InsufficientValidators,
    CrossShardError,
    SyncError,
    LoadBalancingError,
}

impl std::fmt::Display for ShardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShardError::ShardNotFound => write!(f, "Shard not found"),
            ShardError::InvalidShardId => write!(f, "Invalid shard ID"),
            ShardError::ValidatorNotFound => write!(f, "Validator not found"),
            ShardError::StateUpdateFailed => write!(f, "Failed to update shard state"),
            ShardError::TooManyValidators => write!(f, "Too many validators in shard"),
            ShardError::InsufficientValidators => write!(f, "Insufficient validators in shard"),
            ShardError::CrossShardError => write!(f, "Cross-shard operation failed"),
            ShardError::SyncError => write!(f, "Shard synchronization failed"),
            ShardError::LoadBalancingError => write!(f, "Load balancing failed"),
        }
    }
}

impl std::error::Error for ShardError {}

impl IShardManager for ShardRouter {
    fn get_shard_info(&self, shard_id: u32) -> Option<Shard> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.get_shard_info(shard_id).await.ok()
        })
    }

    fn update_shard_state(&mut self, shard_id: u32, new_state: String) -> Result<(), String> {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut shards = self.shards.lock().await;
            if let Some(shard) = shards.get_mut(&shard_id) {
                shard.state_root = new_state;
                shard.last_sync = Utc::now().timestamp() as u64;
                Ok(())
            } else {
                Err("Shard not found".to_string())
            }
        })
    }

    fn validate_cross_shard_transaction(&self, transaction: &Transaction) -> bool {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            self.is_cross_shard_transaction(transaction).await.unwrap_or(false)
        })
    }
}
