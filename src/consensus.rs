use crate::crypto::CryptoManager;
use crate::state::ChainState;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub stake: u64,
    pub beta_angle: f64,
    pub efficiency: f64,
    pub last_active: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub hash: String,
    pub previous_hash: String,
    pub height: u64,
    pub timestamp: DateTime<Utc>,
    pub transactions: Vec<Transaction>,
    pub validator: String,
    pub signature: String,
    pub merkle_root: String,
    pub torque: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    pub current_height: u64,
    pub last_block_hash: String,
    pub pending_transactions: Vec<Transaction>,
    pub active_validators: HashMap<String, Validator>,
    pub current_round: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub network_load: f64,
    pub total_stake: u64,
    pub active_validators: usize,
    pub total_validators: usize,
    pub current_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    pub validator_address: String,
    pub block_hash: String,
    pub vote_type: VoteType,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
    Commit,
}

impl ConsensusState {
    pub fn new(chain_state: Arc<ChainState>, crypto: Arc<Mutex<CryptoManager>>) -> Self {
        Self {
            current_height: 0,
            last_block_hash: "genesis".to_string(),
            pending_transactions: Vec::new(),
            active_validators: HashMap::new(),
            current_round: 0,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        // Initialize with current chain state
        // This would start the consensus process
        tracing::info!("Starting consensus state at height {}", self.current_height);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        // Stop consensus process gracefully
        tracing::info!("Stopping consensus state at height {}", self.current_height);
        self.pending_transactions.clear();
        Ok(())
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.pending_transactions.push(transaction);
    }

    pub fn remove_transaction(&mut self, tx_hash: &str) -> Option<Transaction> {
        if let Some(pos) = self
            .pending_transactions
            .iter()
            .position(|tx| tx.hash == tx_hash)
        {
            Some(self.pending_transactions.remove(pos))
        } else {
            None
        }
    }

    pub fn update_height(&mut self, height: u64, block_hash: String) {
        self.current_height = height;
        self.last_block_hash = block_hash;
        self.current_round = 0; // Reset round for new height
    }

    pub fn add_validator(&mut self, validator: Validator) {
        self.active_validators
            .insert(validator.address.clone(), validator);
    }

    pub fn remove_validator(&mut self, address: &str) {
        self.active_validators.remove(address);
    }

    pub fn get_validator(&self, address: &str) -> Option<&Validator> {
        self.active_validators.get(address)
    }

    pub fn increment_round(&mut self) {
        self.current_round += 1;
    }
}

pub struct RotaryBFT {
    validators: Arc<RwLock<HashMap<String, Validator>>>,
    chain_state: Arc<ChainState>,
    crypto: Arc<Mutex<CryptoManager>>,
    min_torque_threshold: f64,
    min_commit_torque: f64,
}

impl Validator {
    pub fn calculate_torque(&self, network_load: f64) -> f64 {
        if network_load <= 0.0 {
            return 0.0;
        }

        let beta_rad = self.beta_angle.to_radians();
        (self.stake as f64) * beta_rad.sin() / network_load * self.efficiency
    }

    pub fn can_vote(&self, network_load: f64) -> bool {
        self.is_active && self.calculate_torque(network_load) >= 8.0
    }

    pub fn validate_self_lock(&self) -> bool {
        const FRICTION_ANGLE: f64 = 8.5; // degrees
        const FRICTION_COEFF: f64 = 0.15;

        let beta_rad = self.beta_angle.to_radians();
        let friction_rad = FRICTION_ANGLE.to_radians();

        // tan(φ) ≤ μ·sec(β)
        friction_rad.tan() <= FRICTION_COEFF * beta_rad.cos().recip()
    }
}

impl RotaryBFT {
    pub fn new(chain_state: Arc<ChainState>) -> Self {
        Self {
            validators: Arc::new(RwLock::new(HashMap::new())),
            chain_state,
            crypto: Arc::new(Mutex::new(CryptoManager::new())),
            min_torque_threshold: 8.0, // 8 Nm
            min_commit_torque: 24.0,   // 24 Nm
        }
    }

    pub async fn add_validator(&self, validator: Validator) -> Result<()> {
        if !validator.validate_self_lock() {
            anyhow::bail!("Validator fails self-lock validation");
        }

        let mut validators = self.validators.write().await;
        validators.insert(validator.address.clone(), validator);
        Ok(())
    }

    pub async fn propose_block(&self, transactions: Vec<Transaction>) -> Result<Block> {
        let network_load = self.calculate_network_load().await;
        let proposer = self.select_block_proposer(network_load).await?;

        // Validate transactions
        let valid_transactions = self.validate_transactions(transactions).await?;

        // Create block
        let previous_block = self.get_latest_block().await?;
        let height = previous_block.height + 1;

        let block = Block {
            hash: String::new(), // Will be calculated
            previous_hash: previous_block.hash,
            height,
            timestamp: Utc::now(),
            transactions: valid_transactions.clone(),
            validator: proposer.address.clone(),
            signature: String::new(), // Will be calculated
            merkle_root: self.calculate_merkle_root(&valid_transactions),
            torque: proposer.calculate_torque(network_load),
        };

        // Calculate block hash
        let mut temp_block = block.clone();
        temp_block.hash = String::new();
        temp_block.signature = String::new();

        let block_data = serde_json::to_string(&temp_block)?;
        let calculated_hash = crate::crypto::CryptoManager::hash_sha256(block_data.as_bytes());

        // Sign the block
        let crypto = self.crypto.lock().await;
        let signature = crypto.sign_data(block_data.as_bytes())?;

        let mut final_block = temp_block;
        final_block.hash = calculated_hash;
        final_block.signature = signature;

        Ok(final_block)
    }

    pub async fn validate_and_commit_block(&self, block: Block) -> Result<bool> {
        let network_load = self.calculate_network_load().await;

        // Calculate total torque from voting validators
        let total_torque = self.calculate_voting_torque(network_load).await?;

        if total_torque < self.min_commit_torque {
            return Ok(false);
        }

        // Validate block structure
        if !self.validate_block_structure(&block).await? {
            return Ok(false);
        }

        // Execute transactions and update state
        self.chain_state
            .execute_transactions(&block.transactions)
            .await?;

        // Add block to chain
        self.chain_state.add_block(&block).await?;

        Ok(true)
    }

    async fn calculate_network_load(&self) -> f64 {
        // Simple network load calculation based on pending transactions
        let pending = self
            .chain_state
            .get_pending_transactions()
            .await
            .unwrap_or_default();
        let base_load = 10.0;
        base_load + (pending.len() as f64 * 0.1)
    }

    async fn select_block_proposer(&self, network_load: f64) -> Result<Validator> {
        let validators = self.validators.read().await;

        let mut best_validator = None;
        let mut best_torque = 0.0;

        for validator in validators.values() {
            if validator.can_vote(network_load) {
                let torque = validator.calculate_torque(network_load);
                if torque > best_torque {
                    best_torque = torque;
                    best_validator = Some(validator.clone());
                }
            }
        }

        best_validator.ok_or_else(|| anyhow::anyhow!("No eligible validators found"))
    }

    async fn calculate_voting_torque(&self, network_load: f64) -> Result<f64> {
        let validators = self.validators.read().await;
        let mut total_torque = 0.0;

        for validator in validators.values() {
            if validator.can_vote(network_load) {
                total_torque += validator.calculate_torque(network_load);
            }
        }

        Ok(total_torque)
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<Transaction>,
    ) -> Result<Vec<Transaction>> {
        let mut valid_transactions = Vec::new();

        for tx in transactions {
            if self.chain_state.validate_transaction(&tx).await? {
                valid_transactions.push(tx);
            }
        }

        Ok(valid_transactions)
    }

    async fn validate_block_structure(&self, block: &Block) -> Result<bool> {
        // Validate block hash
        let mut temp_block = block.clone();
        temp_block.hash = String::new();
        temp_block.signature = String::new();

        let block_data = serde_json::to_string(&temp_block)?;
        let calculated_hash = crate::crypto::CryptoManager::hash_sha256(block_data.as_bytes());

        if calculated_hash != block.hash {
            return Ok(false);
        }

        // Validate merkle root
        let calculated_merkle = self.calculate_merkle_root(&block.transactions);
        if calculated_merkle != block.merkle_root {
            return Ok(false);
        }

        // Validate proposer torque
        let validators = self.validators.read().await;
        if let Some(validator) = validators.get(&block.validator) {
            let network_load = self.calculate_network_load().await;
            let required_torque = validator.calculate_torque(network_load);
            if block.torque < required_torque || required_torque < self.min_torque_threshold {
                tracing::warn!(
                    "Block torque {} below threshold {}",
                    block.torque,
                    self.min_torque_threshold
                );
                return Ok(false);
            }
        } else {
            tracing::error!("Unknown validator {} for block", block.validator);
            return Ok(false);
        }

        // Validate timestamp (not too far in future or past)
        let now = Utc::now();
        let time_diff = (now.timestamp() - block.timestamp.timestamp()).abs();
        if time_diff > 300 {
            // 5 minutes tolerance
            tracing::warn!(
                "Block timestamp too far from current time: {} seconds",
                time_diff
            );
            return Ok(false);
        }

        Ok(true)
    }

    fn calculate_merkle_root(&self, transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return "empty".to_string();
        }

        let tx_hashes: Vec<String> = transactions.iter().map(|tx| tx.hash.clone()).collect();

        let tx_hashes_bytes: Vec<Vec<u8>> = tx_hashes.iter()
            .map(|hash| hash.as_bytes().to_vec())
            .collect();
        let merkle_tree = crate::crypto::MerkleTree::new(tx_hashes_bytes);
        merkle_tree.root
    }

    async fn get_latest_block(&self) -> Result<Block> {
        let status = self.chain_state.get_status().await?;

        if let Some(state_block) = self.chain_state.get_block(&status.best_block_hash).await? {
            // Convert state::Block to consensus::Block
            Ok(Block {
                hash: state_block.hash,
                previous_hash: state_block.previous_hash,
                height: state_block.index,
                timestamp: chrono::DateTime::from_timestamp(state_block.timestamp as i64, 0)
                    .unwrap_or_else(|| Utc::now()),
                transactions: state_block
                    .transactions
                    .iter()
                    .map(|tx| Transaction {
                        hash: tx.hash.clone(),
                        from: tx.from.clone(),
                        to: tx.to.clone(),
                        amount: tx.amount,
                        gas_price: tx.gas_price,
                        gas_limit: tx.gas_limit,
                        nonce: tx.nonce,
                        data: tx.data.clone(),
                        signature: tx.signature.clone(),
                        timestamp: chrono::DateTime::from_timestamp(tx.timestamp as i64, 0)
                            .unwrap_or_else(|| Utc::now()),
                    })
                    .collect(),
                validator: state_block.validator,
                signature: state_block.signatures.join(","),
                merkle_root: state_block.merkle_root,
                torque: 0.0,
            })
        } else {
            // Return genesis block
            Ok(Block {
                hash: "genesis".to_string(),
                previous_hash: "0".to_string(),
                height: 0,
                timestamp: Utc::now(),
                transactions: Vec::new(),
                validator: "genesis".to_string(),
                signature: "genesis".to_string(),
                merkle_root: "genesis".to_string(),
                torque: 0.0,
            })
        }
    }

    pub async fn start_consensus(&self) -> Result<()> {
        tracing::info!("Starting RotaryBFT consensus engine");

        // Initialize genesis validators if none exist
        let validators = self.validators.read().await;
        if validators.is_empty() {
            drop(validators);
            self.initialize_genesis_validators().await?;
        }

        Ok(())
    }

    pub async fn stop_consensus(&self) -> Result<()> {
        tracing::info!("Stopping RotaryBFT consensus engine");
        Ok(())
    }

    pub async fn is_validator_active(&self, address: &str) -> bool {
        let validators = self.validators.read().await;
        validators
            .get(address)
            .map(|v| v.is_active)
            .unwrap_or(false)
    }

    pub async fn get_validator_count(&self) -> usize {
        let validators = self.validators.read().await;
        validators.len()
    }

    pub async fn get_active_validator_count(&self) -> usize {
        let validators = self.validators.read().await;
        validators.values().filter(|v| v.is_active).count()
    }

    pub async fn initialize_genesis_validators(&self) -> Result<()> {
        let genesis_validators = vec![
            Validator {
                address: "genesis_validator_1".to_string(),
                stake: 10000,
                beta_angle: 40.0,
                efficiency: 0.92,
                last_active: Utc::now(),
                is_active: true,
            },
            Validator {
                address: "genesis_validator_2".to_string(),
                stake: 8000,
                beta_angle: 35.0,
                efficiency: 0.88,
                last_active: Utc::now(),
                is_active: true,
            },
            Validator {
                address: "genesis_validator_3".to_string(),
                stake: 12000,
                beta_angle: 45.0,
                efficiency: 0.95,
                last_active: Utc::now(),
                is_active: true,
            },
        ];

        for validator in genesis_validators {
            self.add_validator(validator).await?;
        }

        Ok(())
    }

    pub async fn get_validators(&self) -> Result<Vec<Validator>> {
        let validators = self.validators.read().await;
        Ok(validators.values().cloned().collect())
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>> {
        let state_txs = self.chain_state.get_pending_transactions().await?;
        
        let consensus_txs = state_txs.into_iter().map(|tx| Transaction {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            gas_price: tx.gas_price,
            gas_limit: tx.gas_limit,
            nonce: tx.nonce,
            data: tx.data,
            signature: tx.signature,
            timestamp: chrono::DateTime::from_timestamp(tx.timestamp as i64, 0)
                .unwrap_or_else(|| Utc::now()),
        }).collect();
        
        Ok(consensus_txs)
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> Result<()> {
        // Convert consensus transaction to state transaction
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
            nonce: transaction.nonce,
            data: transaction.data.clone(),
            signature: transaction.signature.clone(),
            timestamp: transaction.timestamp.timestamp() as u64,
            block_height: 0,
            status: crate::state::TransactionStatus::Pending,
        };

        // Validate transaction first
        if !self.chain_state.validate_transaction(&state_transaction).await? {
            anyhow::bail!("Transaction validation failed");
        }

        // Add to pending transactions
        self.chain_state.add_pending_transaction(state_transaction).await
    }

    pub async fn get_validator(&self, address: &str) -> Option<Validator> {
        let validators = self.validators.read().await;
        validators.get(address).cloned()
    }

    pub async fn remove_validator(&self, address: &str) -> Result<()> {
        let mut validators = self.validators.write().await;
        validators.remove(address);
        Ok(())
    }

    pub async fn update_validator(&self, validator: Validator) -> Result<()> {
        if !validator.validate_self_lock() {
            anyhow::bail!("Validator fails self-lock validation");
        }

        let mut validators = self.validators.write().await;
        validators.insert(validator.address.clone(), validator);
        Ok(())
    }

    pub async fn get_network_status(&self) -> Result<NetworkStatus> {
        let validators = self.validators.read().await;
        let network_load = self.calculate_network_load().await;
        let total_stake: u64 = validators.values().map(|v| v.stake).sum();
        let active_validators = validators.values().filter(|v| v.is_active).count();

        Ok(NetworkStatus {
            network_load,
            total_stake,
            active_validators,
            total_validators: validators.len(),
            current_height: self.chain_state.get_status().await?.height,
        })
    }

    pub async fn process_vote(&self, vote: ConsensusVote) -> Result<()> {
        // Validate vote
        let validators = self.validators.read().await;
        let validator = validators
            .get(&vote.validator_address)
            .ok_or_else(|| anyhow::anyhow!("Unknown validator"))?;

        let network_load = self.calculate_network_load().await;
        if !validator.can_vote(network_load) {
            anyhow::bail!("Validator cannot vote with current torque");
        }

        // Process the vote (simplified implementation)
        // In a real implementation, this would handle vote aggregation
        Ok(())
    }

    pub async fn finalize_block(&self, block: &Block) -> Result<()> {
        // Convert consensus block to state block
        let state_block = crate::state::Block {
            index: block.height,
            timestamp: block.timestamp.timestamp() as u64,
            previous_hash: block.previous_hash.clone(),
            merkle_root: block.merkle_root.clone(),
            transactions: block.transactions.iter().map(|tx| crate::state::Transaction {
                id: tx.hash.clone(),
                hash: tx.hash.clone(),
                from: tx.from.clone(),
                to: tx.to.clone(),
                value: tx.amount,
                amount: tx.amount,
                fee: tx.gas_price * tx.gas_limit,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                gas_used: 21000, // Default gas used
                nonce: tx.nonce,
                data: tx.data.clone(),
                signature: tx.signature.clone(),
                timestamp: tx.timestamp.timestamp() as u64,
                block_height: block.height,
                status: crate::state::TransactionStatus::Confirmed,
            }).collect(),
            hash: block.hash.clone(),
            signatures: vec![block.signature.clone()],
            validator: block.validator.clone(),
            gas_limit: block.transactions.iter().map(|tx| tx.gas_limit).sum(),
            gas_used: block.transactions.iter().map(|_| 21000u64).sum(), // Default gas used per tx
            size: 1024, // Default block size
            nonce: 0,   // Default nonce
        };
        
        // Add block to chain
        self.chain_state.add_block(&state_block).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validator_torque_calculation() {
        let validator = Validator {
            address: "test".to_string(),
            stake: 1000,
            beta_angle: 40.0,
            efficiency: 0.92,
            last_active: Utc::now(),
            is_active: true,
        };

        let torque = validator.calculate_torque(10.0);
        assert!(torque > 0.0);
        assert!(validator.can_vote(10.0));
    }

    #[tokio::test]
    async fn test_self_lock_validation() {
        let validator = Validator {
            address: "test".to_string(),
            stake: 1000,
            beta_angle: 40.0,
            efficiency: 0.92,
            last_active: Utc::now(),
            is_active: true,
        };

        assert!(validator.validate_self_lock());

        let invalid_validator = Validator {
            beta_angle: 80.0, // Too high angle
            ..validator
        };

        assert!(!invalid_validator.validate_self_lock());
    }

    #[tokio::test]
    async fn test_block_proposal() {
        let state = Arc::new(ChainState::new());
        let consensus = RotaryBFT::new(state);

        consensus.initialize_genesis_validators().await.unwrap();

        let transactions = vec![Transaction {
            hash: "tx1".to_string(),
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount: 100,
            gas_price: 21,
            gas_limit: 21000,
            nonce: 1,
            data: Vec::new(),
            signature: "sig1".to_string(),
            timestamp: Utc::now(),
        }];

        let block = consensus.propose_block(transactions).await.unwrap();
        assert_eq!(block.height, 1);
        assert!(!block.hash.is_empty());
    }
}
