use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;

use crate::crypto::CryptoManager;
use crate::state::ChainState;

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

pub struct ConsensusManager {
    state: Arc<RwLock<ConsensusState>>,
    chain_state: Arc<ChainState>,
    crypto_manager: Arc<CryptoManager>,
    validators: Arc<Mutex<HashMap<String, Validator>>>,
}

impl ConsensusManager {
    pub fn new(chain_state: Arc<ChainState>, crypto_manager: Arc<CryptoManager>) -> Self {
        let initial_state = ConsensusState {
            current_height: 0,
            last_block_hash: "genesis".to_string(),
            pending_transactions: Vec::new(),
            active_validators: HashMap::new(),
            current_round: 0,
        };

        Self {
            state: Arc::new(RwLock::new(initial_state)),
            chain_state,
            crypto_manager,
            validators: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting consensus manager");
        // Initialize genesis validators if needed
        self.initialize_genesis_validators().await?;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping consensus manager");
        Ok(())
    }

    pub async fn add_validator(&self, validator: Validator) -> Result<()> {
        // Validate minimum stake
        if validator.stake < 1000 {
            anyhow::bail!("Validator stake below minimum requirement");
        }

        // Validate beta angle is within acceptable range
        if validator.beta_angle < 10.0 || validator.beta_angle > 80.0 {
            anyhow::bail!("Invalid beta angle: must be between 10-80 degrees");
        }

        let mut validators = self.validators.lock().await;
        validators.insert(validator.address.clone(), validator.clone());

        let mut state = self.state.write().await;
        state.active_validators.insert(validator.address.clone(), validator);

        tracing::info!("Added validator: {}", validator.address);
        Ok(())
    }

    pub async fn propose_block(&self, transactions: Vec<Transaction>) -> Result<Block> {
        let state = self.state.read().await;

        // Select proposer based on stake-weighted selection
        let proposer = self.select_block_proposer(&state.active_validators).await?;

        // Validate transactions
        let valid_transactions = self.validate_transactions(transactions).await?;

        // Calculate merkle root
        let merkle_root = self.calculate_merkle_root(&valid_transactions)?;

        // Create block
        let block = Block {
            hash: String::new(), // Will be calculated after creation
            previous_hash: state.last_block_hash.clone(),
            height: state.current_height + 1,
            timestamp: Utc::now(),
            transactions: valid_transactions,
            validator: proposer.address.clone(),
            signature: String::new(), // Will be signed after hash calculation
            merkle_root,
        };

        // Calculate block hash
        let block_hash = self.calculate_block_hash(&block)?;

        // TODO: Sign block with proposer's private key
        let mut signed_block = block;
        signed_block.hash = block_hash;
        // signed_block.signature = sign_block_hash(...);

        Ok(signed_block)
    }

    pub async fn validate_block(&self, block: &Block) -> Result<bool> {
        // Validate block structure
        if block.transactions.is_empty() {
            return Ok(false);
        }

        // Validate previous hash
        let state = self.state.read().await;
        if block.previous_hash != state.last_block_hash {
            return Ok(false);
        }

        // Validate height
        if block.height != state.current_height + 1 {
            return Ok(false);
        }

        // Validate timestamp (not too far in future)
        let now = Utc::now();
        if block.timestamp > now + chrono::Duration::minutes(5) {
            return Ok(false);
        }

        // Validate proposer is active validator
        if !state.active_validators.contains_key(&block.validator) {
            return Ok(false);
        }

        // Validate merkle root
        let calculated_merkle = self.calculate_merkle_root(&block.transactions)?;
        if block.merkle_root != calculated_merkle {
            return Ok(false);
        }

        // Validate transactions
        for tx in &block.transactions {
            if !self.validate_transaction(tx).await? {
                return Ok(false);
            }
        }

        // TODO: Validate block signature

        Ok(true)
    }

    pub async fn commit_block(&self, block: Block) -> Result<()> {
        // Final validation
        if !self.validate_block(&block).await? {
            anyhow::bail!("Invalid block cannot be committed");
        }

        // Update chain state
        self.chain_state.add_block(block.clone()).await?;

        // Update consensus state
        let mut state = self.state.write().await;
        state.current_height = block.height;
        state.last_block_hash = block.hash;
        state.current_round += 1;

        // Remove committed transactions from pending
        let committed_hashes: std::collections::HashSet<_> = 
            block.transactions.iter().map(|tx| &tx.hash).collect();
        state.pending_transactions.retain(|tx| !committed_hashes.contains(&tx.hash));

        tracing::info!("Committed block {} at height {}", block.hash, block.height);
        Ok(())
    }

    async fn initialize_genesis_validators(&self) -> Result<()> {
        // Add genesis validators with default parameters
        let genesis_validators = vec![
            Validator {
                address: "genesis_validator_1".to_string(),
                stake: 10000,
                beta_angle: 40.0,
                efficiency: 0.92,
                last_active: Utc::now(),
                is_active: true,
            },
        ];

        for validator in genesis_validators {
            self.add_validator(validator).await?;
        }

        Ok(())
    }

    async fn select_block_proposer(&self, validators: &HashMap<String, Validator>) -> Result<&Validator> {
        if validators.is_empty() {
            anyhow::bail!("No active validators available");
        }

        // Simple stake-weighted random selection
        // TODO: Implement proper weighted selection algorithm
        let validator = validators.values().next().unwrap();
        Ok(validator)
    }

    async fn validate_transactions(&self, transactions: Vec<Transaction>) -> Result<Vec<Transaction>> {
        let mut valid_transactions = Vec::new();

        for tx in transactions {
            if self.validate_transaction(&tx).await? {
                valid_transactions.push(tx);
            }
        }

        Ok(valid_transactions)
    }

    async fn validate_transaction(&self, tx: &Transaction) -> Result<bool> {
        // Basic validation
        if tx.amount == 0 {
            return Ok(false);
        }

        if tx.from == tx.to {
            return Ok(false);
        }

        // Check sender has sufficient balance
        let sender_balance = self.chain_state.get_account_balance(&tx.from).await?;
        if sender_balance < tx.amount + (tx.gas_price * tx.gas_limit) {
            return Ok(false);
        }

        // TODO: Validate signature
        // TODO: Validate nonce

        Ok(true)
    }

    fn calculate_merkle_root(&self, transactions: &[Transaction]) -> Result<String> {
        if transactions.is_empty() {
            return Ok("empty_tree".to_string());
        }

        // Simple implementation - should use proper Merkle tree
        let mut hasher = sha3::Keccak256::new();
        for tx in transactions {
            hasher.update(tx.hash.as_bytes());
        }

        Ok(hex::encode(hasher.finalize()))
    }

    fn calculate_block_hash(&self, block: &Block) -> Result<String> {
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(block.previous_hash.as_bytes());
        hasher.update(&block.height.to_le_bytes());
        hasher.update(block.timestamp.timestamp().to_le_bytes());
        hasher.update(block.merkle_root.as_bytes());
        hasher.update(block.validator.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    pub async fn calculate_validator_torque(&self, validator: &Validator, network_load: f64) -> f64 {
        if network_load <= 0.0 {
            return 0.0;
        }

        let beta_rad = validator.beta_angle.to_radians();
        let base_torque = (validator.stake as f64) * beta_rad.sin() / network_load;
        base_torque * validator.efficiency
    }

    pub async fn is_self_lock_active(&self, cpu_temp: f64) -> bool {
        // Self-lock is active if CPU temperature is below 80°C
        cpu_temp < 80.0
    }
}