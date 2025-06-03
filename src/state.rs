use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use sha3::{Digest, Keccak256};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub height: u64,
    pub best_block_hash: String,
    pub total_transactions: u64,
    pub validator_count: u64,
    pub total_supply: u64,
    pub active_accounts: u64,
    pub pending_transactions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
    pub storage: HashMap<String, String>,
    pub code_hash: String,
    pub storage_root: String,
    pub created_at: u64,
    pub last_activity: u64,
}

impl Account {
    pub fn new(address: String) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        Account {
            address,
            balance: 0,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
            code_hash: String::new(),
            storage_root: String::new(),
            created_at: timestamp,
            last_activity: timestamp,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = chrono::Utc::now().timestamp() as u64;
    }

    pub fn is_contract(&self) -> bool {
        self.code.is_some()
    }

    pub fn get_storage(&self, key: &str) -> Option<&String> {
        self.storage.get(key)
    }

    pub fn set_storage(&mut self, key: String, value: String) {
        self.storage.insert(key, value);
        self.update_activity();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: u64,
    pub amount: u64,
    pub fee: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub gas_used: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub signature: String,
    pub timestamp: u64,
    pub block_height: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Failed,
    Rejected,
}

impl Transaction {
    pub fn new(
        from: String,
        to: String,
        amount: u64,
        gas_limit: u64,
        gas_price: u64,
        nonce: u64,
        data: Vec<u8>,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let id = Self::generate_id(&from, &to, timestamp, nonce);
        let hash = Self::calculate_hash(&id, &from, &to, amount, timestamp);

        Transaction {
            id,
            hash,
            from,
            to,
            value: amount,
            amount,
            fee: gas_limit * gas_price,
            gas_limit,
            gas_price,
            gas_used: 0, // default
            nonce,
            data,
            signature: String::new(),
            timestamp,
            block_height: 0, //default
            status: "Pending".to_string(), //TransactionStatus::Pending,
        }
    }

    fn generate_id(from: &str, to: &str, timestamp: u64, nonce: u64) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(from.as_bytes());
        hasher.update(to.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(nonce.to_be_bytes());
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    fn calculate_hash(id: &str, from: &str, to: &str, amount: u64, timestamp: u64) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(id.as_bytes());
        hasher.update(from.as_bytes());
        hasher.update(to.as_bytes());
        hasher.update(amount.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    pub fn total_cost(&self) -> u64 {
        self.amount + self.fee
    }

    pub fn is_contract_call(&self) -> bool {
        !self.data.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub transactions: Vec<Transaction>,
    pub hash: String,
    pub signatures: Vec<String>,
    pub validator: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub size: u64,
    pub nonce: u64,
}

impl Block {
    pub fn new(
        index: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
        validator: String,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let merkle_root = Self::calculate_merkle_root(&transactions);
        let gas_used = transactions.iter().map(|tx| tx.gas_used).sum();
        let gas_limit = transactions.iter().map(|tx| tx.gas_limit).sum();

        let mut block = Block {
            index,
            timestamp,
            previous_hash,
            merkle_root: merkle_root.clone(),
            transactions,
            hash: String::new(),
            signatures: Vec::new(),
            validator,
            gas_limit,
            gas_used,
            size: 0,
            nonce: 0, //default
        };

        block.hash = block.calculate_hash();
        block.size = block.calculate_size();
        block
    }

    fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }

        let mut hasher = Keccak256::new();
        for tx in transactions {
            hasher.update(tx.hash.as_bytes());
        }
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    fn calculate_hash(&self) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(self.index.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(self.merkle_root.as_bytes());
        hasher.update(self.validator.as_bytes());
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    fn calculate_size(&self) -> u64 {
        let base_size = 256; // Block header size
        let tx_size: usize = self.transactions.iter()
            .map(|tx| tx.data.len() + 200) // Approximate transaction size
            .sum();
        (base_size + tx_size) as u64
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum StateError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    #[error("Account already exists: {0}")]
    AccountAlreadyExists(String),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
    #[error("Block not found: {0}")]
    BlockNotFound(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("State corruption detected: {0}")]
    StateCorruption(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Concurrent modification detected")]
    ConcurrentModification,
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug)]
pub struct ChainState {
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    pending_transactions: Arc<Mutex<Vec<Transaction>>>,
    confirmed_transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    blocks: Arc<Mutex<Vec<Block>>>,
    block_index: Arc<Mutex<HashMap<String, u64>>>,
    validator_set: Arc<Mutex<Vec<String>>>,
    current_height: Arc<Mutex<u64>>,
    total_supply: Arc<Mutex<u64>>,
    transaction_count: Arc<Mutex<u64>>,
    state_root: Arc<Mutex<String>>,
}

const INITIAL_SUPPLY: u64 = 1_000_000_000_000_000; // 1M tokens with 9 decimals

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            pending_transactions: Arc::new(Mutex::new(Vec::new())),
            confirmed_transactions: Arc::new(Mutex::new(HashMap::new())),
            blocks: Arc::new(Mutex::new(Vec::new())),
            block_index: Arc::new(Mutex::new(HashMap::new())),
            validator_set: Arc::new(Mutex::new(Vec::new())),
            current_height: Arc::new(Mutex::new(0)),
            total_supply: Arc::new(Mutex::new(INITIAL_SUPPLY)),
            transaction_count: Arc::new(Mutex::new(0)),
            state_root: Arc::new(Mutex::new(String::new())),
        }
    }

    pub async fn initialize_genesis(&self, genesis_accounts: Vec<(String, u64)>) -> Result<(), StateError> {
        let mut accounts = self.accounts.lock().await;
        let mut supply = self.total_supply.lock().await;

        *supply = 0;

        for (address, balance) in genesis_accounts {
            let mut account = Account::new(address.clone());
            account.balance = balance;
            accounts.insert(address, account);
            *supply += balance;
        }

        // Update state root
        self.update_state_root().await?;

        Ok(())
    }

    pub async fn get_status(&self) -> Result<ChainStatus, StateError> {
        let height = *self.current_height.lock().await;
        let blocks = self.blocks.lock().await;
        let accounts = self.accounts.lock().await;
        let pending = self.pending_transactions.lock().await;
        let validators = self.validator_set.lock().await;
        let total_supply = *self.total_supply.lock().await;
        let tx_count = *self.transaction_count.lock().await;

        let best_block_hash = blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000000000000000000000000000".to_string());

        Ok(ChainStatus {
            height,
            best_block_hash,
            total_transactions: tx_count,
            validator_count: validators.len() as u64,
            total_supply,
            active_accounts: accounts.len() as u64,
            pending_transactions: pending.len() as u64,
        })
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>, StateError> {
        let blocks = self.blocks.lock().await;
        let block_index = self.block_index.lock().await;

        if let Some(&index) = block_index.get(hash) {
            if let Some(block) = blocks.get(index as usize) {
                return Ok(Some(block.clone()));
            }
        }

        // Fallback: linear search
        Ok(blocks.iter().find(|b| b.hash == hash).cloned())
    }

    pub async fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, StateError> {
        let blocks = self.blocks.lock().await;
        Ok(blocks.get(height as usize).cloned())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>, StateError> {
        // First check confirmed transactions
        let confirmed = self.confirmed_transactions.lock().await;
        if let Some(tx) = confirmed.get(hash) {
            return Ok(Some(tx.clone()));
        }

        // Then check pending transactions
        let pending = self.pending_transactions.lock().await;
        Ok(pending.iter().find(|tx| tx.hash == hash).cloned())
    }

    pub async fn get_account(&self, address: &str) -> Option<Account> {
        let accounts = self.accounts.lock().await;
        accounts.get(address).cloned()
    }

    pub async fn get_balance(&self, address: &str) -> u64 {
        let accounts = self.accounts.lock().await;
        accounts.get(address)
            .map(|account| account.balance)
            .unwrap_or(0)
    }

    pub async fn get_nonce(&self, address: &str) -> u64 {
        let accounts = self.accounts.lock().await;
        accounts.get(address)
            .map(|account| account.nonce)
            .unwrap_or(0)
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, StateError> {
        let pending = self.pending_transactions.lock().await;
        Ok(pending.clone())
    }

    pub async fn get_pending_transaction_count(&self) -> usize {
        let pending = self.pending_transactions.lock().await;
        pending.len()
    }

    pub async fn create_account(&self, address: String) -> Result<(), StateError> {
        let mut accounts = self.accounts.lock().await;
        if accounts.contains_key(&address) {
            return Err(StateError::AccountAlreadyExists(address));
        }

        let account = Account::new(address.clone());
        accounts.insert(address, account);

        self.update_state_root().await?;
        Ok(())
    }

    pub async fn set_balance(&self, address: &str, balance: u64) -> Result<(), StateError> {
        let mut accounts = self.accounts.lock().await;
        let account = accounts.get_mut(address)
            .ok_or_else(|| StateError::AccountNotFound(address.to_string()))?;

        account.balance = balance;
        account.update_activity();

        drop(accounts);
        self.update_state_root().await?;
        Ok(())
    }

    pub async fn apply_transaction(&self, transaction: &Transaction) -> Result<(), StateError> {
        // Validate transaction
        self.validate_transaction(transaction).await?;

        let mut accounts = self.accounts.lock().await;

        // Get source account
        let from_account = accounts.get_mut(&transaction.from)
            .ok_or_else(|| StateError::AccountNotFound(transaction.from.clone()))?;

        // Validate nonce
        if from_account.nonce != transaction.nonce {
            return Err(StateError::InvalidNonce {
                expected: from_account.nonce,
                actual: transaction.nonce,
            });
        }

        let total_cost = transaction.total_cost();
        if from_account.balance < total_cost {
            return Err(StateError::InsufficientBalance {
                required: total_cost,
                available: from_account.balance,
            });
        }

        // Apply changes
        from_account.balance -= total_cost;
        from_account.nonce += 1;
        from_account.update_activity();

        // Update recipient
        let to_account = accounts.entry(transaction.to.clone())
            .or_insert_with(|| Account::new(transaction.to.clone()));
        to_account.balance += transaction.amount;
        to_account.update_activity();

        // Handle contract calls
        if transaction.is_contract_call() {
            // Contract execution would go here
            tracing::debug!("Contract call detected in transaction: {}", transaction.hash);
        }

        drop(accounts);

        // Update transaction count
        let mut tx_count = self.transaction_count.lock().await;
        *tx_count += 1;

        self.update_state_root().await?;
        Ok(())
    }

    pub async fn validate_transaction(&self, transaction: &Transaction) -> Result<bool, StateError> {
        if transaction.amount == 0 && transaction.data.is_empty() {
            return Err(StateError::InvalidTransaction("Empty transaction".to_string()));
        }

        if transaction.gas_price == 0 {
            return Err(StateError::InvalidTransaction("Zero gas price".to_string()));
        }

        if transaction.gas_limit == 0 {
            return Err(StateError::InvalidTransaction("Zero gas limit".to_string()));
        }

        let accounts = self.accounts.lock().await;
        let from_account = accounts.get(&transaction.from)
            .ok_or_else(|| StateError::AccountNotFound(transaction.from.clone()))?;

        // Validate nonce
        if from_account.nonce != transaction.nonce {
            return Ok(false);
        }

        // Validate balance
        let total_cost = transaction.total_cost();
        Ok(from_account.balance >= total_cost)
    }

    pub async fn add_pending_transaction(&self, mut transaction: Transaction) -> Result<(), StateError> {
        // Validate transaction
        if !self.validate_transaction(&transaction).await? {
            return Err(StateError::InvalidTransaction("Transaction validation failed".to_string()));
        }

        //transaction.status = TransactionStatus::Pending;

        let mut pool = self.pending_transactions.lock().await;

        // Check for duplicate transactions
        if pool.iter().any(|tx| tx.hash == transaction.hash) {
            return Err(StateError::InvalidTransaction("Duplicate transaction".to_string()));
        }

        pool.push(transaction);
        Ok(())
    }

    pub async fn add_block(&self, block: &Block) -> Result<(), StateError> {
        let mut blocks = self.blocks.lock().await;
        let mut block_index = self.block_index.lock().await;
        let mut confirmed_txs = self.confirmed_transactions.lock().await;
        let mut pending_txs = self.pending_transactions.lock().await;

        // Validate block
        if block.index != blocks.len() as u64 {
            return Err(StateError::InvalidBlock("Invalid block index".to_string()));
        }

        if !blocks.is_empty() {
            let last_block = blocks.last().unwrap();
            if block.previous_hash != last_block.hash {
                return Err(StateError::InvalidBlock("Invalid previous hash".to_string()));
            }
        }

        // Move transactions from pending to confirmed
        for tx in &block.transactions {
            let mut confirmed_tx = tx.clone();
            //confirmed_tx.status = TransactionStatus::Confirmed;
            //confirmed_tx.block_height = Some(block.index);
            confirmed_txs.insert(tx.hash.clone(), confirmed_tx);

            // Remove from pending
            pending_txs.retain(|pending_tx| pending_tx.hash != tx.hash);
        }

        // Add block
        block_index.insert(block.hash.clone(), block.index);
        blocks.push(block.clone());

        // Update current height
        let mut height = self.current_height.lock().await;
        *height = block.index;

        drop(blocks);
        drop(block_index);
        drop(confirmed_txs);
        drop(pending_txs);
        drop(height);

        self.update_state_root().await?;
        Ok(())
    }

    pub async fn execute_transactions(&self, transactions: &[Transaction]) -> Result<(), StateError> {
        for tx in transactions {
            self.apply_transaction(tx).await?;
        }
        Ok(())
    }

    pub async fn get_transactions_by_account(&self, address: &str, limit: Option<usize>) -> Result<Vec<Transaction>, StateError> {
        let confirmed = self.confirmed_transactions.lock().await;
        let pending = self.pending_transactions.lock().await;

        let mut transactions: Vec<Transaction> = confirmed.values()
            .filter(|tx| tx.from == address || tx.to == address)
            .cloned()
            .collect();

        transactions.extend(
            pending.iter()
                .filter(|tx| tx.from == address || tx.to == address)
                .cloned()
        );

        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            transactions.truncate(limit);
        }

        Ok(transactions)
    }

    pub async fn get_block_count(&self) -> u64 {
        let blocks = self.blocks.lock().await;
        blocks.len() as u64
    }

    pub async fn get_latest_blocks(&self, count: usize) -> Result<Vec<Block>, StateError> {
        let blocks = self.blocks.lock().await;
        let start = blocks.len().saturating_sub(count);
        Ok(blocks[start..].to_vec())
    }

    async fn update_state_root(&self) -> Result<(), StateError> {
        let accounts = self.accounts.lock().await;
        let mut hasher = Keccak256::new();

        let mut sorted_accounts: Vec<_> = accounts.iter().collect();
        sorted_accounts.sort_by(|a, b| a.0.cmp(b.0));

        for (address, account) in sorted_accounts {
            hasher.update(address.as_bytes());
            hasher.update(account.balance.to_be_bytes());
            hasher.update(account.nonce.to_be_bytes());
            if let Some(ref code) = account.code {
                hasher.update(code);
            }
        }

        let mut state_root = self.state_root.lock().await;
        *state_root = format!("0x{}", hex::encode(hasher.finalize()));

        Ok(())
    }

    pub async fn get_state_root(&self) -> String {
        let state_root = self.state_root.lock().await;
        state_root.clone()
    }

    pub async fn prune_old_transactions(&self, max_age_seconds: u64) -> Result<usize, StateError> {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let cutoff_time = current_time.saturating_sub(max_age_seconds);

        let mut confirmed = self.confirmed_transactions.lock().await;
        let initial_count = confirmed.len();

        confirmed.retain(|_, tx| tx.timestamp >= cutoff_time);

        Ok(initial_count - confirmed.len())
    }

    pub async fn get_account_count(&self) -> u64 {
        let accounts = self.accounts.lock().await;
        accounts.len() as u64
    }

    pub async fn backup_state(&self) -> Result<String, StateError> {
        let accounts = self.accounts.lock().await;
        let blocks = self.blocks.lock().await;
        let state_root = self.state_root.lock().await;

        let backup_data = serde_json::json!({
            "accounts": *accounts,
            "blocks": *blocks,
            "state_root": *state_root,
            "timestamp": chrono::Utc::now().timestamp()
        });

        serde_json::to_string(&backup_data)
            .map_err(|e| StateError::SerializationError(e.to_string()))
    }

    pub async fn get_account_balance(&self, address: &str) -> Result<u64, StateError> {
        Ok(self.get_balance(address).await)
    }

    pub async fn get_total_transaction_count(&self) -> Result<u64, StateError> {
        Ok(*self.transaction_count.lock().await)
    }

    pub async fn get_latest_block_height(&self) -> Result<u64, StateError> {
        Ok(*self.current_height.lock().await)
    }

    pub async fn get_blocks_by_height_range(&self, start: u64, end: u64) -> Result<Vec<Block>, StateError> {
        let blocks = self.blocks.lock().await;
        let mut result = Vec::new();

        for height in start..=end {
            if let Some(block) = blocks.get(height as usize) {
                result.push(block.clone());
            }
        }

        Ok(result)
    }

    pub async fn get_transactions_paginated(&self, page: usize, limit: usize) -> Result<Vec<Transaction>, StateError> {
        let confirmed = self.confirmed_transactions.lock().await;
        let pending = self.pending_transactions.lock().await;

        let mut all_transactions: Vec<Transaction> = confirmed.values().cloned().collect();
        all_transactions.extend(pending.iter().cloned());

        // Sort by timestamp descending
        all_transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply pagination
        let start = page * limit;
        let end = std::cmp::min(start + limit, all_transactions.len());

        if start >= all_transactions.len() {
            return Ok(Vec::new());
        }

        Ok(all_transactions[start..end].to_vec())
    }

    pub async fn get_blocks_paginated(&self, page: usize, limit: usize) -> Result<Vec<Block>, StateError> {
        let blocks = self.blocks.lock().await;

        // Calculate pagination
        let total_blocks = blocks.len();
        let start = page * limit;

        if start >= total_blocks {
            return Ok(Vec::new());
        }

        let end = std::cmp::min(start + limit, total_blocks);

        // Return blocks in reverse order (newest first)
        let mut result: Vec<Block> = blocks[start..end].to_vec();
        result.reverse();

        Ok(result)
    }

    pub async fn get_validator_set(&self) -> Vec<String> {
        let validators = self.validator_set.lock().await;
        validators.clone()
    }

    pub async fn add_validator(&self, validator_address: String) -> Result<(), StateError> {
        let mut validators = self.validator_set.lock().await;
        if !validators.contains(&validator_address) {
            validators.push(validator_address);
        }
        Ok(())
    }

    pub async fn remove_validator(&self, validator_address: &str) -> Result<(), StateError> {
        let mut validators = self.validator_set.lock().await;
        validators.retain(|v| v != validator_address);
        Ok(())
    }

    pub async fn get_mempool_size(&self) -> usize {
        let pending = self.pending_transactions.lock().await;
        pending.len()
    }

    pub async fn clear_mempool(&self) -> Result<(), StateError> {
        let mut pending = self.pending_transactions.lock().await;
        pending.clear();
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_chain_stats(&self) -> Result<ChainStats, StateError> {
        let height = *self.current_height.lock().await;
        let blocks = self.blocks.lock().await;
        let accounts = self.accounts.lock().await;
        let tx_count = *self.transaction_count.lock().await;
        let validators = self.validator_set.lock().await;

        // Calculate average block time
        let avg_block_time = if blocks.len() > 1 {
            let first_time = blocks.first().unwrap().timestamp;
            let last_time = blocks.last().unwrap().timestamp;
            let total_time = last_time - first_time;
            total_time as f64 / (blocks.len() - 1) as f64
        } else {
            0.0
        };

        Ok(ChainStats {
            total_blocks: height,
            total_transactions: tx_count,
            total_accounts: accounts.len() as u64,
            average_block_time: avg_block_time,
            network_hash_rate: 1000.0, // Placeholder
            active_validators: validators.len() as u64,
        })
    }

    pub async fn estimate_gas(&self, transaction: &Transaction) -> Result<u64, StateError> {
        // Base gas cost
        let mut gas_cost = 21000u64; // Base transaction cost

        // Add cost for data
        gas_cost += transaction.data.len() as u64 * 16; // 16 gas per byte

        // Add cost for value transfer
        if transaction.amount > 0 {
            gas_cost += 9000; // Additional cost for value transfer
        }

        // Contract interaction cost
        if transaction.is_contract_call() {
            gas_cost += 25000; // Additional cost for contract calls
        }

        Ok(gas_cost)
    }

    #[allow(dead_code)]
    pub async fn simulate_transaction(&self, transaction: &Transaction) -> Result<TransactionResult, StateError> {
        // Validate the transaction first
        if !self.validate_transaction(transaction).await? {
            return Ok(TransactionResult {
                success: false,
                gas_used: 0,
                error: Some("Transaction validation failed".to_string()),
                return_data: Vec::new(),
            });
        }

        let gas_estimate = self.estimate_gas(transaction).await?;

        Ok(TransactionResult {
            success: true,
            gas_used: gas_estimate,
            error: None,
            return_data: Vec::new(),
        })
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    pub success: bool,
    pub gas_used: u64,
    pub error: Option<String>,
    pub return_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_account_creation() {
        let state = ChainState::new();
        let result = state.create_account("0x123".to_string()).await;
        assert!(result.is_ok());

        let account = state.get_account("0x123").await;
        assert!(account.is_some());
    }

    #[tokio::test]
    async fn test_balance_operations() {
        let state = ChainState::new();
        state.create_account("0x123".to_string()).await.unwrap();```
        let result = state.set_balance("0x123", 1000).await;
        assert!(result.is_ok());

        let balance = state.get_balance("0x123").await;
        assert_eq!(balance, 1000);
    }

    #[tokio::test]
    async fn test_transaction_creation() {
        let tx = Transaction::new(
            "0x123".to_string(),
            "0x456".to_string(),
            1000,
            21000,
            20,
            0,
            vec![],
        );

        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.total_cost(), 1000 + (21000 * 20));
        //assert_eq!(tx.status, TransactionStatus::Pending);
    }

    #[tokio::test]
    async fn test_state_operations() {
        let state = ChainState::new();

        // Initialize with genesis accounts
        let genesis_accounts = vec![
            ("0x123".to_string(), 10000),
            ("0x456".to_string(), 5000),
        ];

        state.initialize_genesis(genesis_accounts).await.unwrap();

        let status = state.get_status().await.unwrap();
        assert_eq!(status.active_accounts, 2);
        assert_eq!(status.total_supply, 15000);
    }
}