use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use std::sync::Arc;
use sha3::{Digest, Keccak256};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub code: Option<Vec<u8>>, // Smart contract code
    pub storage: HashMap<String, String>,
    pub code_hash: String,
    pub storage_root: String,
}

impl Account {
    pub fn new(address: String) -> Self {
        Account {
            address,
            balance: 0,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
            code_hash: String::new(),
            storage_root: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub signature: String,
    pub timestamp: u64,
    pub amount: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateError {
    AccountNotFound,
    InsufficientBalance,
    AccountAlreadyExists,
    InvalidTransaction(String),
    InvalidNonce,
    Other(String),
}

pub struct ChainState {
    accounts: Arc<RwLock<HashMap<String, Account>>>,
    transaction_pool: Arc<RwLock<Vec<Transaction>>>,
    blocks: Arc<RwLock<Vec<Block>>>,
    current_block_height: Arc<RwLock<u64>>,
    total_supply: Arc<RwLock<u64>>,
    accounts: HashMap<String, Account>,
    transaction_count: u64,
    state_root: String,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            transaction_pool: Arc::new(RwLock::new(Vec::new())),
            blocks: Arc::new(RwLock::new(Vec::new())),
            current_block_height: Arc::new(RwLock::new(0)),
            total_supply: Arc::new(RwLock::new(1_000_000_000)), // 1B initial supply
            accounts: HashMap::new(),
            transaction_count: 0,
            state_root: String::new(),
        }
    }

    
    pub async fn apply_transaction(&mut self, transaction: &Transaction) -> Result<(), StateError> {
        // Validate transaction first
        if transaction.amount == 0 {
            return Err(StateError::InvalidTransaction("Zero amount transaction".to_string()));
        }

        // Check if accounts exist and create if necessary
        let from_account = self.accounts.get_mut(&transaction.from)
            .ok_or(StateError::AccountNotFound)?;

        // Validate nonce
        if from_account.nonce != transaction.nonce {
            return Err(StateError::InvalidNonce);
        }

        // Calculate total cost (amount + gas fees)
        let gas_cost = transaction.gas_price * transaction.gas_limit;
        let total_cost = transaction.amount + gas_cost;

        if from_account.balance < total_cost {
            return Err(StateError::InsufficientBalance);
        }

        // Apply changes atomically
        from_account.balance -= total_cost;
        from_account.nonce += 1;

        // Update recipient account
        let to_account = self.accounts.entry(transaction.to.clone())
            .or_insert_with(|| Account::new(transaction.to.clone()));
        to_account.balance += transaction.amount;

        // Process contract data if any
        if !transaction.data.is_empty() {
            self.process_contract_call(transaction).await?;
        }

        self.transaction_count += 1;

        // Update state root
        self.update_state_root().await?;

        Ok(())
    }

    async fn process_contract_call(&mut self, transaction: &Transaction) -> Result<(), StateError> {
        // Basic contract execution simulation
        // In a full implementation, this would involve WASM execution

        if transaction.to.starts_with("0x") && transaction.to.len() == 42 {
            // Contract call
            tracing::info!("Processing contract call to {}", transaction.to);

            // For now, just store the data
            // Real implementation would execute WASM contract
        }

        Ok(())
    }

    async fn update_state_root(&mut self) -> Result<(), StateError> {
        // Calculate new state root based on all account states
        let mut hasher = Keccak256::new();

        // Sort accounts for deterministic hash
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(address, _)| *address);

        for (address, account) in sorted_accounts {
            hasher.update(address.as_bytes());
            hasher.update(&account.balance.to_le_bytes());
            hasher.update(&account.nonce.to_le_bytes());
            hasher.update(&account.code_hash.as_bytes());
            hasher.update(&account.storage_root.as_bytes());
        }

        self.state_root = hex::encode(hasher.finalize());

        Ok(())
    }

    pub async fn get_account(&self, address: &str) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub async fn get_balance(&self, address: &str) -> u64 {
        self.accounts.get(address)
            .map(|account| account.balance)
            .unwrap_or(0)
    }

    pub async fn get_nonce(&self, address: &str) -> u64 {
        self.accounts.get(address)
            .map(|account| account.nonce)
            .unwrap_or(0)
    }

    pub async fn create_account(&mut self, address: String) -> Result<(), StateError> {
        if self.accounts.contains_key(&address) {
            return Err(StateError::AccountAlreadyExists);
        }

        let account = Account::new(address.clone());
        self.accounts.insert(address, account);

        self.update_state_root().await?;

        Ok(())
    }

    pub async fn set_balance(&mut self, address: &str, balance: u64) -> Result<(), StateError> {
        let account = self.accounts.get_mut(address)
            .ok_or(StateError::AccountNotFound)?;

        account.balance = balance;
        self.update_state_root().await?;

        Ok(())
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_account_creation() {
        let mut state = ChainState::new();
        let result = state.create_account("0x123".to_string()).await;
        assert!(result.is_ok());

        let account = state.get_account("0x123").await;
        assert!(account.is_some());
    }

    #[tokio::test]
    async fn test_set_balance() {
        let mut state = ChainState::new();
        state.create_account("0x123".to_string()).await.unwrap();
        let result = state.set_balance("0x123", 1000).await;
        assert!(result.is_ok());

        let balance = state.get_balance("0x123").await;
        assert_eq!(balance, 1000);
    }
}