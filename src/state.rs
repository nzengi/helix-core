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

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum StateError {
    #[error("Account not found")]
    AccountNotFound,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Account already exists")]
    AccountAlreadyExists,
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Other error: {0}")]
    Other(String),
}

pub struct ChainState {
    accounts: Arc<RwLock<HashMap<String, Account>>>,
    transaction_pool: Arc<RwLock<Vec<Transaction>>>,
    blocks: Arc<RwLock<Vec<Block>>>,
    current_block_height: Arc<RwLock<u64>>,
    total_supply: Arc<RwLock<u64>>,
    transaction_count: Arc<RwLock<u64>>,
    state_root: Arc<RwLock<String>>,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            transaction_pool: Arc::new(RwLock::new(Vec::new())),
            blocks: Arc::new(RwLock::new(Vec::new())),
            current_block_height: Arc::new(RwLock::new(0)),
            total_supply: Arc::new(RwLock::new(1_000_000_000)), // 1B initial supply
            transaction_count: Arc::new(RwLock::new(0)),
            state_root: Arc::new(RwLock::new(String::new())),
        }
    }

    
    pub async fn apply_transaction(&self, transaction: &Transaction) -> Result<(), StateError> {
        // Validate transaction first
        if transaction.amount == 0 {
            return Err(StateError::InvalidTransaction("Zero amount transaction".to_string()));
        }

        let mut accounts = self.accounts.write().await;

        // Check if from account exists
        let from_account = accounts.get_mut(&transaction.from)
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
        let to_account = accounts.entry(transaction.to.clone())
            .or_insert_with(|| Account::new(transaction.to.clone()));
        to_account.balance += transaction.amount;

        // Update transaction count
        let mut tx_count = self.transaction_count.write().await;
        *tx_count += 1;

        Ok(())
    }

    pub async fn validate_transaction(&self, transaction: &Transaction) -> Result<bool, StateError> {
        let accounts = self.accounts.read().await;
        
        // Check if from account exists
        let from_account = accounts.get(&transaction.from)
            .ok_or(StateError::AccountNotFound)?;

        // Validate nonce
        if from_account.nonce != transaction.nonce {
            return Ok(false);
        }

        // Calculate total cost
        let gas_cost = transaction.gas_price * transaction.gas_limit;
        let total_cost = transaction.amount + gas_cost;

        Ok(from_account.balance >= total_cost)
    }

    pub async fn add_pending_transaction(&self, transaction: Transaction) -> Result<(), StateError> {
        let mut pool = self.transaction_pool.write().await;
        pool.push(transaction);
        Ok(())
    }

    pub async fn get_account(&self, address: &str) -> Option<Account> {
        let accounts = self.accounts.read().await;
        accounts.get(address).cloned()
    }

    pub async fn get_balance(&self, address: &str) -> u64 {
        let accounts = self.accounts.read().await;
        accounts.get(address)
            .map(|account| account.balance)
            .unwrap_or(0)
    }

    pub async fn get_nonce(&self, address: &str) -> u64 {
        let accounts = self.accounts.read().await;
        accounts.get(address)
            .map(|account| account.nonce)
            .unwrap_or(0)
    }

    pub async fn create_account(&self, address: String) -> Result<(), StateError> {
        let mut accounts = self.accounts.write().await;
        if accounts.contains_key(&address) {
            return Err(StateError::AccountAlreadyExists);
        }

        let account = Account::new(address.clone());
        accounts.insert(address, account);

        Ok(())
    }

    pub async fn set_balance(&self, address: &str, balance: u64) -> Result<(), StateError> {
        let mut accounts = self.accounts.write().await;
        let account = accounts.get_mut(address)
            .ok_or(StateError::AccountNotFound)?;

        account.balance = balance;

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