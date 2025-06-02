use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use sha3::{Digest, Keccak256};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub height: u64,
    pub best_block_hash: String,
    pub total_transactions: u64,
    pub validator_count: u64,
}

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
    pub id: String,
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: u64,
    pub amount: u64,
    pub fee: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub signature: String,
    pub timestamp: u64,
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

#[derive(Debug)]
pub struct ChainState {
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    pending_transactions: Arc<Mutex<Vec<Transaction>>>,
    blocks: Arc<Mutex<Vec<Block>>>,
    validator_set: Arc<Mutex<Vec<String>>>,
    current_height: Arc<Mutex<u64>>,
    total_supply: Arc<Mutex<u64>>,
    transaction_count: Arc<Mutex<u64>>,
}

const INITIAL_SUPPLY: u64 = 1_000_000_000;

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            pending_transactions: Arc::new(Mutex::new(Vec::new())),
            blocks: Arc::new(Mutex::new(Vec::new())),
            validator_set: Arc::new(Mutex::new(Vec::new())),
            current_height: Arc::new(Mutex::new(0)),
            total_supply: Arc::new(Mutex::new(INITIAL_SUPPLY)),
            transaction_count: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn get_status(&self) -> Result<ChainStatus, StateError> {
        let height = *self.current_height.lock().await;
        let blocks = self.blocks.lock().await;
        let best_block_hash = blocks.last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        Ok(ChainStatus {
            height,
            best_block_hash,
            total_transactions: 0,
            validator_count: 0,
        })
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>, StateError> {
        let blocks = self.blocks.lock().await;
        Ok(blocks.iter().find(|b| b.hash == hash).cloned())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>, StateError> {
        let pending = self.pending_transactions.lock().await;
        Ok(pending.iter().find(|tx| tx.hash == hash).cloned())
    }

    pub async fn get_account_balance(&self, address: &str) -> Result<u64, StateError> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).map(|acc| acc.balance).unwrap_or(0))
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, StateError> {
        let pending = self.pending_transactions.lock().await;
        Ok(pending.clone())
    }

    pub async fn execute_transactions(&self, transactions: &[Transaction]) -> Result<(), StateError> {
        for tx in transactions {
            // Convert and execute transaction
            tracing::debug!("Executing transaction: {}", tx.hash);
        }
        Ok(())
    }

    pub async fn add_block(&self, block: &Block) -> Result<(), StateError> {
        let mut blocks = self.blocks.lock().await;
        let state_block = Block {
            index: block.index,
            hash: block.hash.clone(),
            previous_hash: block.previous_hash.clone(),
            timestamp: block.timestamp,
            transactions: block.transactions.clone(),
            merkle_root: block.merkle_root.clone(),
            signatures: block.signatures.clone(),
            validator: block.validator.clone(),
        };
        blocks.push(state_block);

        let mut height = self.current_height.lock().await;
        *height = block.index;

        Ok(())
    }


    pub async fn apply_transaction(&self, transaction: &Transaction) -> Result<(), StateError> {
        // Validate transaction first
        if transaction.amount == 0 {
            return Err(StateError::InvalidTransaction("Zero amount transaction".to_string()));
        }

        let mut accounts = self.accounts.lock().await;

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
        let mut tx_count = self.transaction_count.lock().await;
        *tx_count += 1;

        Ok(())
    }

    pub async fn validate_transaction(&self, transaction: &Transaction) -> Result<bool, StateError> {
        let accounts = self.accounts.lock().await;

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
        let mut pool = self.pending_transactions.lock().await;
        pool.push(transaction);
        Ok(())
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

    pub async fn create_account(&self, address: String) -> Result<(), StateError> {
        let mut accounts = self.accounts.lock().await;
        if accounts.contains_key(&address) {
            return Err(StateError::AccountAlreadyExists);
        }

        let account = Account::new(address.clone());
        accounts.insert(address, account);

        Ok(())
    }

    pub async fn set_balance(&self, address: &str, balance: u64) -> Result<(), StateError> {
        let mut accounts = self.accounts.lock().await;
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