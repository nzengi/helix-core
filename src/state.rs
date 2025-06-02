
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use crate::consensus::{Block, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
    pub storage: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub best_block_hash: String,
    pub total_difficulty: u64,
    pub peer_count: u32,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Synced,
    Syncing { current: u64, target: u64 },
    NotSynced,
}

#[derive(Debug, Clone)]
pub struct ChainState {
    accounts: Arc<RwLock<HashMap<String, Account>>>,
    blocks: Arc<RwLock<HashMap<String, Block>>>,
    transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    chain_info: Arc<RwLock<ChainInfo>>,
    pending_transactions: Arc<RwLock<Vec<Transaction>>>,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            blocks: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            chain_info: Arc::new(RwLock::new(ChainInfo {
                height: 0,
                best_block_hash: "genesis".to_string(),
                total_difficulty: 0,
                peer_count: 0,
                sync_status: SyncStatus::NotSynced,
            })),
            pending_transactions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn get_account_balance(&self, address: &str) -> Result<u64> {
        let accounts = self.accounts.read().await;
        match accounts.get(address) {
            Some(account) => Ok(account.balance),
            None => Ok(0),
        }
    }

    pub async fn update_account_balance(&self, address: &str, balance: u64) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        
        let account = accounts.entry(address.to_string()).or_insert_with(|| Account {
            address: address.to_string(),
            balance: 0,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
            created_at: Utc::now(),
        });
        
        account.balance = balance;
        Ok(())
    }

    pub async fn transfer(&self, from: &str, to: &str, amount: u64) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        
        // Check sender balance
        let sender = accounts.get_mut(from)
            .ok_or_else(|| anyhow::anyhow!("Sender account not found"))?;
        
        if sender.balance < amount {
            anyhow::bail!("Insufficient balance");
        }
        
        sender.balance -= amount;
        sender.nonce += 1;
        
        // Update receiver
        let receiver = accounts.entry(to.to_string()).or_insert_with(|| Account {
            address: to.to_string(),
            balance: 0,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
            created_at: Utc::now(),
        });
        
        receiver.balance += amount;
        Ok(())
    }

    pub async fn add_block(&self, block: Block) -> Result<()> {
        let mut blocks = self.blocks.write().await;
        let mut chain_info = self.chain_info.write().await;
        
        blocks.insert(block.hash.clone(), block.clone());
        
        if block.height > chain_info.height {
            chain_info.height = block.height;
            chain_info.best_block_hash = block.hash.clone();
        }
        
        Ok(())
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).cloned())
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> Result<()> {
        let mut transactions = self.transactions.write().await;
        transactions.insert(transaction.hash.clone(), transaction);
        Ok(())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>> {
        let transactions = self.transactions.read().await;
        Ok(transactions.get(hash).cloned())
    }

    pub async fn add_pending_transaction(&self, transaction: Transaction) -> Result<()> {
        let mut pending = self.pending_transactions.write().await;
        pending.push(transaction);
        Ok(())
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<Transaction>> {
        let pending = self.pending_transactions.read().await;
        Ok(pending.clone())
    }

    pub async fn clear_pending_transactions(&self) -> Result<()> {
        let mut pending = self.pending_transactions.write().await;
        pending.clear();
        Ok(())
    }

    pub async fn get_status(&self) -> Result<ChainInfo> {
        let chain_info = self.chain_info.read().await;
        Ok(chain_info.clone())
    }

    pub async fn update_sync_status(&self, status: SyncStatus) -> Result<()> {
        let mut chain_info = self.chain_info.write().await;
        chain_info.sync_status = status;
        Ok(())
    }

    pub async fn increment_nonce(&self, address: &str) -> Result<u64> {
        let mut accounts = self.accounts.write().await;
        
        let account = accounts.entry(address.to_string()).or_insert_with(|| Account {
            address: address.to_string(),
            balance: 0,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
            created_at: Utc::now(),
        });
        
        account.nonce += 1;
        Ok(account.nonce)
    }

    pub async fn get_nonce(&self, address: &str) -> Result<u64> {
        let accounts = self.accounts.read().await;
        match accounts.get(address) {
            Some(account) => Ok(account.nonce),
            None => Ok(0),
        }
    }

    pub async fn execute_transactions(&self, transactions: &[Transaction]) -> Result<()> {
        for tx in transactions {
            // Execute transfer
            if tx.amount > 0 {
                self.transfer(&tx.from, &tx.to, tx.amount).await?;
            }
            
            // Add to transaction history
            self.add_transaction(tx.clone()).await?;
        }
        Ok(())
    }

    pub async fn validate_transaction(&self, tx: &Transaction) -> Result<bool> {
        // Check sender exists and has sufficient balance
        let sender_balance = self.get_account_balance(&tx.from).await?;
        if sender_balance < tx.amount {
            return Ok(false);
        }

        // Check nonce
        let current_nonce = self.get_nonce(&tx.from).await?;
        if tx.nonce != current_nonce + 1 {
            return Ok(false);
        }

        // Basic validation passed
        Ok(true)
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
    async fn test_account_operations() {
        let state = ChainState::new();
        
        // Test balance operations
        state.update_account_balance("alice", 1000).await.unwrap();
        let balance = state.get_account_balance("alice").await.unwrap();
        assert_eq!(balance, 1000);
        
        // Test transfer
        state.update_account_balance("bob", 500).await.unwrap();
        state.transfer("alice", "bob", 300).await.unwrap();
        
        let alice_balance = state.get_account_balance("alice").await.unwrap();
        let bob_balance = state.get_account_balance("bob").await.unwrap();
        
        assert_eq!(alice_balance, 700);
        assert_eq!(bob_balance, 800);
    }

    #[tokio::test]
    async fn test_nonce_management() {
        let state = ChainState::new();
        
        let nonce1 = state.increment_nonce("alice").await.unwrap();
        let nonce2 = state.increment_nonce("alice").await.unwrap();
        
        assert_eq!(nonce1, 1);
        assert_eq!(nonce2, 2);
    }
}
