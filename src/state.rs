
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::database::Database;
use crate::consensus::{Block, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub staked_amount: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    pub current_height: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub total_supply: u64,
    pub last_block_time: DateTime<Utc>,
}

pub struct ChainState {
    accounts: Arc<RwLock<HashMap<String, Account>>>,
    blocks: Arc<RwLock<HashMap<String, Block>>>,
    transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    database: Arc<Database>,
    current_height: Arc<RwLock<u64>>,
}

impl ChainState {
    pub async fn new(database: Arc<Database>) -> Result<Self> {
        let state = Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            blocks: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            database,
            current_height: Arc::new(RwLock::new(0)),
        };

        // Load state from database
        state.load_from_database().await?;
        
        Ok(state)
    }

    pub async fn get_account_balance(&self, address: &str) -> Result<u64> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(address).map(|acc| acc.balance).unwrap_or(0))
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn update_account_balance(&self, address: &str, new_balance: u64) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        
        match accounts.get_mut(address) {
            Some(account) => {
                account.balance = new_balance;
                account.updated_at = Utc::now();
            }
            None => {
                let account = Account {
                    address: address.to_string(),
                    balance: new_balance,
                    nonce: 0,
                    staked_amount: 0,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                accounts.insert(address.to_string(), account);
            }
        }

        // Persist to database
        self.save_account_to_database(address).await?;
        
        Ok(())
    }

    pub async fn transfer(&self, from: &str, to: &str, amount: u64) -> Result<()> {
        if amount == 0 {
            anyhow::bail!("Transfer amount must be greater than 0");
        }

        let mut accounts = self.accounts.write().await;
        
        // Check sender balance
        let sender = accounts.get(from).ok_or_else(|| anyhow::anyhow!("Sender account not found"))?;
        if sender.balance < amount {
            anyhow::bail!("Insufficient balance");
        }

        // Update sender
        let mut sender = sender.clone();
        sender.balance -= amount;
        sender.updated_at = Utc::now();
        accounts.insert(from.to_string(), sender);

        // Update receiver
        match accounts.get_mut(to) {
            Some(receiver) => {
                receiver.balance += amount;
                receiver.updated_at = Utc::now();
            }
            None => {
                let receiver = Account {
                    address: to.to_string(),
                    balance: amount,
                    nonce: 0,
                    staked_amount: 0,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                accounts.insert(to.to_string(), receiver);
            }
        }

        // Persist changes
        drop(accounts);
        self.save_account_to_database(from).await?;
        self.save_account_to_database(to).await?;

        Ok(())
    }

    pub async fn add_block(&self, block: Block) -> Result<()> {
        // Process all transactions in the block
        for tx in &block.transactions {
            self.process_transaction(tx).await?;
        }

        // Store block
        let mut blocks = self.blocks.write().await;
        blocks.insert(block.hash.clone(), block.clone());

        // Update current height
        let mut height = self.current_height.write().await;
        *height = block.height;

        // Persist to database
        self.save_block_to_database(&block).await?;

        Ok(())
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).cloned())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>> {
        let transactions = self.transactions.read().await;
        Ok(transactions.get(hash).cloned())
    }

    pub async fn get_status(&self) -> Result<ChainStatus> {
        let height = *self.current_height.read().await;
        let accounts = self.accounts.read().await;
        let transactions = self.transactions.read().await;
        
        let total_supply = accounts.values().map(|acc| acc.balance).sum();
        let last_block_time = Utc::now(); // TODO: Get from last block

        Ok(ChainStatus {
            current_height: height,
            total_transactions: transactions.len() as u64,
            total_accounts: accounts.len() as u64,
            total_supply,
            last_block_time,
        })
    }

    async fn process_transaction(&self, tx: &Transaction) -> Result<()> {
        // Transfer funds
        self.transfer(&tx.from, &tx.to, tx.amount).await?;

        // Update nonce
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.get_mut(&tx.from) {
            account.nonce += 1;
        }

        // Store transaction
        drop(accounts);
        let mut transactions = self.transactions.write().await;
        transactions.insert(tx.hash.clone(), tx.clone());

        // Persist transaction
        self.save_transaction_to_database(tx).await?;

        Ok(())
    }

    async fn load_from_database(&self) -> Result<()> {
        // TODO: Implement database loading
        tracing::info!("Loading state from database...");
        Ok(())
    }

    async fn save_account_to_database(&self, address: &str) -> Result<()> {
        // TODO: Implement database persistence
        tracing::debug!("Saving account {} to database", address);
        Ok(())
    }

    async fn save_block_to_database(&self, block: &Block) -> Result<()> {
        // TODO: Implement database persistence  
        tracing::debug!("Saving block {} to database", block.hash);
        Ok(())
    }

    async fn save_transaction_to_database(&self, tx: &Transaction) -> Result<()> {
        // TODO: Implement database persistence
        tracing::debug!("Saving transaction {} to database", tx.hash);
        Ok(())
    }
}

impl Account {
    pub fn new() -> Self {
        Self {
            address: String::new(),
            balance: 0,
            nonce: 0,
            staked_amount: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn calculate_torque(&self) -> f64 {
        // Simplified torque calculation based on stake
        self.staked_amount as f64 * 0.1
    }
}
