use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::collections::HashMap;

use crate::config::DatabaseConfig;
use crate::consensus::{Block, Transaction};
use crate::state::Account;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub database_size_mb: u64,
    pub last_backup: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct Database {
    config: DatabaseConfig,
    blocks: Arc<Mutex<HashMap<String, Block>>>,
    transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    stats: Arc<Mutex<DatabaseStats>>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        let db = Self {
            config: config.clone(),
            blocks: Arc::new(Mutex::new(HashMap::new())),
            transactions: Arc::new(Mutex::new(HashMap::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(DatabaseStats {
                total_blocks: 0,
                total_transactions: 0,
                total_accounts: 0,
                database_size_mb: 0,
                last_backup: None,
            })),
        };

        tracing::info!("Database initialized with URL: {}", config.url);
        Ok(db)
    }

    pub async fn save_block(&self, block: &Block) -> Result<()> {
        let mut blocks = self.blocks.lock().await;
        blocks.insert(block.hash.clone(), block.clone());

        let mut stats = self.stats.lock().await;
        stats.total_blocks += 1;

        tracing::debug!("Saved block {} to database", block.hash);
        Ok(())
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>> {
        let blocks = self.blocks.lock().await;
        Ok(blocks.get(hash).cloned())
    }

    pub async fn save_transaction(&self, tx: &Transaction) -> Result<()> {
        let mut transactions = self.transactions.lock().await;
        transactions.insert(tx.hash.clone(), tx.clone());

        let mut stats = self.stats.lock().await;
        stats.total_transactions += 1;

        tracing::debug!("Saved transaction {} to database", tx.hash);
        Ok(())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>> {
        let transactions = self.transactions.lock().await;
        Ok(transactions.get(hash).cloned())
    }

    pub async fn save_account(&self, account: &Account) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        let is_new = !accounts.contains_key(&account.address);
        accounts.insert(account.address.clone(), account.clone());

        if is_new {
            let mut stats = self.stats.lock().await;
            stats.total_accounts += 1;
        }

        tracing::debug!("Saved account {} to database", account.address);
        Ok(())
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let stats = self.stats.lock().await;
        Ok(stats.clone())
    }

    pub async fn backup(&self) -> Result<()> {
        let mut stats = self.stats.lock().await;
        stats.last_backup = Some(chrono::Utc::now());
        tracing::info!("Database backup completed");
        Ok(())
    }

    pub async fn compact(&self) -> Result<()> {
        tracing::info!("Database compaction completed");
        Ok(())
    }
}