
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::collections::HashMap;
use tokio::time::{timeout, Duration};

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
    pub connection_count: u32,
    pub query_count: u64,
    pub avg_query_time_ms: f64,
}

#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub order_by: Option<String>,
    pub ascending: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            limit: None,
            offset: None,
            order_by: None,
            ascending: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Index {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    pub data: HashMap<String, Vec<String>>,
}

impl Index {
    pub fn new(name: String, fields: Vec<String>, unique: bool) -> Self {
        Self {
            name,
            fields,
            unique,
            data: HashMap::new(),
        }
    }
}

pub struct Database {
    config: DatabaseConfig,
    blocks: Arc<Mutex<HashMap<String, Block>>>,
    transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    stats: Arc<Mutex<DatabaseStats>>,
    connection_pool: Arc<Mutex<Vec<DatabaseConnection>>>,
    indices: Arc<Mutex<HashMap<String, Index>>>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[derive(Debug, Clone)]
pub struct DatabaseConnection {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: chrono::DateTime<chrono::Utc>,
    pub in_use: bool,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub access_count: u64,
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
                connection_count: 0,
                query_count: 0,
                avg_query_time_ms: 0.0,
            })),
            connection_pool: Arc::new(Mutex::new(Vec::new())),
            indices: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };

        // Initialize connection pool
        db.initialize_connection_pool().await?;
        
        // Create default indices
        db.create_default_indices().await?;

        tracing::info!("Database initialized with URL: {}", config.url);
        Ok(db)
    }

    async fn initialize_connection_pool(&self) -> Result<()> {
        let mut pool = self.connection_pool.lock().await;
        for i in 0..self.config.max_connections {
            let connection = DatabaseConnection {
                id: format!("conn_{}", i),
                created_at: chrono::Utc::now(),
                last_used: chrono::Utc::now(),
                in_use: false,
            };
            pool.push(connection);
        }
        Ok(())
    }

    async fn create_default_indices(&self) -> Result<()> {
        let mut indices = self.indices.lock().await;
        
        // Block indices
        indices.insert("blocks_by_height".to_string(), Index::new(
            "blocks_by_height".to_string(),
            vec!["height".to_string()],
            true,
        ));
        
        // Transaction indices
        indices.insert("transactions_by_sender".to_string(), Index::new(
            "transactions_by_sender".to_string(),
            vec!["sender".to_string()],
            false,
        ));
        
        indices.insert("transactions_by_receiver".to_string(), Index::new(
            "transactions_by_receiver".to_string(),
            vec!["receiver".to_string()],
            false,
        ));

        // Account indices
        indices.insert("accounts_by_balance".to_string(), Index::new(
            "accounts_by_balance".to_string(),
            vec!["balance".to_string()],
            false,
        ));

        Ok(())
    }

    pub async fn get_connection(&self) -> Result<DatabaseConnection> {
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        
        timeout(timeout_duration, async {
            loop {
                let mut pool = self.connection_pool.lock().await;
                if let Some(conn) = pool.iter_mut().find(|c| !c.in_use) {
                    conn.in_use = true;
                    conn.last_used = chrono::Utc::now();
                    return Ok(conn.clone());
                }
                drop(pool);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await?
    }

    pub async fn release_connection(&self, connection_id: &str) -> Result<()> {
        let mut pool = self.connection_pool.lock().await;
        if let Some(conn) = pool.iter_mut().find(|c| c.id == connection_id) {
            conn.in_use = false;
        }
        Ok(())
    }

    // Block operations
    pub async fn save_block(&self, block: &Block) -> Result<()> {
        let _conn = self.get_connection().await?;
        
        let mut blocks = self.blocks.lock().await;
        blocks.insert(block.hash.clone(), block.clone());

        // Update indices
        self.update_block_indices(block).await?;

        let mut stats = self.stats.lock().await;
        stats.total_blocks += 1;
        stats.query_count += 1;

        tracing::debug!("Saved block {} to database", block.hash);
        Ok(())
    }

    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>> {
        let _conn = self.get_connection().await?;
        
        // Try cache first
        if let Some(cached) = self.get_from_cache(&format!("block:{}", hash)).await? {
            if let Ok(block) = bincode::deserialize::<Block>(&cached) {
                return Ok(Some(block));
            }
        }

        let blocks = self.blocks.lock().await;
        let block = blocks.get(hash).cloned();
        
        // Cache the result
        if let Some(ref block) = block {
            if let Ok(serialized) = bincode::serialize(block) {
                self.store_in_cache(&format!("block:{}", hash), serialized, 3600).await?;
            }
        }

        let mut stats = self.stats.lock().await;
        stats.query_count += 1;

        Ok(block)
    }

    pub async fn get_blocks_by_height_range(&self, start_height: u64, end_height: u64) -> Result<Vec<Block>> {
        let _conn = self.get_connection().await?;
        
        let blocks = self.blocks.lock().await;
        let mut result = Vec::new();
        
        for block in blocks.values() {
            if block.index >= start_height && block.index <= end_height {
                result.push(block.clone());
            }
        }
        
        // Sort by height
        result.sort_by(|a, b| a.index.cmp(&b.index));
        
        Ok(result)
    }

    pub async fn get_latest_blocks(&self, count: usize) -> Result<Vec<Block>> {
        let _conn = self.get_connection().await?;
        
        let blocks = self.blocks.lock().await;
        let mut result: Vec<Block> = blocks.values().cloned().collect();
        
        // Sort by height in descending order
        result.sort_by(|a, b| b.index.cmp(&a.index));
        result.truncate(count);
        
        Ok(result)
    }

    // Transaction operations
    pub async fn save_transaction(&self, tx: &Transaction) -> Result<()> {
        let _conn = self.get_connection().await?;
        
        let mut transactions = self.transactions.lock().await;
        transactions.insert(tx.hash.clone(), tx.clone());

        // Update indices
        self.update_transaction_indices(tx).await?;

        let mut stats = self.stats.lock().await;
        stats.total_transactions += 1;
        stats.query_count += 1;

        tracing::debug!("Saved transaction {} to database", tx.hash);
        Ok(())
    }

    pub async fn get_transaction(&self, hash: &str) -> Result<Option<Transaction>> {
        let _conn = self.get_connection().await?;
        
        let transactions = self.transactions.lock().await;
        let tx = transactions.get(hash).cloned();
        
        let mut stats = self.stats.lock().await;
        stats.query_count += 1;
        
        Ok(tx)
    }

    pub async fn get_transactions_by_sender(&self, sender: &str, options: QueryOptions) -> Result<Vec<Transaction>> {
        let _conn = self.get_connection().await?;
        
        let transactions = self.transactions.lock().await;
        let mut result = Vec::new();
        
        for tx in transactions.values() {
            if tx.sender == sender {
                result.push(tx.clone());
            }
        }

        self.apply_query_options(&mut result, options);
        Ok(result)
    }

    pub async fn get_transactions_by_receiver(&self, receiver: &str, options: QueryOptions) -> Result<Vec<Transaction>> {
        let _conn = self.get_connection().await?;
        
        let transactions = self.transactions.lock().await;
        let mut result = Vec::new();
        
        for tx in transactions.values() {
            if tx.receiver == receiver {
                result.push(tx.clone());
            }
        }

        self.apply_query_options(&mut result, options);
        Ok(result)
    }

    // Account operations
    pub async fn save_account(&self, account: &Account) -> Result<()> {
        let _conn = self.get_connection().await?;
        
        let mut accounts = self.accounts.lock().await;
        let is_new = !accounts.contains_key(&account.address);
        accounts.insert(account.address.clone(), account.clone());

        // Update indices
        self.update_account_indices(account).await?;

        if is_new {
            let mut stats = self.stats.lock().await;
            stats.total_accounts += 1;
        }

        let mut stats = self.stats.lock().await;
        stats.query_count += 1;

        tracing::debug!("Saved account {} to database", account.address);
        Ok(())
    }

    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let _conn = self.get_connection().await?;
        
        let accounts = self.accounts.lock().await;
        let account = accounts.get(address).cloned();
        
        let mut stats = self.stats.lock().await;
        stats.query_count += 1;
        
        Ok(account)
    }

    pub async fn get_accounts_by_balance_range(&self, min_balance: u64, max_balance: u64) -> Result<Vec<Account>> {
        let _conn = self.get_connection().await?;
        
        let accounts = self.accounts.lock().await;
        let mut result = Vec::new();
        
        for account in accounts.values() {
            if account.balance >= min_balance && account.balance <= max_balance {
                result.push(account.clone());
            }
        }
        
        Ok(result)
    }

    // Batch operations
    pub async fn save_blocks_batch(&self, blocks: &[Block]) -> Result<()> {
        let _conn = self.get_connection().await?;
        
        let mut block_storage = self.blocks.lock().await;
        for block in blocks {
            block_storage.insert(block.hash.clone(), block.clone());
            self.update_block_indices(block).await?;
        }

        let mut stats = self.stats.lock().await;
        stats.total_blocks += blocks.len() as u64;
        stats.query_count += 1;

        tracing::debug!("Saved {} blocks in batch", blocks.len());
        Ok(())
    }

    pub async fn save_transactions_batch(&self, transactions: &[Transaction]) -> Result<()> {
        let _conn = self.get_connection().await?;
        
        let mut tx_storage = self.transactions.lock().await;
        for tx in transactions {
            tx_storage.insert(tx.hash.clone(), tx.clone());
            self.update_transaction_indices(tx).await?;
        }

        let mut stats = self.stats.lock().await;
        stats.total_transactions += transactions.len() as u64;
        stats.query_count += 1;

        tracing::debug!("Saved {} transactions in batch", transactions.len());
        Ok(())
    }

    // Index management
    async fn update_block_indices(&self, block: &Block) -> Result<()> {
        let mut indices = self.indices.lock().await;
        
        if let Some(index) = indices.get_mut("blocks_by_height") {
            index.data.insert(block.index.to_string(), vec![block.hash.clone()]);
        }
        
        Ok(())
    }

    async fn update_transaction_indices(&self, tx: &Transaction) -> Result<()> {
        let mut indices = self.indices.lock().await;
        
        // Update sender index
        if let Some(index) = indices.get_mut("transactions_by_sender") {
            index.data.entry(tx.sender.clone())
                .or_insert_with(Vec::new)
                .push(tx.hash.clone());
        }
        
        // Update receiver index
        if let Some(index) = indices.get_mut("transactions_by_receiver") {
            index.data.entry(tx.receiver.clone())
                .or_insert_with(Vec::new)
                .push(tx.hash.clone());
        }
        
        Ok(())
    }

    async fn update_account_indices(&self, account: &Account) -> Result<()> {
        let mut indices = self.indices.lock().await;
        
        if let Some(index) = indices.get_mut("accounts_by_balance") {
            index.data.entry(account.balance.to_string())
                .or_insert_with(Vec::new)
                .push(account.address.clone());
        }
        
        Ok(())
    }

    // Cache operations
    async fn store_in_cache(&self, key: &str, data: Vec<u8>, ttl_seconds: i64) -> Result<()> {
        let mut cache = self.cache.lock().await;
        let entry = CacheEntry {
            data,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds),
            access_count: 0,
        };
        cache.insert(key.to_string(), entry);
        Ok(())
    }

    async fn get_from_cache(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut cache = self.cache.lock().await;
        
        if let Some(entry) = cache.get_mut(key) {
            if chrono::Utc::now() < entry.expires_at {
                entry.access_count += 1;
                return Ok(Some(entry.data.clone()));
            } else {
                cache.remove(key);
            }
        }
        
        Ok(None)
    }

    pub async fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.lock().await;
        cache.clear();
        tracing::info!("Cache cleared");
        Ok(())
    }

    // Helper methods
    fn apply_query_options<T>(&self, data: &mut Vec<T>, options: QueryOptions) 
    where 
        T: Clone,
    {
        if let Some(offset) = options.offset {
            if offset < data.len() {
                data.drain(0..offset);
            } else {
                data.clear();
                return;
            }
        }

        if let Some(limit) = options.limit {
            data.truncate(limit);
        }
    }

    // Statistics and monitoring
    pub async fn get_stats(&self) -> Result<DatabaseStats> {
        let mut stats = self.stats.lock().await;
        
        // Update database size estimation
        let blocks = self.blocks.lock().await;
        let transactions = self.transactions.lock().await;
        let accounts = self.accounts.lock().await;
        
        let estimated_size = (blocks.len() + transactions.len() + accounts.len()) * 1024; // Rough estimation
        stats.database_size_mb = (estimated_size / (1024 * 1024)) as u64;
        
        // Update connection count
        let pool = self.connection_pool.lock().await;
        stats.connection_count = pool.iter().filter(|c| c.in_use).count() as u32;
        
        Ok(stats.clone())
    }

    pub async fn get_health_status(&self) -> Result<HashMap<String, String>> {
        let mut status = HashMap::new();
        
        let stats = self.get_stats().await?;
        status.insert("status".to_string(), "healthy".to_string());
        status.insert("total_blocks".to_string(), stats.total_blocks.to_string());
        status.insert("total_transactions".to_string(), stats.total_transactions.to_string());
        status.insert("total_accounts".to_string(), stats.total_accounts.to_string());
        status.insert("connection_count".to_string(), stats.connection_count.to_string());
        status.insert("query_count".to_string(), stats.query_count.to_string());
        
        Ok(status)
    }

    // Maintenance operations
    pub async fn backup(&self) -> Result<String> {
        let backup_id = format!("backup_{}", chrono::Utc::now().timestamp());
        
        // Simulate backup process
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let mut stats = self.stats.lock().await;
        stats.last_backup = Some(chrono::Utc::now());
        
        tracing::info!("Database backup completed: {}", backup_id);
        Ok(backup_id)
    }

    pub async fn compact(&self) -> Result<()> {
        // Clean expired cache entries
        let mut cache = self.cache.lock().await;
        let now = chrono::Utc::now();
        cache.retain(|_, entry| now < entry.expires_at);
        
        tracing::info!("Database compaction completed");
        Ok(())
    }

    pub async fn optimize(&self) -> Result<()> {
        // Rebuild indices
        self.rebuild_indices().await?;
        
        // Compact data
        self.compact().await?;
        
        tracing::info!("Database optimization completed");
        Ok(())
    }

    async fn rebuild_indices(&self) -> Result<()> {
        let mut indices = self.indices.lock().await;
        
        // Clear all indices
        for index in indices.values_mut() {
            index.data.clear();
        }
        
        // Rebuild block indices
        let blocks = self.blocks.lock().await;
        for block in blocks.values() {
            if let Some(index) = indices.get_mut("blocks_by_height") {
                index.data.insert(block.height.to_string(), vec![block.hash.clone()]);
            }
        }
        
        // Rebuild transaction indices
        let transactions = self.transactions.lock().await;
        for tx in transactions.values() {
            if let Some(index) = indices.get_mut("transactions_by_sender") {
                index.data.entry(tx.from.clone())
                    .or_insert_with(Vec::new)
                    .push(tx.hash.clone());
            }
            
            if let Some(index) = indices.get_mut("transactions_by_receiver") {
                index.data.entry(tx.to.clone())
                    .or_insert_with(Vec::new)
                    .push(tx.hash.clone());
            }
        }
        
        // Rebuild account indices
        let accounts = self.accounts.lock().await;
        for account in accounts.values() {
            if let Some(index) = indices.get_mut("accounts_by_balance") {
                index.data.entry(account.balance.to_string())
                    .or_insert_with(Vec::new)
                    .push(account.address.clone());
            }
        }
        
        tracing::info!("Database indices rebuilt");
        Ok(())
    }

    // Cleanup operations
    pub async fn cleanup_old_data(&self, max_age_days: i64) -> Result<u64> {
        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(max_age_days);
        let mut cleaned_count = 0u64;
        
        // Clean old blocks (if they have timestamp)
        let mut blocks = self.blocks.lock().await;
        let block_count_before = blocks.len();
        blocks.retain(|_, block| {
            chrono::DateTime::from_timestamp(block.timestamp as i64, 0)
                .map(|dt| dt > cutoff_date)
                .unwrap_or(true)
        });
        cleaned_count += (block_count_before - blocks.len()) as u64;
        
        // Clean old transactions
        let mut transactions = self.transactions.lock().await;
        let tx_count_before = transactions.len();
        transactions.retain(|_, tx| {
            chrono::DateTime::from_timestamp(tx.timestamp as i64, 0)
                .map(|dt| dt > cutoff_date)
                .unwrap_or(true)
        });
        cleaned_count += (tx_count_before - transactions.len()) as u64;
        
        if cleaned_count > 0 {
            // Rebuild indices after cleanup
            drop(blocks);
            drop(transactions);
            self.rebuild_indices().await?;
        }
        
        tracing::info!("Cleaned up {} old records", cleaned_count);
        Ok(cleaned_count)
    }

    // Transaction management
    pub async fn begin_transaction(&self) -> Result<String> {
        let tx_id = format!("tx_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        tracing::debug!("Started database transaction: {}", tx_id);
        Ok(tx_id)
    }

    pub async fn commit_transaction(&self, _tx_id: &str) -> Result<()> {
        tracing::debug!("Committed database transaction: {}", _tx_id);
        Ok(())
    }

    pub async fn rollback_transaction(&self, _tx_id: &str) -> Result<()> {
        tracing::debug!("Rolled back database transaction: {}", _tx_id);
        Ok(())
    }

    // Export/Import operations
    pub async fn export_data(&self) -> Result<Vec<u8>> {
        let blocks = self.blocks.lock().await;
        let transactions = self.transactions.lock().await;
        let accounts = self.accounts.lock().await;
        
        let export_data = serde_json::json!({
            "blocks": *blocks,
            "transactions": *transactions,
            "accounts": *accounts,
            "exported_at": chrono::Utc::now()
        });
        
        let serialized = serde_json::to_vec(&export_data)?;
        tracing::info!("Exported database data ({} bytes)", serialized.len());
        Ok(serialized)
    }

    pub async fn import_data(&self, data: &[u8]) -> Result<()> {
        let import_data: serde_json::Value = serde_json::from_slice(data)?;
        
        if let Some(blocks_obj) = import_data.get("blocks") {
            let blocks: HashMap<String, Block> = serde_json::from_value(blocks_obj.clone())?;
            let mut db_blocks = self.blocks.lock().await;
            db_blocks.extend(blocks);
        }
        
        if let Some(transactions_obj) = import_data.get("transactions") {
            let transactions: HashMap<String, Transaction> = serde_json::from_value(transactions_obj.clone())?;
            let mut db_transactions = self.transactions.lock().await;
            db_transactions.extend(transactions);
        }
        
        if let Some(accounts_obj) = import_data.get("accounts") {
            let accounts: HashMap<String, Account> = serde_json::from_value(accounts_obj.clone())?;
            let mut db_accounts = self.accounts.lock().await;
            db_accounts.extend(accounts);
        }
        
        // Rebuild indices after import
        self.rebuild_indices().await?;
        
        tracing::info!("Imported database data");
        Ok(())
    }
}

// Error handling
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Query failed: {0}")]
    QueryFailed(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Index error: {0}")]
    IndexError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Block, Transaction};
    use crate::state::Account;
    use crate::config::DatabaseConfig;

    fn create_test_config() -> DatabaseConfig {
        DatabaseConfig {
            url: "memory://test".to_string(),
            max_connections: 5,
            timeout_seconds: 10,
        }
    }

    #[tokio::test]
    async fn test_database_initialization() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let stats = db.get_stats().await.unwrap();
        assert_eq!(stats.total_blocks, 0);
        assert_eq!(stats.total_transactions, 0);
        assert_eq!(stats.total_accounts, 0);
    }

    #[tokio::test]
    async fn test_block_operations() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let block = Block {
            index: 1,
            hash: "test_hash".to_string(),
            previous_hash: "prev_hash".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            merkle_root: "merkle_root".to_string(),
            transactions: vec![],
            nonce: 0,
            difficulty: 1,
            validator: "test_validator".to_string(),
            size: 1024,
            gas_used: 0,
            gas_limit: 1000000,
        };
        
        db.save_block(&block).await.unwrap();
        let retrieved = db.get_block("test_hash").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, "test_hash");
    }

    #[tokio::test]
    async fn test_transaction_operations() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let tx = Transaction {
            hash: "tx_hash".to_string(),
            sender: "sender".to_string(),
            receiver: "receiver".to_string(),
            amount: 100,
            gas_price: 1,
            gas_limit: 21000,
            nonce: 1,
            signature: "signature".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            data: vec![],
            block_hash: Some("block_hash".to_string()),
            block_number: Some(1),
            transaction_index: Some(0),
            status: "success".to_string(),
        };
        
        db.save_transaction(&tx).await.unwrap();
        let retrieved = db.get_transaction("tx_hash").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash, "tx_hash");
    }

    #[tokio::test]
    async fn test_account_operations() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let account = Account::new("test_address".to_string());
        
        db.save_account(&account).await.unwrap();
        let retrieved = db.get_account("test_address").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().address, "test_address");
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let blocks = vec![
            Block {
                index: 1,
                hash: "hash1".to_string(),
                previous_hash: "prev1".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                merkle_root: "merkle1".to_string(),
                transactions: vec![],
                nonce: 0,
                difficulty: 1,
                validator: "validator1".to_string(),
                size: 1024,
                gas_used: 0,
                gas_limit: 1000000,
            },
            Block {
                index: 2,
                hash: "hash2".to_string(),
                previous_hash: "prev2".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                merkle_root: "merkle2".to_string(),
                transactions: vec![],
                nonce: 0,
                difficulty: 1,
                validator: "validator2".to_string(),
                size: 1024,
                gas_used: 0,
                gas_limit: 1000000,
            },
        ];
        
        db.save_blocks_batch(&blocks).await.unwrap();
        
        let stats = db.get_stats().await.unwrap();
        assert_eq!(stats.total_blocks, 2);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let data = b"test data".to_vec();
        db.store_in_cache("test_key", data.clone(), 3600).await.unwrap();
        
        let retrieved = db.get_from_cache("test_key").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
    }

    #[tokio::test]
    async fn test_connection_pool() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        let conn1 = db.get_connection().await.unwrap();
        let conn2 = db.get_connection().await.unwrap();
        
        assert_ne!(conn1.id, conn2.id);
        
        db.release_connection(&conn1.id).await.unwrap();
        db.release_connection(&conn2.id).await.unwrap();
    }

    #[tokio::test]
    async fn test_query_options() {
        let config = create_test_config();
        let db = Database::new(&config).await.unwrap();
        
        // Add test transactions
        for i in 0..10 {
            let tx = Transaction {
                hash: format!("tx_hash_{}", i),
                sender: "test_sender".to_string(),
                receiver: "test_receiver".to_string(),
                amount: i * 10,
                gas_price: 1,
                gas_limit: 21000,
                nonce: i,
                signature: "signature".to_string(),
                timestamp: chrono::Utc::now().timestamp() as u64,
                data: vec![],
                block_hash: Some("block_hash".to_string()),
                block_number: Some(1),
                transaction_index: Some(i as u32),
                status: "success".to_string(),
            };
            db.save_transaction(&tx).await.unwrap();
        }
        
        let options = QueryOptions {
            limit: Some(5),
            offset: Some(2),
            order_by: None,
            ascending: true,
        };
        
        let txs = db.get_transactions_by_sender("test_sender", options).await.unwrap();
        assert!(txs.len() <= 5);
    }
}
