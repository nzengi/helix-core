use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use rusqlite::{Connection, params};
use crate::consensus::{Block, Transaction};
use crate::sharding::ShardId;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    #[serde(skip)]
    pub db: Arc<Mutex<Connection>>,
    pub accounts: Arc<Mutex<HashMap<String, Account>>>,
    pub shard_states: Arc<Mutex<HashMap<ShardId, ShardState>>>,
    pub last_block: Arc<Mutex<Option<Block>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: f64,
    pub nonce: u64,
    pub shard_id: ShardId,
    pub storage_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardState {
    pub shard_id: ShardId,
    pub last_block: Option<Block>,
    pub accounts: HashMap<String, Account>,
    pub storage: HashMap<String, Vec<u8>>,
}

impl State {
    pub fn new() -> Result<Self, String> {
        let db = Connection::open("helix.db")
            .map_err(|e| e.to_string())?;
        
        // Veritabanı tablolarını oluştur
        db.execute(
            "CREATE TABLE IF NOT EXISTS accounts (
                address TEXT PRIMARY KEY,
                balance REAL NOT NULL,
                nonce INTEGER NOT NULL,
                shard_id INTEGER NOT NULL,
                storage_root TEXT NOT NULL
            )",
            [],
        ).map_err(|e| e.to_string())?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT PRIMARY KEY,
                parent_hash TEXT NOT NULL,
                number INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                transactions TEXT NOT NULL,
                state_root TEXT NOT NULL
            )",
            [],
        ).map_err(|e| e.to_string())?;

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            shard_states: Arc::new(Mutex::new(HashMap::new())),
            last_block: Arc::new(Mutex::new(None)),
        })
    }

    // Account işlemleri
    pub async fn get_account(&self, address: &str) -> Result<Option<Account>, String> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn update_account(&self, account: Account) -> Result<(), String> {
        let mut accounts = self.accounts.lock().await;
        accounts.insert(account.address.clone(), account.clone());

        // Veritabanına kaydet
        let db = self.db.lock().await;
        db.execute(
            "INSERT OR REPLACE INTO accounts (address, balance, nonce, shard_id, storage_root)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account.address,
                account.balance,
                account.nonce,
                account.shard_id,
                account.storage_root
            ],
        ).map_err(|e| e.to_string())?;

        Ok(())
    }

    // Block işlemleri
    pub async fn get_block(&self, hash: &str) -> Result<Option<Block>, String> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT hash, parent_hash, number, timestamp, transactions, state_root
             FROM blocks WHERE hash = ?1"
        ).map_err(|e| e.to_string())?;

        let block = stmt.query_row(params![hash], |row| {
            Ok(Block {
                hash: row.get(0)?,
                parent_hash: row.get(1)?,
                number: row.get(2)?,
                timestamp: row.get(3)?,
                transactions: serde_json::from_str(&row.get::<_, String>(4)?).unwrap(),
                state_root: row.get(5)?,
            })
        }).optional().map_err(|e| e.to_string())?;

        Ok(block)
    }

    pub async fn save_block(&self, block: Block) -> Result<(), String> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO blocks (hash, parent_hash, number, timestamp, transactions, state_root)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                block.hash,
                block.parent_hash,
                block.number,
                block.timestamp,
                serde_json::to_string(&block.transactions).unwrap(),
                block.state_root
            ],
        ).map_err(|e| e.to_string())?;

        // Son bloğu güncelle
        let mut last_block = self.last_block.lock().await;
        *last_block = Some(block);

        Ok(())
    }

    // Shard işlemleri
    pub async fn get_shard_state(&self, shard_id: ShardId) -> Result<Option<ShardState>, String> {
        let shard_states = self.shard_states.lock().await;
        Ok(shard_states.get(&shard_id).cloned())
    }

    pub async fn update_shard_state(&self, state: ShardState) -> Result<(), String> {
        let mut shard_states = self.shard_states.lock().await;
        shard_states.insert(state.shard_id, state);
        Ok(())
    }

    // State senkronizasyonu
    pub async fn sync_state(&self, other_state: &State) -> Result<(), String> {
        // Account senkronizasyonu
        let other_accounts = other_state.accounts.lock().await;
        let mut accounts = self.accounts.lock().await;
        
        for (address, account) in other_accounts.iter() {
            accounts.insert(address.clone(), account.clone());
        }

        // Block senkronizasyonu
        if let Some(block) = other_state.last_block.lock().await.as_ref() {
            self.save_block(block.clone()).await?;
        }

        // Shard senkronizasyonu
        let other_shards = other_state.shard_states.lock().await;
        let mut shards = self.shard_states.lock().await;
        
        for (shard_id, state) in other_shards.iter() {
            shards.insert(*shard_id, state.clone());
        }

        Ok(())
    }

    // Storage işlemleri
    pub async fn get_storage(&self, shard_id: ShardId, key: &str) -> Result<Option<Vec<u8>>, String> {
        let shard_states = self.shard_states.lock().await;
        if let Some(state) = shard_states.get(&shard_id) {
            Ok(state.storage.get(key).cloned())
        } else {
            Ok(None)
        }
    }

    pub async fn set_storage(&self, shard_id: ShardId, key: String, value: Vec<u8>) -> Result<(), String> {
        let mut shard_states = self.shard_states.lock().await;
        if let Some(state) = shard_states.get_mut(&shard_id) {
            state.storage.insert(key, value);
        }
        Ok(())
    }
}

// State hata yönetimi
#[derive(Debug)]
pub enum StateError {
    DatabaseError(String),
    AccountNotFound,
    InvalidBlock,
    ShardNotFound,
    StorageError,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::DatabaseError(e) => write!(f, "Database error: {}", e),
            StateError::AccountNotFound => write!(f, "Account not found"),
            StateError::InvalidBlock => write!(f, "Invalid block"),
            StateError::ShardNotFound => write!(f, "Shard not found"),
            StateError::StorageError => write!(f, "Storage error"),
        }
    }
}

impl std::error::Error for StateError {} 