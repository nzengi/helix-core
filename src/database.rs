use std::sync::Arc;
use rusqlite::{Connection, Result, types::{FromSql, ToSql, ValueRef}, OptionalExtension};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, NaiveDateTime};

#[derive(Debug, Clone)]
pub struct DbDateTime(pub DateTime<Utc>);

impl FromSql for DbDateTime {
    fn column_result(value: ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let text = value.as_str()?;
        let naive = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S")
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(DbDateTime(DateTime::from_naive_utc_and_offset(naive, Utc)))
    }
}

impl ToSql for DbDateTime {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let text = self.0.format("%Y-%m-%d %H:%M:%S").to_string();
        Ok(text.into())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub id: i64,
    pub from_address: String,
    pub to_address: String,
    pub amount: f64,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub address: String,
    pub balance: f64,
    pub staked_amount: f64,
    pub beta_angle: f64,
    pub efficiency: f64,
    pub last_updated: DateTime<Utc>,
}

pub struct Database {
    db_path: String,
}

impl Database {
    pub async fn new() -> Result<Self> {
        let db_path = "helix.db".to_string();
        let db_path_clone = db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path_clone)?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    status TEXT NOT NULL
                )",
                [],
            )?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS accounts (
                    address TEXT PRIMARY KEY,
                    balance REAL NOT NULL,
                    staked_amount REAL NOT NULL,
                    beta_angle REAL NOT NULL,
                    efficiency REAL NOT NULL,
                    last_updated TEXT NOT NULL
                )",
                [],
            )?;
            Ok::<_, rusqlite::Error>(())
        }).await.unwrap()?;
        Ok(Self { db_path })
    }
    
    pub async fn save_transaction(&self, tx: &Transaction) -> Result<()> {
        let tx = tx.clone();
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute(
                "INSERT INTO transactions (from_address, to_address, amount, timestamp, signature, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    &tx.from_address,
                    &tx.to_address,
                    tx.amount,
                    tx.timestamp.to_rfc3339(),
                    &tx.signature,
                    &tx.status,
                ),
            )?;
            Ok::<_, rusqlite::Error>(())
        }).await.unwrap()?;
        Ok(())
    }
    
    pub async fn get_transaction(&self, signature: &str) -> Result<Option<Transaction>> {
        let signature = signature.to_string();
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT id, from_address, to_address, amount, timestamp, signature, status
                 FROM transactions WHERE signature = ?1",
            )?;
            let tx = stmt.query_row([&signature], |row| {
                Ok(Transaction {
                    id: row.get(0)?,
                    from_address: row.get(1)?,
                    to_address: row.get(2)?,
                    amount: row.get(3)?,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    signature: row.get(5)?,
                    status: row.get(6)?,
                })
            }).optional()?;
            Ok::<_, rusqlite::Error>(tx)
        }).await.unwrap()
    }
    
    pub async fn save_account(&self, account: &Account) -> Result<()> {
        let account = account.clone();
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            conn.execute(
                "INSERT OR REPLACE INTO accounts (address, balance, staked_amount, beta_angle, efficiency, last_updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    &account.address,
                    account.balance,
                    account.staked_amount,
                    account.beta_angle,
                    account.efficiency,
                    account.last_updated.to_rfc3339(),
                ),
            )?;
            Ok::<_, rusqlite::Error>(())
        }).await.unwrap()?;
        Ok(())
    }
    
    pub async fn get_account(&self, address: &str) -> Result<Option<Account>> {
        let address = address.to_string();
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT address, balance, staked_amount, beta_angle, efficiency, last_updated
                 FROM accounts WHERE address = ?1",
            )?;
            let account = stmt.query_row([&address], |row| {
                Ok(Account {
                    address: row.get(0)?,
                    balance: row.get(1)?,
                    staked_amount: row.get(2)?,
                    beta_angle: row.get(3)?,
                    efficiency: row.get(4)?,
                    last_updated: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            }).optional()?;
            Ok::<_, rusqlite::Error>(account)
        }).await.unwrap()
    }

    pub async fn get_all_transactions(&self) -> Result<Vec<Transaction>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT id, from_address, to_address, amount, timestamp, signature, status
                 FROM transactions ORDER BY timestamp DESC"
            )?;
            let transactions = stmt.query_map([], |row| {
                Ok(Transaction {
                    id: row.get(0)?,
                    from_address: row.get(1)?,
                    to_address: row.get(2)?,
                    amount: row.get(3)?,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    signature: row.get(5)?,
                    status: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>>>()?;
            Ok::<_, rusqlite::Error>(transactions)
        }).await.unwrap()
    }

    pub async fn get_all_accounts(&self) -> Result<Vec<Account>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let conn = Connection::open(&db_path)?;
            let mut stmt = conn.prepare(
                "SELECT address, balance, staked_amount, beta_angle, efficiency, last_updated
                 FROM accounts"
            )?;
            let accounts = stmt.query_map([], |row| {
                Ok(Account {
                    address: row.get(0)?,
                    balance: row.get(1)?,
                    staked_amount: row.get(2)?,
                    beta_angle: row.get(3)?,
                    efficiency: row.get(4)?,
                    last_updated: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<Result<Vec<_>>>()?;
            Ok::<_, rusqlite::Error>(accounts)
        }).await.unwrap()
    }
} 