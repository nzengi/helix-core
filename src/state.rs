
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub code: Option<Vec<u8>>, // Smart contract code
    pub storage: HashMap<String, String>,
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

pub struct ChainState {
    accounts: Arc<RwLock<HashMap<String, Account>>>,
    transaction_pool: Arc<RwLock<Vec<Transaction>>>,
    blocks: Arc<RwLock<Vec<Block>>>,
    current_block_height: Arc<RwLock<u64>>,
    total_supply: Arc<RwLock<u64>>,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            transaction_pool: Arc::new(RwLock::new(Vec::new())),
            blocks: Arc::new(RwLock::new(Vec::new())),
            current_block_height: Arc::new(RwLock::new(0)),
            total_supply: Arc::new(RwLock::new(1_000_000_000)), // 1B initial supply
        }
    }

    pub async fn get_account(&self, address: &str) -> Option<Account> {
        let accounts = self.accounts.read().await;
        accounts.get(address).cloned()
    }

    pub async fn create_account(&self, address: String, initial_balance: u64) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        
        if accounts.contains_key(&address) {
            return Err("Account already exists".to_string());
        }
        
        let account = Account {
            address: address.clone(),
            balance: initial_balance,
            nonce: 0,
            code: None,
            storage: HashMap::new(),
        };
        
        accounts.insert(address, account);
        Ok(())
    }

    pub async fn transfer(&self, from: &str, to: &str, amount: u64) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        
        // From account kontrolü
        let mut from_account = accounts.get(from)
            .ok_or("From account not found")?
            .clone();
        
        if from_account.balance < amount {
            return Err("Insufficient balance".to_string());
        }
        
        // To account kontrolü veya oluşturma
        let mut to_account = accounts.get(to).cloned()
            .unwrap_or_else(|| Account {
                address: to.to_string(),
                balance: 0,
                nonce: 0,
                code: None,
                storage: HashMap::new(),
            });
        
        // Transfer işlemi
        from_account.balance -= amount;
        to_account.balance += amount;
        from_account.nonce += 1;
        
        // Hesapları güncelle
        accounts.insert(from.to_string(), from_account);
        accounts.insert(to.to_string(), to_account);
        
        Ok(())
    }

    pub async fn add_transaction(&self, transaction: Transaction) -> Result<(), String> {
        // Transaction doğrulaması
        self.validate_transaction(&transaction).await?;
        
        let mut pool = self.transaction_pool.write().await;
        pool.push(transaction);
        Ok(())
    }

    pub async fn validate_transaction(&self, tx: &Transaction) -> Result<(), String> {
        let accounts = self.accounts.read().await;
        
        // From account kontrolü
        let from_account = accounts.get(&tx.from)
            .ok_or("From account not found")?;
        
        // Balance kontrolü
        let total_cost = tx.value + (tx.gas_limit * tx.gas_price);
        if from_account.balance < total_cost {
            return Err("Insufficient balance for transaction".to_string());
        }
        
        // Nonce kontrolü
        if tx.nonce != from_account.nonce + 1 {
            return Err("Invalid nonce".to_string());
        }
        
        // Signature kontrolü (placeholder)
        if tx.signature.is_empty() {
            return Err("Missing signature".to_string());
        }
        
        Ok(())
    }

    pub async fn get_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        let pool = self.transaction_pool.read().await;
        pool.iter().take(limit).cloned().collect()
    }

    pub async fn remove_transactions(&self, tx_hashes: &[String]) {
        let mut pool = self.transaction_pool.write().await;
        pool.retain(|tx| !tx_hashes.contains(&tx.hash));
    }

    pub async fn add_block(&self, block: Block) -> Result<(), String> {
        // Blok doğrulaması
        self.validate_block(&block).await?;
        
        // Transaction'ları işle
        for tx in &block.transactions {
            self.process_transaction(tx).await?;
        }
        
        // Bloku ekle
        let mut blocks = self.blocks.write().await;
        blocks.push(block);
        
        // Block height güncelle
        let mut height = self.current_block_height.write().await;
        *height += 1;
        
        Ok(())
    }

    async fn validate_block(&self, block: &Block) -> Result<(), String> {
        let blocks = self.blocks.read().await;
        let current_height = self.current_block_height.read().await;
        
        // Index kontrolü
        if block.index != *current_height + 1 {
            return Err("Invalid block index".to_string());
        }
        
        // Previous hash kontrolü
        if let Some(last_block) = blocks.last() {
            if block.previous_hash != last_block.hash {
                return Err("Invalid previous hash".to_string());
            }
        }
        
        // Timestamp kontrolü
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if block.timestamp > now + 60 {
            return Err("Block timestamp too far in future".to_string());
        }
        
        Ok(())
    }

    async fn process_transaction(&self, tx: &Transaction) -> Result<(), String> {
        // Gas fee hesaplama
        let gas_fee = tx.gas_limit * tx.gas_price;
        
        // Transfer işlemi
        self.transfer(&tx.from, &tx.to, tx.value).await?;
        
        // Gas fee ödemesi (validator'a)
        // Şimdilik yakılan gas olarak işlem yapıyoruz
        let mut accounts = self.accounts.write().await;
        if let Some(mut from_account) = accounts.get(&tx.from).cloned() {
            if from_account.balance >= gas_fee {
                from_account.balance -= gas_fee;
                accounts.insert(tx.from.clone(), from_account);
            }
        }
        
        Ok(())
    }

    pub async fn get_account_balance(&self, address: &str) -> u64 {
        let accounts = self.accounts.read().await;
        accounts.get(address)
            .map(|acc| acc.balance)
            .unwrap_or(0)
    }

    pub async fn get_account_nonce(&self, address: &str) -> u64 {
        let accounts = self.accounts.read().await;
        accounts.get(address)
            .map(|acc| acc.nonce)
            .unwrap_or(0)
    }

    pub async fn get_block_by_index(&self, index: u64) -> Option<Block> {
        let blocks = self.blocks.read().await;
        blocks.iter().find(|b| b.index == index).cloned()
    }

    pub async fn get_latest_block(&self) -> Option<Block> {
        let blocks = self.blocks.read().await;
        blocks.last().cloned()
    }

    pub async fn get_current_height(&self) -> u64 {
        let height = self.current_block_height.read().await;
        *height
    }

    pub async fn get_total_supply(&self) -> u64 {
        let supply = self.total_supply.read().await;
        *supply
    }

    pub async fn mint_tokens(&self, to: &str, amount: u64) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        let mut supply = self.total_supply.write().await;
        
        let mut account = accounts.get(to).cloned()
            .unwrap_or_else(|| Account {
                address: to.to_string(),
                balance: 0,
                nonce: 0,
                code: None,
                storage: HashMap::new(),
            });
        
        account.balance += amount;
        *supply += amount;
        
        accounts.insert(to.to_string(), account);
        Ok(())
    }

    pub async fn burn_tokens(&self, from: &str, amount: u64) -> Result<(), String> {
        let mut accounts = self.accounts.write().await;
        let mut supply = self.total_supply.write().await;
        
        let mut account = accounts.get(from)
            .ok_or("Account not found")?
            .clone();
        
        if account.balance < amount {
            return Err("Insufficient balance to burn".to_string());
        }
        
        account.balance -= amount;
        *supply -= amount;
        
        accounts.insert(from.to_string(), account);
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
        let state = ChainState::new();
        let result = state.create_account("0x123".to_string(), 1000).await;
        assert!(result.is_ok());
        
        let account = state.get_account("0x123").await;
        assert!(account.is_some());
        assert_eq!(account.unwrap().balance, 1000);
    }

    #[tokio::test]
    async fn test_transfer() {
        let state = ChainState::new();
        state.create_account("0x123".to_string(), 1000).await.unwrap();
        state.create_account("0x456".to_string(), 0).await.unwrap();
        
        let result = state.transfer("0x123", "0x456", 500).await;
        assert!(result.is_ok());
        
        assert_eq!(state.get_account_balance("0x123").await, 500);
        assert_eq!(state.get_account_balance("0x456").await, 500);
    }
}
