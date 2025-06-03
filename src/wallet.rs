
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use anyhow::Result;

use crate::address::{Address, AddressGenerator, GearParameters};
use crate::crypto::CryptoManager;
use crate::consensus::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub address: Address,
    pub private_key_hex: String, // Store as hex string for serialization
    pub public_key_hex: String,  // Store as hex string for serialization
    pub balance: u64,
    pub nonce: u64,
    pub gear_params: Option<GearParameters>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_transaction: Option<chrono::DateTime<chrono::Utc>>,
    pub transaction_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub seed_phrase: String,
    pub derivation_path: String,
    pub auto_save: bool,
    pub encryption_enabled: bool,
    pub backup_interval_hours: u64,
    pub max_accounts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBuilder {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub amount: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub data: Vec<u8>,
    pub nonce: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatistics {
    pub total_accounts: usize,
    pub total_balance: u64,
    pub total_transactions: u64,
    pub oldest_account: Option<chrono::DateTime<chrono::Utc>>,
    pub newest_account: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct HelixWallet {
    accounts: Arc<Mutex<HashMap<Address, WalletAccount>>>,
    secp: Secp256k1<secp256k1::All>,
    crypto_manager: Arc<CryptoManager>,
    address_generator: AddressGenerator,
    config: WalletConfig,
    transaction_history: Arc<Mutex<Vec<Transaction>>>,
}

impl HelixWallet {
    pub fn new(seed: &str) -> Result<Self> {
        let config = WalletConfig {
            seed_phrase: seed.to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            auto_save: true,
            encryption_enabled: false,
            backup_interval_hours: 24,
            max_accounts: 1000,
        };

        Ok(Self {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            secp: Secp256k1::new(),
            crypto_manager: Arc::new(CryptoManager::new()),
            address_generator: AddressGenerator::new(),
            config,
            transaction_history: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn with_config(seed: &str, config: WalletConfig) -> Result<Self> {
        Ok(Self {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            secp: Secp256k1::new(),
            crypto_manager: Arc::new(CryptoManager::new()),
            address_generator: AddressGenerator::new(),
            config,
            transaction_history: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn create_account(&self) -> Result<Address> {
        let accounts = self.accounts.lock().await;
        if accounts.len() >= self.config.max_accounts {
            anyhow::bail!("Maximum number of accounts reached");
        }
        drop(accounts);

        let (secret_key, public_key, address) = self.address_generator.generate_keypair()?;

        let account = WalletAccount {
            address: address.clone(),
            private_key_hex: hex::encode(secret_key.secret_bytes()),
            public_key_hex: hex::encode(public_key.serialize()),
            balance: 0,
            nonce: 0,
            gear_params: None,
            created_at: chrono::Utc::now(),
            last_transaction: None,
            transaction_count: 0,
        };

        let mut accounts = self.accounts.lock().await;
        accounts.insert(address.clone(), account);

        tracing::info!("Created new account: {}", address);
        Ok(address)
    }

    pub async fn create_gear_account(&self, beta_angle: f64, stake: u64) -> Result<Address> {
        let accounts = self.accounts.lock().await;
        if accounts.len() >= self.config.max_accounts {
            anyhow::bail!("Maximum number of accounts reached");
        }
        drop(accounts);

        let (secret_key, public_key, _base_address) = self.address_generator.generate_keypair()?;
        let (gear_params, gear_address) = self.address_generator.generate_gear_address(beta_angle, stake)?;

        let account = WalletAccount {
            address: gear_address.clone(),
            private_key_hex: hex::encode(secret_key.secret_bytes()),
            public_key_hex: hex::encode(public_key.serialize()),
            balance: 0,
            nonce: 0,
            gear_params: Some(gear_params),
            created_at: chrono::Utc::now(),
            last_transaction: None,
            transaction_count: 0,
        };

        let mut accounts = self.accounts.lock().await;
        accounts.insert(gear_address.clone(), account);

        tracing::info!("Created new gear account: {} with β={:.1}°", gear_address, beta_angle);
        Ok(gear_address)
    }

    pub async fn import_account(&self, private_key_hex: &str) -> Result<Address> {
        let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))?;
        let secret_key = SecretKey::from_slice(&private_key_bytes)?;
        let public_key = PublicKey::from_secret_key(&self.secp, &secret_key);
        let address = Address::from_public_key(&public_key);

        let accounts = self.accounts.lock().await;
        if accounts.contains_key(&address) {
            anyhow::bail!("Account already exists in wallet");
        }
        if accounts.len() >= self.config.max_accounts {
            anyhow::bail!("Maximum number of accounts reached");
        }
        drop(accounts);

        let account = WalletAccount {
            address: address.clone(),
            private_key_hex: hex::encode(secret_key.secret_bytes()),
            public_key_hex: hex::encode(public_key.serialize()),
            balance: 0,
            nonce: 0,
            gear_params: None,
            created_at: chrono::Utc::now(),
            last_transaction: None,
            transaction_count: 0,
        };

        let mut accounts = self.accounts.lock().await;
        accounts.insert(address.clone(), account);

        tracing::info!("Imported account: {}", address);
        Ok(address)
    }

    pub async fn remove_account(&self, address: &Address) -> Result<bool> {
        let mut accounts = self.accounts.lock().await;
        let removed = accounts.remove(address).is_some();
        
        if removed {
            tracing::info!("Removed account: {}", address);
        }
        
        Ok(removed)
    }

    pub async fn get_account(&self, address: &Address) -> Result<Option<WalletAccount>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn list_accounts(&self) -> Result<Vec<Address>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.keys().cloned().collect())
    }

    pub async fn get_account_details(&self, address: &Address) -> Result<Option<WalletAccount>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn get_balance(&self, address: &Address) -> Result<u64> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).map(|acc| acc.balance).unwrap_or(0))
    }

    pub async fn update_balance(&self, address: &Address, new_balance: u64) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        if let Some(account) = accounts.get_mut(address) {
            account.balance = new_balance;
            tracing::debug!("Updated balance for {}: {}", address, new_balance);
        } else {
            anyhow::bail!("Account not found: {}", address);
        }
        Ok(())
    }

    pub async fn increment_nonce(&self, address: &Address) -> Result<u64> {
        let mut accounts = self.accounts.lock().await;
        if let Some(account) = accounts.get_mut(address) {
            account.nonce += 1;
            account.last_transaction = Some(chrono::Utc::now());
            account.transaction_count += 1;
            Ok(account.nonce)
        } else {
            anyhow::bail!("Account not found: {}", address);
        }
    }

    pub async fn sign_transaction(&self, tx: &Transaction) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let from_address = Address::from(tx.from.clone());

        let account = accounts.get(&from_address)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        let private_key_bytes = hex::decode(&account.private_key_hex)?;
        let secret_key = SecretKey::from_slice(&private_key_bytes)?;

        let tx_hash = self.calculate_transaction_hash(tx)?;
        let message = Message::from_slice(&tx_hash)?;
        let signature = self.secp.sign_ecdsa(&message, &secret_key);

        Ok(hex::encode(signature.serialize_compact()))
    }

    pub async fn verify_transaction_signature(&self, tx: &Transaction) -> Result<bool> {
        if tx.signature.is_empty() {
            return Ok(false);
        }

        let tx_hash = self.calculate_transaction_hash(tx)?;
        let message = Message::from_slice(&tx_hash)?;
        
        let signature_bytes = hex::decode(&tx.signature)?;
        let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)?;

        // Try to recover public key from signature
        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(0)?;
        let recovered_pubkey = self.secp.recover_ecdsa(&message, &secp256k1::ecdsa::RecoverableSignature::from_compact(&signature_bytes, recovery_id)?)?;
        
        let expected_address = Address::from_public_key(&recovered_pubkey);
        let from_address = Address::from(tx.from.clone());
        
        Ok(expected_address == from_address)
    }

    pub async fn create_transaction(&self, builder: TransactionBuilder) -> Result<Transaction> {
        let from = builder.from.ok_or_else(|| anyhow::anyhow!("From address required"))?;
        let to = builder.to.ok_or_else(|| anyhow::anyhow!("To address required"))?;

        let accounts = self.accounts.lock().await;
        let account = accounts.get(&from)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        let nonce = builder.nonce.unwrap_or(account.nonce);

        // Validate sufficient balance
        let total_cost = builder.amount + (builder.gas_price * builder.gas_limit);
        if account.balance < total_cost {
            anyhow::bail!("Insufficient balance: required {}, available {}", total_cost, account.balance);
        }

        let mut tx = Transaction {
            hash: String::new(),
            from: from.to_string(),
            to: to.to_string(),
            amount: builder.amount,
            gas_price: builder.gas_price,
            gas_limit: builder.gas_limit,
            nonce,
            data: builder.data,
            signature: String::new(),
            timestamp: chrono::Utc::now(),
        };

        // Calculate hash
        tx.hash = hex::encode(self.calculate_transaction_hash(&tx)?);

        // Sign transaction
        drop(accounts);
        tx.signature = self.sign_transaction(&tx).await?;

        // Add to transaction history
        let mut history = self.transaction_history.lock().await;
        history.push(tx.clone());

        Ok(tx)
    }

    pub async fn send_transaction(
        &self,
        from: &Address,
        to: &Address,
        amount: u64,
        gas_price: u64,
        gas_limit: u64,
    ) -> Result<Transaction> {
        let builder = TransactionBuilder {
            from: Some(from.clone()),
            to: Some(to.clone()),
            amount,
            gas_price,
            gas_limit,
            data: Vec::new(),
            nonce: None,
        };

        self.create_transaction(builder).await
    }

    pub async fn send_transaction_with_data(
        &self,
        from: &Address,
        to: &Address,
        amount: u64,
        gas_price: u64,
        gas_limit: u64,
        data: Vec<u8>,
    ) -> Result<Transaction> {
        let builder = TransactionBuilder {
            from: Some(from.clone()),
            to: Some(to.clone()),
            amount,
            gas_price,
            gas_limit,
            data,
            nonce: None,
        };

        self.create_transaction(builder).await
    }

    pub async fn estimate_gas(&self, tx: &TransactionBuilder) -> Result<u64> {
        let base_gas = 21000u64;
        let data_gas = tx.data.len() as u64 * 68;
        let contract_gas = if !tx.data.is_empty() { 32000 } else { 0 };
        let total_gas = base_gas + data_gas + contract_gas;

        Ok(total_gas.min(8_000_000)) // Cap at 8M gas (typical block limit)
    }

    pub async fn get_transaction_count(&self, address: &Address) -> Result<u64> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).map(|acc| acc.transaction_count).unwrap_or(0))
    }

    pub async fn get_transaction_history(&self, address: Option<&Address>, limit: Option<usize>) -> Result<Vec<Transaction>> {
        let history = self.transaction_history.lock().await;
        let mut filtered: Vec<Transaction> = if let Some(addr) = address {
            history.iter()
                .filter(|tx| tx.from == addr.to_string() || tx.to == addr.to_string())
                .cloned()
                .collect()
        } else {
            history.clone()
        };

        // Sort by timestamp (newest first)
        filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            filtered.truncate(limit);
        }

        Ok(filtered)
    }

    pub async fn export_private_key(&self, address: &Address) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let account = accounts.get(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        Ok(format!("0x{}", account.private_key_hex))
    }

    pub async fn export_account(&self, address: &Address) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let account = accounts.get(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        serde_json::to_string_pretty(account)
            .map_err(|e| anyhow::anyhow!("Failed to serialize account: {}", e))
    }

    pub async fn backup_wallet(&self) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let history = self.transaction_history.lock().await;
        
        let backup_data = serde_json::json!({
            "config": self.config,
            "accounts": *accounts,
            "transaction_history": *history,
            "backup_timestamp": chrono::Utc::now(),
            "version": "1.0"
        });

        tracing::info!("Wallet backup created with {} accounts", accounts.len());
        serde_json::to_string_pretty(&backup_data)
            .map_err(|e| anyhow::anyhow!("Failed to create backup: {}", e))
    }

    pub async fn restore_wallet(&self, backup_data: &str) -> Result<()> {
        let backup: serde_json::Value = serde_json::from_str(backup_data)?;
        
        let restored_accounts: HashMap<Address, WalletAccount> = 
            serde_json::from_value(backup["accounts"].clone())?;
        
        let mut accounts = self.accounts.lock().await;
        accounts.clear();
        accounts.extend(restored_accounts);

        if let Ok(history) = serde_json::from_value::<Vec<Transaction>>(backup["transaction_history"].clone()) {
            let mut tx_history = self.transaction_history.lock().await;
            tx_history.clear();
            tx_history.extend(history);
        }

        tracing::info!("Wallet restored with {} accounts", accounts.len());
        Ok(())
    }

    pub async fn get_wallet_statistics(&self) -> Result<WalletStatistics> {
        let accounts = self.accounts.lock().await;
        
        let total_accounts = accounts.len();
        let total_balance = accounts.values().map(|acc| acc.balance).sum();
        let total_transactions = accounts.values().map(|acc| acc.transaction_count).sum();
        
        let oldest_account = accounts.values()
            .map(|acc| acc.created_at)
            .min();
        
        let newest_account = accounts.values()
            .map(|acc| acc.created_at)
            .max();

        Ok(WalletStatistics {
            total_accounts,
            total_balance,
            total_transactions,
            oldest_account,
            newest_account,
        })
    }

    pub async fn validate_address(&self, address: &str) -> bool {
        Address::is_valid(address)
    }

    pub async fn clear_transaction_history(&self) -> Result<usize> {
        let mut history = self.transaction_history.lock().await;
        let count = history.len();
        history.clear();
        Ok(count)
    }

    fn calculate_transaction_hash(&self, tx: &Transaction) -> Result<Vec<u8>> {
        let mut hasher = Keccak256::new();
        hasher.update(tx.from.as_bytes());
        hasher.update(tx.to.as_bytes());
        hasher.update(&tx.amount.to_le_bytes());
        hasher.update(&tx.gas_price.to_le_bytes());
        hasher.update(&tx.gas_limit.to_le_bytes());
        hasher.update(&tx.nonce.to_le_bytes());
        hasher.update(&tx.data);
        hasher.update(&tx.timestamp.timestamp().to_le_bytes());

        Ok(hasher.finalize().to_vec())
    }
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            from: None,
            to: None,
            amount: 0,
            gas_price: 20_000_000_000, // 20 gwei default
            gas_limit: 21000,
            data: Vec::new(),
            nonce: None,
        }
    }

    pub fn from(mut self, address: Address) -> Self {
        self.from = Some(address);
        self
    }

    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }

    pub fn amount(mut self, amount: u64) -> Self {
        self.amount = amount;
        self
    }

    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.from.is_none() {
            anyhow::bail!("From address is required");
        }
        if self.to.is_none() {
            anyhow::bail!("To address is required");
        }
        if self.gas_price == 0 {
            anyhow::bail!("Gas price must be greater than 0");
        }
        if self.gas_limit == 0 {
            anyhow::bail!("Gas limit must be greater than 0");
        }
        Ok(())
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            seed_phrase: String::new(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            auto_save: true,
            encryption_enabled: false,
            backup_interval_hours: 24,
            max_accounts: 1000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_creation() {
        let wallet = HelixWallet::new("test seed phrase").unwrap();
        let stats = wallet.get_wallet_statistics().await.unwrap();
        assert_eq!(stats.total_accounts, 0);
    }

    #[tokio::test]
    async fn test_account_creation() {
        let wallet = HelixWallet::new("test seed phrase").unwrap();
        let address = wallet.create_account().await.unwrap();
        
        let account = wallet.get_account(&address).await.unwrap();
        assert!(account.is_some());
        assert_eq!(account.unwrap().balance, 0);
    }

    #[tokio::test]
    async fn test_gear_account_creation() {
        let wallet = HelixWallet::new("test seed phrase").unwrap();
        let address = wallet.create_gear_account(45.0, 1000).await.unwrap();
        
        let account = wallet.get_account(&address).await.unwrap();
        assert!(account.is_some());
        assert!(account.unwrap().gear_params.is_some());
    }

    #[tokio::test]
    async fn test_transaction_building() {
        let wallet = HelixWallet::new("test seed phrase").unwrap();
        let from = wallet.create_account().await.unwrap();
        let to = wallet.create_account().await.unwrap();
        
        // Set balance for from account
        wallet.update_balance(&from, 100000).await.unwrap();
        
        let builder = TransactionBuilder::new()
            .from(from)
            .to(to)
            .amount(1000)
            .gas_price(20_000_000_000)
            .gas_limit(21000);
            
        assert!(builder.validate().is_ok());
        
        let tx = wallet.create_transaction(builder).await.unwrap();
        assert_eq!(tx.amount, 1000);
        assert!(!tx.hash.is_empty());
        assert!(!tx.signature.is_empty());
    }

    #[tokio::test]
    async fn test_backup_restore() {
        let wallet = HelixWallet::new("test seed phrase").unwrap();
        let _address = wallet.create_account().await.unwrap();
        
        let backup = wallet.backup_wallet().await.unwrap();
        assert!(!backup.is_empty());
        
        let new_wallet = HelixWallet::new("different seed").unwrap();
        new_wallet.restore_wallet(&backup).await.unwrap();
        
        let stats = new_wallet.get_wallet_statistics().await.unwrap();
        assert_eq!(stats.total_accounts, 1);
    }
}
