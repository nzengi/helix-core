use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use anyhow::Result;

use crate::address::{Address, AddressGenerator, GearParameters};
use crate::crypto::{CryptoManager, KeyPair};
use crate::consensus::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub address: Address,
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub balance: u64,
    pub nonce: u64,
    pub gear_params: Option<GearParameters>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub seed_phrase: String,
    pub derivation_path: String,
    pub auto_save: bool,
    pub encryption_enabled: bool,
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

pub struct HelixWallet {
    accounts: Arc<Mutex<HashMap<Address, WalletAccount>>>,
    secp: Secp256k1<secp256k1::All>,
    crypto_manager: Arc<CryptoManager>,
    address_generator: AddressGenerator,
    config: WalletConfig,
}

impl HelixWallet {
    pub fn new(seed: &str) -> Result<Self> {
        let config = WalletConfig {
            seed_phrase: seed.to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            auto_save: true,
            encryption_enabled: false,
        };

        Ok(Self {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            secp: Secp256k1::new(),
            crypto_manager: Arc::new(CryptoManager::new()),
            address_generator: AddressGenerator::new(),
            config,
        })
    }

    pub async fn create_account(&self) -> Result<Address> {
        let (secret_key, public_key, address) = self.address_generator.generate_keypair()?;

        let account = WalletAccount {
            address: address.clone(),
            private_key: secret_key,
            public_key,
            balance: 0,
            nonce: 0,
            gear_params: None,
            created_at: chrono::Utc::now(),
        };

        let mut accounts = self.accounts.lock().await;
        accounts.insert(address.clone(), account);

        tracing::info!("Created new account: {}", address);
        Ok(address)
    }

    pub async fn create_gear_account(&self, beta_angle: f64, stake: u64) -> Result<Address> {
        let (secret_key, public_key, base_address) = self.address_generator.generate_keypair()?;
        let (gear_params, gear_address) = self.address_generator.generate_gear_address(beta_angle, stake)?;

        let account = WalletAccount {
            address: gear_address.clone(),
            private_key: secret_key,
            public_key,
            balance: 0,
            nonce: 0,
            gear_params: Some(gear_params),
            created_at: chrono::Utc::now(),
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

        let account = WalletAccount {
            address: address.clone(),
            private_key: secret_key,
            public_key,
            balance: 0,
            nonce: 0,
            gear_params: None,
            created_at: chrono::Utc::now(),
        };

        let mut accounts = self.accounts.lock().await;
        accounts.insert(address.clone(), account);

        tracing::info!("Imported account: {}", address);
        Ok(address)
    }

    pub async fn get_account(&self, address: &Address) -> Result<Option<WalletAccount>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).cloned())
    }

    pub async fn list_accounts(&self) -> Result<Vec<Address>> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.keys().cloned().collect())
    }

    pub async fn get_balance(&self, address: &Address) -> Result<u64> {
        let accounts = self.accounts.lock().await;
        Ok(accounts.get(address).map(|acc| acc.balance).unwrap_or(0))
    }

    pub async fn update_balance(&self, address: &Address, new_balance: u64) -> Result<()> {
        let mut accounts = self.accounts.lock().await;
        if let Some(account) = accounts.get_mut(address) {
            account.balance = new_balance;
        }
        Ok(())
    }

    pub async fn sign_transaction(&self, tx: &Transaction) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let from_address = Address::from(tx.from.clone());

        let account = accounts.get(&from_address)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        let tx_hash = self.calculate_transaction_hash(tx)?;
        let message = Message::from_slice(&tx_hash)?;
        let signature = self.secp.sign_ecdsa(&message, &account.private_key);

        Ok(hex::encode(signature.serialize_compact()))
    }

    pub async fn create_transaction(&self, builder: TransactionBuilder) -> Result<Transaction> {
        let from = builder.from.ok_or_else(|| anyhow::anyhow!("From address required"))?;
        let to = builder.to.ok_or_else(|| anyhow::anyhow!("To address required"))?;

        let accounts = self.accounts.lock().await;
        let account = accounts.get(&from)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        let nonce = builder.nonce.unwrap_or(account.nonce);

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

    pub async fn estimate_gas(&self, tx: &TransactionBuilder) -> Result<u64> {
        // Simple gas estimation based on transaction complexity
        let base_gas = 21000u64;
        let data_gas = tx.data.len() as u64 * 68;
        let total_gas = base_gas + data_gas;

        Ok(total_gas.min(1_000_000)) // Cap at 1M gas
    }

    pub async fn export_private_key(&self, address: &Address) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let account = accounts.get(address)
            .ok_or_else(|| anyhow::anyhow!("Account not found in wallet"))?;

        Ok(format!("0x{}", hex::encode(account.private_key.secret_bytes())))
    }

    pub async fn backup_wallet(&self) -> Result<String> {
        let accounts = self.accounts.lock().await;
        let backup_data = serde_json::to_string(&*accounts)?;

        // In a real implementation, this would be encrypted
        tracing::info!("Wallet backup created with {} accounts", accounts.len());
        Ok(backup_data)
    }

    pub async fn restore_wallet(&self, backup_data: &str) -> Result<()> {
        let restored_accounts: HashMap<Address, WalletAccount> = serde_json::from_str(backup_data)?;
        let mut accounts = self.accounts.lock().await;
        accounts.extend(restored_accounts);

        tracing::info!("Wallet restored with {} accounts", accounts.len());
        Ok(())
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
            gas_price: 1,
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
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub address: String,
}

impl serde::Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KeyPair", 3)?;
        state.serialize_field("private_key", &self.private_key.secret_bytes())?;
        state.serialize_field("public_key", &self.public_key.serialize())?;
        state.serialize_field("address", &self.address)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Deserializer, MapAccess, Visitor};
        use std::fmt;

        struct KeyPairVisitor;

        impl<'de> Visitor<'de> for KeyPairVisitor {
            type Value = KeyPair;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct KeyPair")
            }

            fn visit_map<V>(self, mut map: V) -> Result<KeyPair, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut private_key_bytes: Option<[u8; 32]> = None;
                let mut public_key_bytes: Option<[u8; 33]> = None;
                let mut address: Option<String> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "private_key" => {
                            if private_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("private_key"));
                            }
                            private_key_bytes = Some(map.next_value()?);
                        }
                        "public_key" => {
                            if public_key_bytes.is_some() {
                                return Err(de::Error::duplicate_field("public_key"));
                            }
                            public_key_bytes = Some(map.next_value()?);
                        }
                        "address" => {
                            if address.is_some() {
                                return Err(de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }

                let private_key_bytes = private_key_bytes.ok_or_else(|| de::Error::missing_field("private_key"))?;
                let public_key_bytes = public_key_bytes.ok_or_else(|| de::Error::missing_field("public_key"))?;
                let address = address.ok_or_else(|| de::Error::missing_field("address"))?;

                let private_key = SecretKey::from_slice(&private_key_bytes)
                    .map_err(|e| de::Error::custom(format!("Invalid private key: {}", e)))?;
                let public_key = PublicKey::from_slice(&public_key_bytes)
                    .map_err(|e| de::Error::custom(format!("Invalid public key: {}", e)))?;

                Ok(KeyPair {
                    private_key,
                    public_key,
                    address,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["private_key", "public_key", "address"];
        deserializer.deserialize_struct("KeyPair", FIELDS, KeyPairVisitor)
    }
}