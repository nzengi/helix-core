use std::collections::HashMap;
use sha3::{Keccak256, Digest};
use serde::{Serialize, Deserialize};
use crate::state::Account;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub nonce: u64,
    pub shard_id: u32,
    pub storage_root: String,
    pub staked_amount: f64,
    pub beta_angle: f64,
    pub efficiency: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub timestamp: u64,
    pub initial_supply: f64,
    pub initial_validator: String,
    pub chain_id: String,
    pub accounts: HashMap<String, Account>,
}

impl GenesisBlock {
    pub fn new(initial_validator: String) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            initial_supply: 1_000_000.0, // 1 milyon HELIX
            initial_validator,
            chain_id: "helix-mainnet-1".to_string(),
            accounts: HashMap::new(),
        }
    }

    pub fn hash(&self) -> String {
        let data = format!(
            "{}{}{}{}",
            self.timestamp,
            self.initial_supply,
            self.initial_validator,
            self.chain_id
        );
        format!("0x{:x}", Keccak256::digest(data.as_bytes()))
    }
}

#[derive(Clone)]
pub struct GenesisState {
    pub accounts: HashMap<String, Account>,
    pub validators: HashMap<String, f64>,
}

impl GenesisState {
    pub fn new(genesis: &GenesisBlock) -> Self {
        let mut accounts = HashMap::new();
        let mut validators = HashMap::new();
        
        // İlk validator'a tüm başlangıç bakiyesini ver
        accounts.insert(
            genesis.initial_validator.clone(),
            Account {
                address: genesis.initial_validator.clone(),
                nonce: 0,
                shard_id: 0,
                storage_root: String::new(),
                staked_amount: genesis.initial_supply,
                beta_angle: 45.0,
                efficiency: 1.0,
            }
        );
        validators.insert(genesis.initial_validator.clone(), genesis.initial_supply);
        
        // Create initial accounts with balances
        accounts.insert(
            "0x7a3baefdbfad2171fbfdb2a9553e206d73e63f22869e".to_string(),
            Account {
                address: "0x7a3baefdbfad2171fbfdb2a9553e206d73e63f22869e".to_string(),
                nonce: 0,
                shard_id: 0,
                storage_root: String::new(),
                staked_amount: 1000000.0,
                beta_angle: 45.0,
                efficiency: 1.0,
            },
        );
        
        accounts.insert(
            "0x8b4cdefdbfad2171fbfdb2a9553e206d73e63f22869f".to_string(),
            Account {
                address: "0x8b4cdefdbfad2171fbfdb2a9553e206d73e63f22869f".to_string(),
                nonce: 0,
                shard_id: 0,
                storage_root: String::new(),
                staked_amount: 500000.0,
                beta_angle: 45.0,
                efficiency: 1.0,
            },
        );
        
        Self {
            accounts,
            validators,
        }
    }
} 