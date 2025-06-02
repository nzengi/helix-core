
use std::collections::HashMap;
use sha3::{Keccak256, Digest};
use serde::{Serialize, Deserialize};
use anyhow::Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: String,
    pub nonce: u64,
    pub shard_id: u32,
    pub storage_root: String,
    pub staked_amount: u64,
    pub beta_angle: f64,
    pub efficiency: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub timestamp: u64,
    pub initial_supply: u64,
    pub initial_validator: String,
    pub chain_id: String,
    pub accounts: HashMap<String, GenesisAccount>,
    pub hash: String,
    pub previous_hash: String,
    pub height: u64,
    pub merkle_root: String,
}

impl GenesisBlock {
    pub fn new(initial_validator: String, chain_id: Option<String>) -> Result<Self> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let chain_id = chain_id.unwrap_or_else(|| "helix-mainnet-1".to_string());
        let initial_supply = 1_000_000_000; // 1 billion HELIX
        
        let mut genesis = Self {
            timestamp,
            initial_supply,
            initial_validator: initial_validator.clone(),
            chain_id,
            accounts: HashMap::new(),
            hash: String::new(),
            previous_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            height: 0,
            merkle_root: String::new(),
        };
        
        // Add initial validator account
        genesis.add_account(GenesisAccount {
            address: initial_validator,
            nonce: 0,
            shard_id: 0,
            storage_root: String::new(),
            staked_amount: initial_supply,
            beta_angle: 45.0,
            efficiency: 1.0,
        });
        
        // Calculate hash and merkle root
        genesis.merkle_root = genesis.calculate_merkle_root();
        genesis.hash = genesis.calculate_hash()?;
        
        Ok(genesis)
    }
    
    pub fn add_account(&mut self, account: GenesisAccount) {
        self.accounts.insert(account.address.clone(), account);
    }
    
    pub fn remove_account(&mut self, address: &str) -> Option<GenesisAccount> {
        self.accounts.remove(address)
    }
    
    pub fn get_account(&self, address: &str) -> Option<&GenesisAccount> {
        self.accounts.get(address)
    }
    
    pub fn update_account(&mut self, address: &str, account: GenesisAccount) -> Result<()> {
        if self.accounts.contains_key(address) {
            self.accounts.insert(address.to_string(), account);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Account not found: {}", address))
        }
    }
    
    pub fn get_total_supply(&self) -> u64 {
        self.accounts.values().map(|acc| acc.staked_amount).sum()
    }
    
    pub fn get_validator_count(&self) -> usize {
        self.accounts.values().filter(|acc| acc.staked_amount > 0).count()
    }
    
    pub fn validate(&self) -> Result<()> {
        // Check if initial validator exists
        if !self.accounts.contains_key(&self.initial_validator) {
            return Err(anyhow::anyhow!("Initial validator not found in accounts"));
        }
        
        // Check total supply consistency
        let calculated_supply = self.get_total_supply();
        if calculated_supply != self.initial_supply {
            return Err(anyhow::anyhow!(
                "Supply mismatch: expected {}, got {}", 
                self.initial_supply, 
                calculated_supply
            ));
        }
        
        // Validate accounts
        for (address, account) in &self.accounts {
            if address != &account.address {
                return Err(anyhow::anyhow!("Address mismatch for account: {}", address));
            }
            
            if account.beta_angle < 0.0 || account.beta_angle > 90.0 {
                return Err(anyhow::anyhow!("Invalid beta angle for account: {}", address));
            }
            
            if account.efficiency < 0.0 || account.efficiency > 1.0 {
                return Err(anyhow::anyhow!("Invalid efficiency for account: {}", address));
            }
        }
        
        Ok(())
    }
    
    fn calculate_hash(&self) -> Result<String> {
        let data = format!(
            "{}{}{}{}{}{}{}",
            self.timestamp,
            self.initial_supply,
            self.initial_validator,
            self.chain_id,
            self.previous_hash,
            self.height,
            self.merkle_root
        );
        Ok(format!("0x{:x}", Keccak256::digest(data.as_bytes())))
    }
    
    fn calculate_merkle_root(&self) -> String {
        if self.accounts.is_empty() {
            return "0x0000000000000000000000000000000000000000000000000000000000000000".to_string();
        }
        
        let mut hashes: Vec<String> = self.accounts.values()
            .map(|account| {
                let data = format!(
                    "{}{}{}{}{}{}",
                    account.address,
                    account.nonce,
                    account.shard_id,
                    account.staked_amount,
                    account.beta_angle,
                    account.efficiency
                );
                format!("0x{:x}", Keccak256::digest(data.as_bytes()))
            })
            .collect();
        
        // Calculate merkle root
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    chunk[0].clone()
                };
                next_level.push(format!("0x{:x}", Keccak256::digest(combined.as_bytes())));
            }
            hashes = next_level;
        }
        
        hashes.into_iter().next().unwrap_or_else(|| 
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
        )
    }
    
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
    
    pub fn from_json(json: &str) -> Result<Self> {
        let genesis: Self = serde_json::from_str(json)?;
        genesis.validate()?;
        Ok(genesis)
    }
    
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        std::fs::write(path, self.to_json()?)?;
        Ok(())
    }
    
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_json(&content)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisState {
    pub accounts: HashMap<String, StateAccount>,
    pub validators: HashMap<String, ValidatorInfo>,
    pub total_supply: u64,
    pub chain_id: String,
    pub genesis_time: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateAccount {
    pub address: String,
    pub nonce: u64,
    pub shard_id: u32,
    pub storage_root: String,
    pub staked_amount: u64,
    pub beta_angle: f64,
    pub efficiency: f64,
    pub balance: u64,
    pub code_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub stake: u64,
    pub commission: f64,
    pub active: bool,
    pub joined_at: u64,
}

impl GenesisState {
    pub fn new(genesis: &GenesisBlock) -> Result<Self> {
        let mut accounts = HashMap::new();
        let mut validators = HashMap::new();
        
        // Convert genesis accounts to state accounts
        for (address, genesis_account) in &genesis.accounts {
            let state_account = StateAccount {
                address: genesis_account.address.clone(),
                nonce: genesis_account.nonce,
                shard_id: genesis_account.shard_id,
                storage_root: genesis_account.storage_root.clone(),
                staked_amount: genesis_account.staked_amount,
                beta_angle: genesis_account.beta_angle,
                efficiency: genesis_account.efficiency,
                balance: genesis_account.staked_amount,
                code_hash: None,
            };
            
            accounts.insert(address.clone(), state_account);
            
            // Add to validators if staked
            if genesis_account.staked_amount > 0 {
                validators.insert(address.clone(), ValidatorInfo {
                    address: address.clone(),
                    stake: genesis_account.staked_amount,
                    commission: 0.1, // 10% default commission
                    active: true,
                    joined_at: genesis.timestamp,
                });
            }
        }
        
        Ok(Self {
            accounts,
            validators,
            total_supply: genesis.initial_supply,
            chain_id: genesis.chain_id.clone(),
            genesis_time: genesis.timestamp,
        })
    }
    
    pub fn get_account(&self, address: &str) -> Option<&StateAccount> {
        self.accounts.get(address)
    }
    
    pub fn get_validator(&self, address: &str) -> Option<&ValidatorInfo> {
        self.validators.get(address)
    }
    
    pub fn get_total_staked(&self) -> u64 {
        self.validators.values().map(|v| v.stake).sum()
    }
    
    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.validators.values().filter(|v| v.active).collect()
    }
    
    pub fn validate_state(&self) -> Result<()> {
        // Check total supply consistency
        let total_balance: u64 = self.accounts.values().map(|acc| acc.balance).sum();
        if total_balance != self.total_supply {
            return Err(anyhow::anyhow!(
                "Total balance mismatch: expected {}, got {}", 
                self.total_supply, 
                total_balance
            ));
        }
        
        // Check validator consistency
        for (address, validator) in &self.validators {
            if !self.accounts.contains_key(address) {
                return Err(anyhow::anyhow!("Validator account not found: {}", address));
            }
            
            let account = &self.accounts[address];
            if account.staked_amount != validator.stake {
                return Err(anyhow::anyhow!(
                    "Stake mismatch for validator {}: account has {}, validator has {}", 
                    address, 
                    account.staked_amount, 
                    validator.stake
                ));
            }
        }
        
        Ok(())
    }
    
    pub fn export_genesis(&self) -> Result<GenesisBlock> {
        let mut genesis_accounts = HashMap::new();
        
        for (address, state_account) in &self.accounts {
            genesis_accounts.insert(address.clone(), GenesisAccount {
                address: state_account.address.clone(),
                nonce: state_account.nonce,
                shard_id: state_account.shard_id,
                storage_root: state_account.storage_root.clone(),
                staked_amount: state_account.staked_amount,
                beta_angle: state_account.beta_angle,
                efficiency: state_account.efficiency,
            });
        }
        
        // Find initial validator (highest stake)
        let initial_validator = self.validators.values()
            .max_by_key(|v| v.stake)
            .map(|v| v.address.clone())
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());
        
        let mut genesis = GenesisBlock {
            timestamp: self.genesis_time,
            initial_supply: self.total_supply,
            initial_validator,
            chain_id: self.chain_id.clone(),
            accounts: genesis_accounts,
            hash: String::new(),
            previous_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            height: 0,
            merkle_root: String::new(),
        };
        
        genesis.merkle_root = genesis.calculate_merkle_root();
        genesis.hash = genesis.calculate_hash()?;
        
        Ok(genesis)
    }
}

// Genesis builder for easier creation
pub struct GenesisBuilder {
    initial_validator: Option<String>,
    chain_id: Option<String>,
    initial_supply: Option<u64>,
    accounts: Vec<GenesisAccount>,
}

impl GenesisBuilder {
    pub fn new() -> Self {
        Self {
            initial_validator: None,
            chain_id: None,
            initial_supply: None,
            accounts: Vec::new(),
        }
    }
    
    pub fn initial_validator(mut self, validator: String) -> Self {
        self.initial_validator = Some(validator);
        self
    }
    
    pub fn chain_id(mut self, chain_id: String) -> Self {
        self.chain_id = Some(chain_id);
        self
    }
    
    pub fn initial_supply(mut self, supply: u64) -> Self {
        self.initial_supply = Some(supply);
        self
    }
    
    pub fn add_account(mut self, account: GenesisAccount) -> Self {
        self.accounts.push(account);
        self
    }
    
    pub fn add_validator(self, address: String, stake: u64) -> Self {
        self.add_account(GenesisAccount {
            address,
            nonce: 0,
            shard_id: 0,
            storage_root: String::new(),
            staked_amount: stake,
            beta_angle: 45.0,
            efficiency: 1.0,
        })
    }
    
    pub fn build(self) -> Result<GenesisBlock> {
        let initial_validator = self.initial_validator
            .ok_or_else(|| anyhow::anyhow!("Initial validator is required"))?;
        
        let mut genesis = GenesisBlock::new(initial_validator, self.chain_id)?;
        
        if let Some(supply) = self.initial_supply {
            genesis.initial_supply = supply;
        }
        
        // Add additional accounts
        for account in self.accounts {
            genesis.add_account(account);
        }
        
        // Recalculate hash after modifications
        genesis.merkle_root = genesis.calculate_merkle_root();
        genesis.hash = genesis.calculate_hash()?;
        
        genesis.validate()?;
        Ok(genesis)
    }
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block_creation() {
        let validator = "0x1234567890abcdef".to_string();
        let genesis = GenesisBlock::new(validator.clone(), None).unwrap();
        
        assert_eq!(genesis.initial_validator, validator);
        assert_eq!(genesis.chain_id, "helix-mainnet-1");
        assert!(genesis.accounts.contains_key(&validator));
        assert!(genesis.validate().is_ok());
    }
    
    #[test]
    fn test_genesis_builder() {
        let genesis = GenesisBuilder::new()
            .initial_validator("0x1234567890abcdef".to_string())
            .chain_id("test-chain".to_string())
            .initial_supply(1000000)
            .add_validator("0xabcdef1234567890".to_string(), 500000)
            .build()
            .unwrap();
        
        assert_eq!(genesis.chain_id, "test-chain");
        assert_eq!(genesis.accounts.len(), 2);
    }
    
    #[test]
    fn test_genesis_state_conversion() {
        let validator = "0x1234567890abcdef".to_string();
        let genesis = GenesisBlock::new(validator, None).unwrap();
        let state = GenesisState::new(&genesis).unwrap();
        
        assert!(state.validate_state().is_ok());
        assert_eq!(state.total_supply, genesis.initial_supply);
    }
}
