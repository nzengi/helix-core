use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub address: String,
    pub code: Vec<u8>,
    pub creator: String,
    pub created_at: u64,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    pub gas_limit: u64,
    pub gas_price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractState {
    pub nonce: u64,
    pub balance: u64,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCall {
    pub contract_address: String,
    pub caller: String,
    pub value: u64,
    pub data: Vec<u8>,
    pub gas_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub error: Option<String>,
}

pub struct SmartContractManager {
    contracts: Arc<Mutex<HashMap<String, Contract>>>,
    gas_costs: Arc<Mutex<HashMap<String, u64>>>,
}

impl SmartContractManager {
    pub fn new() -> Self {
        Self {
            contracts: Arc::new(Mutex::new(HashMap::new())),
            gas_costs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        creator: String,
        gas_limit: u64,
        gas_price: u64,
    ) -> Result<Contract, ContractError> {
        // Validate code (basic check)
        if code.is_empty() {
            return Err(ContractError::InvalidWasmModule);
        }

        // Generate contract address
        let address = self.generate_contract_address(&creator, &code)?;

        // Create contract
        let contract = Contract {
            address: address.clone(),
            code,
            creator,
            created_at: chrono::Utc::now().timestamp() as u64,
            storage: HashMap::new(),
            gas_limit,
            gas_price,
        };

        // Store contract
        let mut contracts = self.contracts.lock().await;
        contracts.insert(address.clone(), contract.clone());

        Ok(contract)
    }

    pub async fn call_contract(&self, call: ContractCall) -> Result<ContractResult, ContractError> {
        let start_time = Instant::now();
        let mut gas_used = 0;

        // Find contract
        let contracts = self.contracts.lock().await;
        let contract = contracts.get(&call.contract_address)
            .ok_or(ContractError::ContractNotFound)?;

        // Simulate contract execution
        let result = self.execute_contract_function(
            &call.data,
            call.gas_limit,
            &mut gas_used,
        )?;

        // Return result
        Ok(ContractResult {
            success: true,
            return_data: result?,
            gas_used,
            error: None,
        })
    }

    pub async fn get_contract_state(&self, address: &str) -> Result<ContractState, ContractError> {
        let contracts = self.contracts.lock().await;
        let contract = contracts.get(address)
            .ok_or(ContractError::ContractNotFound)?;

        Ok(ContractState {
            nonce: 0, // TODO: Implement nonce tracking
            balance: 0, // TODO: Implement balance tracking
            storage_root: self.calculate_storage_root(&contract.storage)?,
            code_hash: self.hash_code(&contract.code)?,
        })
    }

    pub async fn update_contract_storage(
        &self,
        address: &str,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), ContractError> {
        let mut contracts = self.contracts.lock().await;
        let contract = contracts.get_mut(address)
            .ok_or(ContractError::ContractNotFound)?;

        contract.storage.insert(key, value);
        Ok(())
    }

    pub async fn estimate_gas(&self, call: &ContractCall) -> Result<u64, ContractError> {
        // Simple gas estimation
        let base_cost = 21000; // Base transaction cost
        let data_cost = call.data.len() as u64 * 16; // Cost per byte of data
        let storage_cost = 20000; // Storage cost (estimated)

        Ok(base_cost + data_cost + storage_cost)
    }

    fn execute_contract_function(
        &self,
        data: &[u8],
        gas_limit: u64,
        gas_used: &mut u64,
    ) -> Result<Vec<u8>, ContractError> {
        // Simple contract execution simulation
        *gas_used = data.len() as u64 * 10; // 10 gas per byte

        if *gas_used > gas_limit {
            return Err(ContractError::GasLimitExceeded);
        }

        // Return echoed data for now
        Ok(data.to_vec())
    }

    fn generate_contract_address(&self, creator: &str, code: &[u8]) -> Result<String, ContractError> {
        let mut data = Vec::new();
        data.extend_from_slice(creator.as_bytes());
        data.extend_from_slice(code);

        let hash = Keccak256::digest(&data);
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    fn calculate_storage_root(&self, storage: &HashMap<Vec<u8>, Vec<u8>>) -> Result<[u8; 32], ContractError> {
        // Simple storage root calculation
        let mut hasher = Keccak256::new();

        // Sort storage keys for deterministic hash
        let mut sorted_items: Vec<_> = storage.iter().collect();
        sorted_items.sort_by_key(|(k, _)| *k);

        for (key, value) in sorted_items {
            hasher.update(key);
            hasher.update(value);
        }

        Ok(hasher.finalize().into())
    }

    fn hash_code(&self, code: &[u8]) -> Result<[u8; 32], ContractError> {
        let hash = Keccak256::digest(code);
        Ok(hash.into())
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Invalid WASM module")]
    InvalidWasmModule,
    #[error("Invalid return type")]
    InvalidReturnType,
    #[error("Gas limit exceeded")]
    GasLimitExceeded,
    #[error("Invalid contract address")]
    InvalidAddress,
    #[error("Storage error")]
    StorageError,
    #[error("Execution error: {0}")]
    ExecutionError(String),
}