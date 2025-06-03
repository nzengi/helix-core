
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sha3::{Digest, Keccak256};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub address: String,
    pub code: Vec<u8>,
    pub creator: String,
    pub created_at: u64,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub version: u32,
    pub is_active: bool,
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
    pub logs: Vec<ContractLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
    pub block_number: u64,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    pub contract_address: String,
    pub event_name: String,
    pub data: HashMap<String, String>,
    pub block_number: u64,
    pub timestamp: u64,
}

pub struct SmartContractManager {
    contracts: Arc<Mutex<HashMap<String, Contract>>>,
    contract_states: Arc<Mutex<HashMap<String, ContractState>>>,
    gas_costs: Arc<Mutex<HashMap<String, u64>>>,
    events: Arc<Mutex<Vec<ContractEvent>>>,
    execution_cache: Arc<Mutex<HashMap<String, ContractResult>>>,
}

impl SmartContractManager {
    pub fn new() -> Self {
        let mut gas_costs = HashMap::new();
        
        // Initialize gas costs for different operations
        gas_costs.insert("CALL".to_string(), 700);
        gas_costs.insert("CALLCODE".to_string(), 700);
        gas_costs.insert("DELEGATECALL".to_string(), 700);
        gas_costs.insert("STATICCALL".to_string(), 700);
        gas_costs.insert("CREATE".to_string(), 32000);
        gas_costs.insert("CREATE2".to_string(), 32000);
        gas_costs.insert("SSTORE".to_string(), 20000);
        gas_costs.insert("SLOAD".to_string(), 800);
        gas_costs.insert("LOG0".to_string(), 375);
        gas_costs.insert("LOG1".to_string(), 375 + 375);
        gas_costs.insert("LOG2".to_string(), 375 + 375 * 2);
        gas_costs.insert("LOG3".to_string(), 375 + 375 * 3);
        gas_costs.insert("LOG4".to_string(), 375 + 375 * 4);
        
        Self {
            contracts: Arc::new(Mutex::new(HashMap::new())),
            contract_states: Arc::new(Mutex::new(HashMap::new())),
            gas_costs: Arc::new(Mutex::new(gas_costs)),
            events: Arc::new(Mutex::new(Vec::new())),
            execution_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        creator: String,
        gas_limit: u64,
        gas_price: u64,
        constructor_args: Vec<u8>,
    ) -> Result<Contract, ContractError> {
        // Validate code
        if code.is_empty() {
            return Err(ContractError::InvalidCode);
        }

        // Check gas limit
        if gas_limit < 21000 {
            return Err(ContractError::InsufficientGas);
        }

        // Generate contract address
        let address = self.generate_contract_address(&creator, &code)?;

        // Execute constructor if present
        let mut gas_used = 21000; // Base deployment cost
        if !constructor_args.is_empty() {
            gas_used += constructor_args.len() as u64 * 16; // Data cost
        }

        if gas_used > gas_limit {
            return Err(ContractError::GasLimitExceeded);
        }

        // Create contract
        let contract = Contract {
            address: address.clone(),
            code: code.clone(),
            creator,
            created_at: Utc::now().timestamp() as u64,
            storage: HashMap::new(),
            gas_limit,
            gas_price,
            version: 1,
            is_active: true,
        };

        // Create initial state
        let state = ContractState {
            nonce: 0,
            balance: 0,
            storage_root: self.calculate_storage_root(&HashMap::new())?,
            code_hash: self.hash_code(&code)?,
        };

        // Store contract and state
        let mut contracts = self.contracts.lock().await;
        let mut states = self.contract_states.lock().await;
        
        contracts.insert(address.clone(), contract.clone());
        states.insert(address.clone(), state);

        // Emit deployment event
        let event = ContractEvent {
            contract_address: address.clone(),
            event_name: "ContractDeployed".to_string(),
            data: {
                let mut data = HashMap::new();
                data.insert("creator".to_string(), contract.creator.clone());
                data.insert("gas_used".to_string(), gas_used.to_string());
                data
            },
            block_number: 0, // Will be set by consensus layer
            timestamp: Utc::now().timestamp() as u64,
        };

        let mut events = self.events.lock().await;
        events.push(event);

        Ok(contract)
    }

    pub async fn call_contract(&self, call: ContractCall) -> Result<ContractResult, ContractError> {
        let start_time = Instant::now();
        let mut gas_used = 21000; // Base call cost

        // Check cache first
        let cache_key = self.generate_call_cache_key(&call);
        {
            let cache = self.execution_cache.lock().await;
            if let Some(cached_result) = cache.get(&cache_key) {
                return Ok(cached_result.clone());
            }
        }

        // Find contract
        let contracts = self.contracts.lock().await;
        let contract = contracts.get(&call.contract_address)
            .ok_or(ContractError::ContractNotFound)?;

        if !contract.is_active {
            return Err(ContractError::ContractInactive);
        }

        // Validate gas limit
        if call.gas_limit < gas_used {
            return Err(ContractError::InsufficientGas);
        }

        // Execute contract function
        let execution_result = self.execute_contract_function(
            contract,
            &call.data,
            call.gas_limit - gas_used,
            &mut gas_used,
        ).await;

        let result = match execution_result {
            Ok(return_data) => ContractResult {
                success: true,
                return_data,
                gas_used,
                error: None,
                logs: Vec::new(),
            },
            Err(e) => ContractResult {
                success: false,
                return_data: Vec::new(),
                gas_used,
                error: Some(e.to_string()),
                logs: Vec::new(),
            },
        };

        // Cache successful results
        if result.success {
            let mut cache = self.execution_cache.lock().await;
            cache.insert(cache_key, result.clone());
        }

        Ok(result)
    }

    pub async fn get_contract(&self, address: &str) -> Result<Contract, ContractError> {
        let contracts = self.contracts.lock().await;
        contracts.get(address)
            .cloned()
            .ok_or(ContractError::ContractNotFound)
    }

    pub async fn get_contract_state(&self, address: &str) -> Result<ContractState, ContractError> {
        let states = self.contract_states.lock().await;
        states.get(address)
            .cloned()
            .ok_or(ContractError::ContractNotFound)
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

        // Update storage root
        let mut states = self.contract_states.lock().await;
        if let Some(state) = states.get_mut(address) {
            state.storage_root = self.calculate_storage_root(&contract.storage)?;
        }

        Ok(())
    }

    pub async fn get_contract_storage(
        &self,
        address: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ContractError> {
        let contracts = self.contracts.lock().await;
        let contract = contracts.get(address)
            .ok_or(ContractError::ContractNotFound)?;

        Ok(contract.storage.get(key).cloned())
    }

    pub async fn estimate_gas(&self, call: &ContractCall) -> Result<u64, ContractError> {
        let base_cost = 21000; // Base transaction cost
        let data_cost = call.data.len() as u64 * 16; // Cost per byte of data
        
        // Check if contract exists
        let contracts = self.contracts.lock().await;
        if !contracts.contains_key(&call.contract_address) {
            return Err(ContractError::ContractNotFound);
        }

        // Estimate execution cost based on data complexity
        let execution_cost = if call.data.len() > 4 {
            // Function call
            self.estimate_function_cost(&call.data).await?
        } else {
            // Simple transfer
            0
        };

        Ok(base_cost + data_cost + execution_cost)
    }

    pub async fn get_contract_events(
        &self,
        contract_address: Option<String>,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<ContractEvent>, ContractError> {
        let events = self.events.lock().await;
        
        let filtered_events: Vec<ContractEvent> = events.iter()
            .filter(|event| {
                if let Some(ref addr) = contract_address {
                    if &event.contract_address != addr {
                        return false;
                    }
                }
                
                if let Some(from) = from_block {
                    if event.block_number < from {
                        return false;
                    }
                }
                
                if let Some(to) = to_block {
                    if event.block_number > to {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();

        Ok(filtered_events)
    }

    pub async fn deactivate_contract(&self, address: &str) -> Result<(), ContractError> {
        let mut contracts = self.contracts.lock().await;
        let contract = contracts.get_mut(address)
            .ok_or(ContractError::ContractNotFound)?;

        contract.is_active = false;

        // Emit deactivation event
        let event = ContractEvent {
            contract_address: address.to_string(),
            event_name: "ContractDeactivated".to_string(),
            data: HashMap::new(),
            block_number: 0,
            timestamp: Utc::now().timestamp() as u64,
        };

        let mut events = self.events.lock().await;
        events.push(event);

        Ok(())
    }

    async fn execute_contract_function(
        &self,
        contract: &Contract,
        data: &[u8],
        gas_limit: u64,
        gas_used: &mut u64,
    ) -> Result<Vec<u8>, ContractError> {
        // Initialize WebAssembly runtime
        let mut store = wasmtime::Store::new(&wasmtime::Engine::default(), ());
        let module = wasmtime::Module::from_binary(&wasmtime::Engine::default(), &contract.code)
            .map_err(|_| ContractError::InvalidCode)?;
        
        let instance = wasmtime::Instance::new(&mut store, &module, &[])
            .map_err(|_| ContractError::ExecutionError("Failed to create instance".to_string()))?;

        // Get exported function
        let main_func = instance.get_typed_func::<(i32, i32), i32>(&mut store, "main")
            .map_err(|_| ContractError::ExecutionError("No main function found".to_string()))?;

        // Execute with gas metering
        let start_gas = *gas_used;
        let execution_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            async {
                // Simulate WebAssembly execution
                let result = main_func.call(&mut store, (data.len() as i32, gas_limit as i32))
                    .map_err(|e| ContractError::ExecutionError(e.to_string()))?;
                Ok::<i32, ContractError>(result)
            }
        ).await;

        match execution_result {
            Ok(Ok(result)) => {
                *gas_used += 21000; // Base execution cost
                
                // Advanced function handling
                if data.len() >= 4 {
                    let function_selector = &data[0..4];
                    match function_selector {
                        [0xa9, 0x05, 0x9c, 0xbb] => {
                            // transfer(address,uint256) function
                            self.handle_transfer_function(data, gas_used, contract).await
                        },
                        [0x70, 0xa0, 0x82, 0x31] => {
                            // balanceOf(address) function
                            self.handle_balance_function(data, gas_used, contract).await
                        },
                        [0xa0, 0x71, 0x2d, 0x68] => {
                            // mint(address,uint256) function
                            self.handle_mint_function(data, gas_used, contract).await
                        },
                        [0x42, 0x96, 0x6c, 0x68] => {
                            // burn(uint256) function
                            self.handle_burn_function(data, gas_used, contract).await
                        },
                        _ => {
                            *gas_used += 5000; // Unknown function execution cost
                            Ok(result.to_le_bytes().to_vec())
                        }
                    }
                } else {
                    // Simple value transfer
                    *gas_used += 2300; // Transfer gas cost
                    Ok(vec![0x01]) // Success
                }
            },
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ContractError::ExecutionError("Execution timeout".to_string())),
        }
    }

    async fn handle_transfer_function(
        &self,
        data: &[u8],
        gas_used: &mut u64,
        contract: &Contract,
    ) -> Result<Vec<u8>, ContractError> {
        if data.len() < 68 {
            return Err(ContractError::InvalidData);
        }

        *gas_used += 20000; // Storage write cost
        
        // Extract recipient and amount
        let recipient = hex::encode(&data[16..36]);
        let amount = u64::from_be_bytes(
            data[60..68].try_into().map_err(|_| ContractError::InvalidData)?
        );

        // Update contract storage
        let balance_key = format!("balance_{}", recipient);
        self.update_contract_storage(
            &contract.address,
            balance_key.as_bytes().to_vec(),
            amount.to_le_bytes().to_vec(),
        ).await?;

        // Emit transfer event
        self.emit_contract_event(
            &contract.address,
            "Transfer",
            vec![
                ("from".to_string(), hex::encode(&data[4..24])),
                ("to".to_string(), recipient),
                ("amount".to_string(), amount.to_string()),
            ],
        ).await?;

        Ok(vec![0x01]) // Success
    }

    async fn handle_balance_function(
        &self,
        data: &[u8],
        gas_used: &mut u64,
        contract: &Contract,
    ) -> Result<Vec<u8>, ContractError> {
        if data.len() < 36 {
            return Err(ContractError::InvalidData);
        }

        *gas_used += 800; // Storage read cost
        
        let address = hex::encode(&data[16..36]);
        let balance_key = format!("balance_{}", address);
        
        if let Ok(Some(balance_data)) = self.get_contract_storage(&contract.address, balance_key.as_bytes()).await {
            let balance = u64::from_le_bytes(
                balance_data.try_into().map_err(|_| ContractError::InvalidData)?
            );
            let mut result = vec![0u8; 32];
            result[24..32].copy_from_slice(&balance.to_be_bytes());
            Ok(result)
        } else {
            Ok(vec![0u8; 32]) // Zero balance
        }
    }

    async fn handle_mint_function(
        &self,
        data: &[u8],
        gas_used: &mut u64,
        contract: &Contract,
    ) -> Result<Vec<u8>, ContractError> {
        if data.len() < 68 {
            return Err(ContractError::InvalidData);
        }

        *gas_used += 25000; // Mint operation cost
        
        let recipient = hex::encode(&data[16..36]);
        let amount = u64::from_be_bytes(
            data[60..68].try_into().map_err(|_| ContractError::InvalidData)?
        );

        // Update total supply
        let total_supply_key = "total_supply".as_bytes().to_vec();
        let current_supply = if let Ok(Some(supply_data)) = self.get_contract_storage(&contract.address, &total_supply_key).await {
            u64::from_le_bytes(supply_data.try_into().map_err(|_| ContractError::InvalidData)?)
        } else {
            0
        };

        let new_supply = current_supply + amount;
        self.update_contract_storage(
            &contract.address,
            total_supply_key,
            new_supply.to_le_bytes().to_vec(),
        ).await?;

        // Update recipient balance
        let balance_key = format!("balance_{}", recipient);
        let current_balance = if let Ok(Some(balance_data)) = self.get_contract_storage(&contract.address, balance_key.as_bytes()).await {
            u64::from_le_bytes(balance_data.try_into().map_err(|_| ContractError::InvalidData)?)
        } else {
            0
        };

        let new_balance = current_balance + amount;
        self.update_contract_storage(
            &contract.address,
            balance_key.as_bytes().to_vec(),
            new_balance.to_le_bytes().to_vec(),
        ).await?;

        Ok(vec![0x01]) // Success
    }

    async fn handle_burn_function(
        &self,
        data: &[u8],
        gas_used: &mut u64,
        contract: &Contract,
    ) -> Result<Vec<u8>, ContractError> {
        if data.len() < 36 {
            return Err(ContractError::InvalidData);
        }

        *gas_used += 15000; // Burn operation cost
        
        let amount = u64::from_be_bytes(
            data[28..36].try_into().map_err(|_| ContractError::InvalidData)?
        );

        // Update total supply
        let total_supply_key = "total_supply".as_bytes().to_vec();
        let current_supply = if let Ok(Some(supply_data)) = self.get_contract_storage(&contract.address, &total_supply_key).await {
            u64::from_le_bytes(supply_data.try_into().map_err(|_| ContractError::InvalidData)?)
        } else {
            return Err(ContractError::ExecutionError("No supply to burn".to_string()));
        };

        if current_supply < amount {
            return Err(ContractError::ExecutionError("Insufficient supply to burn".to_string()));
        }

        let new_supply = current_supply - amount;
        self.update_contract_storage(
            &contract.address,
            total_supply_key,
            new_supply.to_le_bytes().to_vec(),
        ).await?;

        Ok(vec![0x01]) // Success
    }

    async fn emit_contract_event(
        &self,
        contract_address: &str,
        event_name: &str,
        parameters: Vec<(String, String)>,
    ) -> Result<(), ContractError> {
        let event = ContractEvent {
            contract_address: contract_address.to_string(),
            event_name: event_name.to_string(),
            data: parameters.into_iter().collect(),
            block_number: 0, // Will be set by consensus layer
            timestamp: Utc::now().timestamp() as u64,
        };

        let mut events = self.events.lock().await;
        events.push(event);

        Ok(())
    }

    async fn estimate_function_cost(&self, data: &[u8]) -> Result<u64, ContractError> {
        if data.len() < 4 {
            return Ok(0);
        }

        let function_selector = &data[0..4];
        let cost = match function_selector {
            [0xa9, 0x05, 0x9c, 0xbb] => 25000, // transfer function
            [0x70, 0xa0, 0x82, 0x31] => 800,   // balanceOf function
            [0x18, 0x16, 0x0d, 0xdd] => 800,   // totalSupply function
            [0xdd, 0x62, 0xed, 0x3e] => 800,   // allowance function
            [0x09, 0x5e, 0xa7, 0xb3] => 25000, // approve function
            [0x23, 0xb8, 0x72, 0xdd] => 30000, // transferFrom function
            _ => 5000, // Default cost for unknown functions
        };

        Ok(cost)
    }

    fn generate_contract_address(&self, creator: &str, code: &[u8]) -> Result<String, ContractError> {
        let mut hasher = Keccak256::new();
        hasher.update(creator.as_bytes());
        hasher.update(code);
        hasher.update(&Utc::now().timestamp().to_be_bytes());
        
        let hash = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    fn generate_call_cache_key(&self, call: &ContractCall) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(call.contract_address.as_bytes());
        hasher.update(call.caller.as_bytes());
        hasher.update(&call.value.to_be_bytes());
        hasher.update(&call.data);
        hasher.update(&call.gas_limit.to_be_bytes());
        
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    fn calculate_storage_root(&self, storage: &HashMap<Vec<u8>, Vec<u8>>) -> Result<[u8; 32], ContractError> {
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

impl Default for SmartContractManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Invalid contract code")]
    InvalidCode,
    #[error("Invalid data format")]
    InvalidData,
    #[error("Gas limit exceeded")]
    GasLimitExceeded,
    #[error("Insufficient gas")]
    InsufficientGas,
    #[error("Invalid contract address")]
    InvalidAddress,
    #[error("Storage error")]
    StorageError,
    #[error("Contract is inactive")]
    ContractInactive,
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_contract_deployment() {
        let manager = SmartContractManager::new();
        let code = vec![0x60, 0x80, 0x60, 0x40]; // Simple bytecode
        
        let result = manager.deploy_contract(
            code,
            "0x123".to_string(),
            100000,
            20,
            vec![],
        ).await;
        
        assert!(result.is_ok());
        let contract = result.unwrap();
        assert!(!contract.address.is_empty());
        assert!(contract.is_active);
    }

    #[tokio::test]
    async fn test_contract_call() {
        let manager = SmartContractManager::new();
        let code = vec![0x60, 0x80, 0x60, 0x40];
        
        let contract = manager.deploy_contract(
            code,
            "0x123".to_string(),
            100000,
            20,
            vec![],
        ).await.unwrap();

        let call = ContractCall {
            contract_address: contract.address,
            caller: "0x456".to_string(),
            value: 0,
            data: vec![0x70, 0xa0, 0x82, 0x31], // balanceOf function selector
            gas_limit: 50000,
        };

        let result = manager.call_contract(call).await;
        assert!(result.is_ok());
        
        let call_result = result.unwrap();
        assert!(call_result.success);
        assert!(call_result.gas_used > 0);
    }

    #[tokio::test]
    async fn test_gas_estimation() {
        let manager = SmartContractManager::new();
        let code = vec![0x60, 0x80, 0x60, 0x40];
        
        let contract = manager.deploy_contract(
            code,
            "0x123".to_string(),
            100000,
            20,
            vec![],
        ).await.unwrap();

        let call = ContractCall {
            contract_address: contract.address,
            caller: "0x456".to_string(),
            value: 0,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // transfer function selector
            gas_limit: 50000,
        };

        let gas_estimate = manager.estimate_gas(&call).await;
        assert!(gas_estimate.is_ok());
        assert!(gas_estimate.unwrap() > 21000);
    }

    #[tokio::test]
    async fn test_storage_operations() {
        let manager = SmartContractManager::new();
        let code = vec![0x60, 0x80, 0x60, 0x40];
        
        let contract = manager.deploy_contract(
            code,
            "0x123".to_string(),
            100000,
            20,
            vec![],
        ).await.unwrap();

        let key = vec![0x01, 0x02, 0x03];
        let value = vec![0x04, 0x05, 0x06];

        let result = manager.update_contract_storage(
            &contract.address,
            key.clone(),
            value.clone(),
        ).await;
        assert!(result.is_ok());

        let stored_value = manager.get_contract_storage(&contract.address, &key).await;
        assert!(stored_value.is_ok());
        assert_eq!(stored_value.unwrap(), Some(value));
    }
}
