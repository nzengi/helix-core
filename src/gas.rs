
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPrice {
    pub base_fee: u64,
    pub priority_fee: u64,
    pub max_fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    pub estimated_gas: u64,
    pub gas_price: GasPrice,
    pub total_cost: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasUsage {
    pub used: u64,
    pub refunded: u64,
    pub burned: u64,
    pub remaining: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasMetrics {
    pub average_gas_price: u64,
    pub peak_usage: u64,
    pub network_congestion: f64,
    pub block_utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionGasInfo {
    pub tx_hash: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub gas_price: u64,
    pub total_fee: u64,
    pub refund: u64,
}

pub struct GasCalculator {
    base_price: u64,
    network_congestion: f64,
    block_gas_limit: u64,
    target_block_utilization: f64,
    gas_price_history: Vec<u64>,
    operation_costs: HashMap<String, u64>,
    dynamic_pricing_enabled: bool,
    eip1559_enabled: bool,
}

impl GasCalculator {
    pub fn new() -> Self {
        let mut operation_costs = HashMap::new();
        
        // Basic operation costs (in gas units)
        operation_costs.insert("transfer".to_string(), 21000);
        operation_costs.insert("contract_call".to_string(), 25000);
        operation_costs.insert("contract_deploy".to_string(), 53000);
        operation_costs.insert("storage_write".to_string(), 20000);
        operation_costs.insert("storage_read".to_string(), 800);
        operation_costs.insert("log_event".to_string(), 375);
        operation_costs.insert("sha3".to_string(), 30);
        operation_costs.insert("signature_verify".to_string(), 3000);
        operation_costs.insert("ec_recover".to_string(), 3000);
        operation_costs.insert("modexp".to_string(), 200);
        operation_costs.insert("bn_add".to_string(), 150);
        operation_costs.insert("bn_mul".to_string(), 6000);
        operation_costs.insert("bn_pairing".to_string(), 45000);
        
        Self {
            base_price: 1000000000, // 1 Gwei in wei
            network_congestion: 0.5,
            block_gas_limit: 30000000, // 30M gas
            target_block_utilization: 0.5,
            gas_price_history: Vec::new(),
            operation_costs,
            dynamic_pricing_enabled: true,
            eip1559_enabled: true,
        }
    }
    
    pub fn calculate_transaction_gas(&mut self, 
        tx_type: &str, 
        data_size: usize, 
        storage_operations: usize,
        contract_calls: usize
    ) -> Result<GasEstimate> {
        let base_gas = self.get_base_operation_cost(tx_type);
        let data_gas = self.calculate_data_gas(data_size);
        let storage_gas = storage_operations as u64 * self.operation_costs.get("storage_write").unwrap_or(&20000);
        let call_gas = contract_calls as u64 * self.operation_costs.get("contract_call").unwrap_or(&25000);
        
        let total_gas = base_gas + data_gas + storage_gas + call_gas;
        
        // Add 10% buffer for gas estimation
        let estimated_gas = (total_gas as f64 * 1.1) as u64;
        
        let gas_price = self.calculate_dynamic_gas_price()?;
        let total_cost = estimated_gas * gas_price.max_fee;
        
        Ok(GasEstimate {
            estimated_gas,
            gas_price,
            total_cost,
            confidence: self.calculate_confidence(),
        })
    }
    
    pub fn calculate_smart_contract_gas(&mut self, 
        bytecode_size: usize,
        constructor_data: usize,
        storage_slots: usize
    ) -> Result<GasEstimate> {
        let creation_gas = self.operation_costs.get("contract_deploy").unwrap_or(&53000);
        let bytecode_gas = (bytecode_size * 200) as u64; // 200 gas per byte
        let constructor_gas = self.calculate_data_gas(constructor_data);
        let storage_gas = storage_slots as u64 * self.operation_costs.get("storage_write").unwrap_or(&20000);
        
        let total_gas = creation_gas + bytecode_gas + constructor_gas + storage_gas;
        let estimated_gas = (total_gas as f64 * 1.2) as u64; // 20% buffer for contracts
        
        let gas_price = self.calculate_dynamic_gas_price()?;
        let total_cost = estimated_gas * gas_price.max_fee;
        
        Ok(GasEstimate {
            estimated_gas,
            gas_price,
            total_cost,
            confidence: self.calculate_confidence(),
        })
    }
    
    pub fn calculate_dynamic_gas_price(&mut self) -> Result<GasPrice> {
        if !self.dynamic_pricing_enabled {
            return Ok(GasPrice {
                base_fee: self.base_price,
                priority_fee: self.base_price / 10,
                max_fee: self.base_price + (self.base_price / 10),
            });
        }
        
        let congestion_multiplier = 1.0 + (self.network_congestion * 2.0);
        let base_fee = (self.base_price as f64 * congestion_multiplier) as u64;
        
        // EIP-1559 style pricing
        if self.eip1559_enabled {
            let priority_fee = self.calculate_priority_fee();
            let max_fee = base_fee + priority_fee;
            
            Ok(GasPrice {
                base_fee,
                priority_fee,
                max_fee,
            })
        } else {
            // Legacy pricing
            Ok(GasPrice {
                base_fee,
                priority_fee: 0,
                max_fee: base_fee,
            })
        }
    }
    
    pub fn process_transaction_gas(&mut self, 
        gas_limit: u64, 
        gas_used: u64, 
        gas_price: u64
    ) -> Result<GasUsage> {
        if gas_used > gas_limit {
            anyhow::bail!("Gas used exceeds gas limit");
        }
        
        let remaining = gas_limit - gas_used;
        let refunded = self.calculate_gas_refund(gas_used);
        let burned = if self.eip1559_enabled { 
            gas_used * (gas_price * 70 / 100) // 70% burned
        } else { 
            0 
        };
        
        // Update network congestion based on gas usage
        self.update_network_congestion(gas_used);
        
        // Store gas price in history
        self.gas_price_history.push(gas_price);
        if self.gas_price_history.len() > 100 {
            self.gas_price_history.remove(0);
        }
        
        Ok(GasUsage {
            used: gas_used,
            refunded,
            burned,
            remaining,
        })
    }
    
    pub fn get_gas_metrics(&self) -> GasMetrics {
        let average_gas_price = if self.gas_price_history.is_empty() {
            self.base_price
        } else {
            self.gas_price_history.iter().sum::<u64>() / self.gas_price_history.len() as u64
        };
        
        let peak_usage = self.gas_price_history.iter().max().cloned().unwrap_or(self.base_price);
        
        GasMetrics {
            average_gas_price,
            peak_usage,
            network_congestion: self.network_congestion,
            block_utilization: self.calculate_block_utilization(),
        }
    }
    
    pub fn estimate_block_gas(&self, transactions: &[TransactionGasInfo]) -> u64 {
        transactions.iter().map(|tx| tx.gas_used).sum()
    }
    
    pub fn validate_gas_limit(&self, gas_limit: u64) -> bool {
        gas_limit <= self.block_gas_limit && gas_limit >= 21000
    }
    
    pub fn optimize_gas_price(&mut self, target_confirmation_blocks: u32) -> Result<GasPrice> {
        let urgency_multiplier = match target_confirmation_blocks {
            1 => 2.0,  // Next block
            2..=3 => 1.5,  // Within 2-3 blocks
            4..=10 => 1.2,  // Within 10 blocks
            _ => 1.0,  // Standard
        };
        
        let mut gas_price = self.calculate_dynamic_gas_price()?;
        
        gas_price.base_fee = (gas_price.base_fee as f64 * urgency_multiplier) as u64;
        gas_price.priority_fee = (gas_price.priority_fee as f64 * urgency_multiplier) as u64;
        gas_price.max_fee = gas_price.base_fee + gas_price.priority_fee;
        
        Ok(gas_price)
    }
    
    pub fn set_network_congestion(&mut self, congestion: f64) {
        self.network_congestion = congestion.clamp(0.0, 2.0);
    }
    
    pub fn set_block_gas_limit(&mut self, limit: u64) {
        self.block_gas_limit = limit;
    }
    
    pub fn enable_eip1559(&mut self, enabled: bool) {
        self.eip1559_enabled = enabled;
    }
    
    pub fn enable_dynamic_pricing(&mut self, enabled: bool) {
        self.dynamic_pricing_enabled = enabled;
    }
    
    pub fn get_current_price(&self) -> u64 {
        self.base_price
    }
    
    pub fn update_operation_cost(&mut self, operation: String, cost: u64) {
        self.operation_costs.insert(operation, cost);
    }
    
    // Private helper methods
    
    fn get_base_operation_cost(&self, tx_type: &str) -> u64 {
        self.operation_costs.get(tx_type).cloned().unwrap_or(21000)
    }
    
    fn calculate_data_gas(&self, data_size: usize) -> u64 {
        // 4 gas per zero byte, 16 gas per non-zero byte (simplified)
        (data_size * 16) as u64
    }
    
    fn calculate_priority_fee(&self) -> u64 {
        let base_priority = self.base_price / 20; // 5% of base
        let congestion_bonus = (base_priority as f64 * self.network_congestion) as u64;
        base_priority + congestion_bonus
    }
    
    fn calculate_gas_refund(&self, gas_used: u64) -> u64 {
        // Simplified refund calculation (max 50% of gas used)
        let max_refund = gas_used / 2;
        // In reality, this would be based on storage deletions, etc.
        max_refund / 10 // Assume 10% refund on average
    }
    
    fn update_network_congestion(&mut self, gas_used: u64) {
        let utilization = gas_used as f64 / self.block_gas_limit as f64;
        let target_utilization = self.target_block_utilization;
        
        if utilization > target_utilization {
            self.network_congestion = (self.network_congestion + 0.1).min(2.0);
        } else {
            self.network_congestion = (self.network_congestion - 0.05).max(0.0);
        }
    }
    
    fn calculate_block_utilization(&self) -> f64 {
        // Simplified calculation based on recent gas usage
        if self.gas_price_history.is_empty() {
            0.5
        } else {
            let recent_avg = self.gas_price_history.iter().rev().take(10).sum::<u64>() as f64 
                / self.gas_price_history.len().min(10) as f64;
            (recent_avg / self.base_price as f64).min(1.0)
        }
    }
    
    fn calculate_confidence(&self) -> f64 {
        if self.gas_price_history.len() < 10 {
            0.7 // Lower confidence with limited data
        } else {
            let variance = self.calculate_price_variance();
            if variance < 0.1 {
                0.95 // High confidence for stable prices
            } else if variance < 0.3 {
                0.85 // Medium confidence
            } else {
                0.7 // Lower confidence for volatile prices
            }
        }
    }
    
    fn calculate_price_variance(&self) -> f64 {
        if self.gas_price_history.len() < 2 {
            return 0.0;
        }
        
        let mean = self.gas_price_history.iter().sum::<u64>() as f64 / self.gas_price_history.len() as f64;
        let variance = self.gas_price_history.iter()
            .map(|&price| {
                let diff = price as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / self.gas_price_history.len() as f64;
        
        (variance.sqrt() / mean).abs()
    }
}

impl Default for GasCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_calculator_creation() {
        let calculator = GasCalculator::new();
        assert_eq!(calculator.base_price, 1000000000);
        assert!(calculator.dynamic_pricing_enabled);
        assert!(calculator.eip1559_enabled);
    }

    #[test]
    fn test_transaction_gas_calculation() {
        let mut calculator = GasCalculator::new();
        let estimate = calculator.calculate_transaction_gas("transfer", 100, 1, 0).unwrap();
        
        assert!(estimate.estimated_gas > 21000);
        assert!(estimate.total_cost > 0);
        assert!(estimate.confidence > 0.0);
    }

    #[test]
    fn test_dynamic_gas_pricing() {
        let mut calculator = GasCalculator::new();
        calculator.set_network_congestion(1.5);
        
        let gas_price = calculator.calculate_dynamic_gas_price().unwrap();
        assert!(gas_price.base_fee > calculator.base_price);
    }

    #[test]
    fn test_gas_usage_processing() {
        let mut calculator = GasCalculator::new();
        let usage = calculator.process_transaction_gas(100000, 80000, 1000000000).unwrap();
        
        assert_eq!(usage.used, 80000);
        assert_eq!(usage.remaining, 20000);
        assert!(usage.refunded > 0);
    }

    #[test]
    fn test_smart_contract_gas_estimation() {
        let mut calculator = GasCalculator::new();
        let estimate = calculator.calculate_smart_contract_gas(1000, 200, 5).unwrap();
        
        assert!(estimate.estimated_gas > 53000); // Base contract creation cost
    }

    #[test]
    fn test_gas_optimization() {
        let mut calculator = GasCalculator::new();
        let optimized = calculator.optimize_gas_price(1).unwrap(); // Next block
        let standard = calculator.calculate_dynamic_gas_price().unwrap();
        
        assert!(optimized.max_fee > standard.max_fee);
    }

    #[test]
    fn test_network_congestion_update() {
        let mut calculator = GasCalculator::new();
        let initial_congestion = calculator.network_congestion;
        
        // High gas usage should increase congestion
        calculator.update_network_congestion(25000000); // High usage
        assert!(calculator.network_congestion >= initial_congestion);
    }

    #[test]
    fn test_gas_validation() {
        let calculator = GasCalculator::new();
        
        assert!(calculator.validate_gas_limit(21000)); // Minimum
        assert!(calculator.validate_gas_limit(1000000)); // Normal
        assert!(!calculator.validate_gas_limit(20000)); // Too low
        assert!(!calculator.validate_gas_limit(50000000)); // Too high
    }
}
