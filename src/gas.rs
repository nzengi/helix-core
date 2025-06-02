use std::time::{SystemTime, UNIX_EPOCH};

pub struct GasCalculator {
    base_price: f64,
}

impl GasCalculator {
    pub fn new() -> Self {
        Self {
            base_price: 0.0001,
        }
    }
    
    pub fn calculate(&mut self, amount: f64, data_size: usize) -> f64 {
        // Simple gas calculation based on amount and data size
        self.base_price * amount + (data_size as f64 * 0.00001)
    }
    
    pub fn get_current_price(&self) -> f64 {
        self.base_price
    }
}