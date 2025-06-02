use sha3::{Keccak256, Digest};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct HelixWallet {
    seed: String,
}

impl HelixWallet {
    pub fn new(seed: &str) -> Self {
        Self {
            seed: seed.to_string(),
        }
    }
    
    pub fn generate_address(&self) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(self.seed.as_bytes());
        let result = hasher.finalize();
        format!("0x{:x}", result)
    }
}