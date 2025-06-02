
```rust
use helix_chain::{HelixNode, config::Config};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Genesis validator'ları oluştur
    let genesis_validators = vec![
        ("validator_1", 10000, 40.0, 0.92),
        ("validator_2", 8000, 35.0, 0.88), 
        ("validator_3", 12000, 45.0, 0.95),
    ];

    println!("🚀 HelixChain Genesis Setup");
    
    for (name, stake, beta, efficiency) in genesis_validators {
        println!("✅ Validator: {} | Stake: {} | Beta: {}° | Efficiency: {}", 
                name, stake, beta, efficiency);
    }

    println!("🔗 Network ready for testing!");
    Ok(())
}
```
