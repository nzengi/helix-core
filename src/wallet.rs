use sha3::{Keccak256, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use hex;

pub struct Wallet {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Wallet {
    pub fn new(seed: &str) -> Self {
        let secp = Secp256k1::new();
        
        // Generate a deterministic secret key from the seed
        let mut hasher = Keccak256::new();
        hasher.update(seed.as_bytes());
        let seed_hash = hasher.finalize();
        
        let secret_key = SecretKey::from_slice(&seed_hash[..32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn generate_address(&self) -> String {
        let public_key_bytes = self.public_key.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&public_key_bytes[1..]);
        let addr_bytes = hasher.finalize();
        
        format!("0x7a3b{}", hex::encode(&addr_bytes[12..]))
    }
}