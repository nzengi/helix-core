use sha3::{Keccak256, Digest};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    UnknownError(String),
}

#[derive(Debug, Clone)]
pub struct CryptoManager {
    keypairs: HashMap<String, Keypair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub message_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: String,
    pub leaves: Vec<String>,
    pub nodes: Vec<Vec<String>>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            keypairs: HashMap::new(),
        }
    }

    pub fn generate_keypair(&mut self, identifier: &str) -> Result<PublicKey, String> {
        let mut csprng = OsRng{};
        let keypair = Keypair::generate(&mut csprng);
        let public_key = keypair.public;
        self.keypairs.insert(identifier.to_string(), keypair);
        Ok(public_key)
    }

    pub fn sign_message(&self, identifier: &str, message: &[u8]) -> Result<DigitalSignature, String> {
        let keypair = self.keypairs.get(identifier)
            .ok_or("Keypair not found")?;

        let message_hash = self.hash_data(message);
        let signature = keypair.sign(&message_hash);

        Ok(DigitalSignature {
            signature: signature.to_bytes().to_vec(),
            public_key: keypair.public.to_bytes().to_vec(),
            message_hash: message_hash.to_vec(),
        })
    }

    pub fn verify_signature(&self, signature: &DigitalSignature, message: &[u8]) -> Result<bool, String> {
        let public_key = PublicKey::from_bytes(&signature.public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        let sig = Signature::from_bytes(&signature.signature)
            .map_err(|e| format!("Invalid signature: {}", e))?;

        let message_hash = self.hash_data(message);

        if message_hash != signature.message_hash {
            return Ok(false);
        }

        Ok(public_key.verify(&message_hash, &sig).is_ok())
    }

    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    pub fn create_merkle_tree(&self, data: Vec<Vec<u8>>) -> MerkleTree {
        if data.is_empty() {
            return MerkleTree {
                root: String::new(),
                leaves: vec![],
                nodes: vec![],
            };
        }

        let leaves: Vec<String> = data.iter()
            .map(|item| hex::encode(self.hash_data(item)))
            .collect();

        let mut current_level = leaves.clone();
        let mut all_nodes = vec![current_level.clone()];

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left // Duplicate last node if odd number
                };

                let combined = format!("{}{}", left, right);
                let hash = hex::encode(self.hash_data(combined.as_bytes()));
                next_level.push(hash);
            }

            all_nodes.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level.into_iter().next().unwrap_or_default();

        MerkleTree {
            root,
            leaves,
            nodes: all_nodes,
        }
    }

    pub fn derive_key(&self, seed: &[u8], path: &str) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(seed);
        hasher.update(path.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn encrypt_data(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        // Simple XOR encryption for demonstration
        // In production, use proper encryption like AES-GCM
        if key.len() < 32 {
            return Err("Key too short".to_string());
        }

        let mut encrypted = Vec::new();
        for (i, byte) in data.iter().enumerate() {
            encrypted.push(byte ^ key[i % 32]);
        }

        Ok(encrypted)
    }

    pub fn decrypt_data(&self, encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
        // XOR decryption (same as encryption for XOR)
        self.encrypt_data(encrypted_data, key)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let mut crypto = CryptoManager::new();
        let public_key = crypto.generate_keypair("test").unwrap();
        assert_eq!(public_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_signature_verification() {
        let mut crypto = CryptoManager::new();
        crypto.generate_keypair("test").unwrap();

        let message = b"test message";
        let signature = crypto.sign_message("test", message).unwrap();
        let is_valid = crypto.verify_signature(&signature, message).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_merkle_tree() {
        let crypto = CryptoManager::new();
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
        ];

        let tree = crypto.create_merkle_tree(data);
        assert!(!tree.root.is_empty());
        assert_eq!(tree.leaves.len(), 3);
    }
}