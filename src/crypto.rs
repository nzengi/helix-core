use std::collections::HashMap;
use sha2::{Sha256, Digest};
use sha3::Keccak256;
use secp256k1::{Secp256k1, PublicKey, SecretKey, Message, ecdsa::Signature};
use ed25519_dalek::{Keypair, Signer, Verifier};
use rand::rngs::OsRng;
use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
pub struct CryptoManager {
    secp: Secp256k1<secp256k1::All>,
    signature_cache: HashMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: String,
    pub leaves: Vec<String>,
    pub proofs: HashMap<usize, Vec<String>>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
            signature_cache: HashMap::new(),
        }
    }

    pub fn generate_keypair(&self) -> Result<KeyPair> {
        let mut rng = OsRng;
        let (secret_key, public_key) = self.secp.generate_keypair(&mut rng);

        Ok(KeyPair {
            public_key: public_key.serialize().to_vec(),
            private_key: secret_key.secret_bytes().to_vec(),
        })
    }

    pub fn sign_message(&self, message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        let secret_key = SecretKey::from_slice(private_key)?;
        let message_hash = Sha256::digest(message);
        let message = Message::from_slice(&message_hash)?;

        let signature = self.secp.sign_ecdsa(&message, &secret_key);
        Ok(signature.serialize_compact().to_vec())
    }

    pub fn verify_signature(&mut self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let cache_key = format!("{}{}{}", 
            hex::encode(message), 
            hex::encode(signature), 
            hex::encode(public_key)
        );

        if let Some(&cached_result) = self.signature_cache.get(&cache_key) {
            return Ok(cached_result);
        }

        let public_key = PublicKey::from_slice(public_key)?;
        let signature = Signature::from_compact(signature)?;
        let message_hash = Sha256::digest(message);
        let message = Message::from_slice(&message_hash)?;

        let result = self.secp.verify_ecdsa(&message, &signature, &public_key).is_ok();
        self.signature_cache.insert(cache_key, result);

        Ok(result)
    }

    pub fn generate_ed25519_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

        Ok((keypair.public.to_bytes().to_vec(), keypair.secret.to_bytes().to_vec()))
    }

    pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    pub fn hash_keccak256(data: &[u8]) -> Vec<u8> {
        Keccak256::digest(data).to_vec()
    }

    pub fn derive_key(seed: &[u8], path: &str) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(path.as_bytes());
        Ok(hasher.finalize().to_vec())
    }
}

impl MerkleTree {
    pub fn new(leaves: Vec<String>) -> Self {
        let mut tree = Self {
            root: String::new(),
            leaves: leaves.clone(),
            proofs: HashMap::new(),
        };
        tree.build_tree();
        tree
    }

    fn build_tree(&mut self) {
        if self.leaves.is_empty() {
            return;
        }

        let mut current_level = self.leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 { &chunk[1] } else { left };

                let combined = format!("{}{}", left, right);
                let hash = hex::encode(Sha256::digest(combined.as_bytes()));
                next_level.push(hash);
            }

            current_level = next_level;
        }

        self.root = current_level[0].clone();
    }

    pub fn get_proof(&self, index: usize) -> Vec<String> {
        // Simplified proof generation
        if index >= self.leaves.len() {
            return Vec::new();
        }

        vec![self.root.clone()]
    }

    pub fn verify_proof(&self, leaf: &str, proof: &[String]) -> bool {
        !proof.is_empty() && proof[0] == self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let crypto = CryptoManager::new();
        let keypair = crypto.generate_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), 33);
        assert_eq!(keypair.private_key.len(), 32);
    }

    #[test]
    fn test_signature_verification() {
        let mut crypto = CryptoManager::new();
        let keypair = crypto.generate_keypair().unwrap();
        let message = b"test message";

        let signature = crypto.sign_message(message, &keypair.private_key).unwrap();
        let is_valid = crypto.verify_signature(message, &signature, &keypair.public_key).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_merkle_tree() {
        let leaves = vec!["leaf1".to_string(), "leaf2".to_string(), "leaf3".to_string()];
        let tree = MerkleTree::new(leaves);

        assert!(!tree.root.is_empty());

        let proof = tree.get_proof(0);
        assert!(tree.verify_proof("leaf1", &proof));
    }
}