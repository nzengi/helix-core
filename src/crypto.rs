use sha3::{Keccak256, Digest};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
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
    keypairs: HashMap<String, SigningKey>,
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

    pub fn generate_keypair(&mut self, identifier: &str) -> Result<VerifyingKey, String> {
        let mut csprng = OsRng{};
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        self.keypairs.insert(identifier.to_string(), signing_key);
        Ok(verifying_key)
    }

    pub fn sign_message(&self, identifier: &str, message: &[u8]) -> Result<DigitalSignature, String> {
        let signing_key = self.keypairs.get(identifier)
            .ok_or("Keypair not found")?;

        let message_hash = self.hash_data(message);
        let signature = signing_key.sign(&message_hash);

        Ok(DigitalSignature {
            signature: signature.to_bytes().to_vec(),
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            message_hash: message_hash.to_vec(),
        })
    }

    pub fn verify_signature(&self, signature: &DigitalSignature, message: &[u8]) -> Result<bool, String> {
        let public_key = VerifyingKey::from_bytes(
            signature.public_key.as_slice().try_into()
                .map_err(|_| "Invalid public key length")?
        ).map_err(|e| format!("Invalid public key: {}", e))?;

        let sig = Signature::from_bytes(
            signature.signature.as_slice().try_into()
                .map_err(|_| "Invalid signature length")?
        );

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

    pub fn sign_data(&self, data: &[u8]) -> Result<String, String> {
        // Use a default key or generate one if none exists
        if self.keypairs.is_empty() {
            return Err("No keypairs available for signing".to_string());
        }
        
        // Use the first available keypair for signing
        let (_, signing_key) = self.keypairs.iter().next().unwrap();
        let signature = signing_key.sign(data);
        Ok(hex::encode(signature.to_bytes()))
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

    pub fn hash_sha256(data: &[u8]) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        use rand::RngCore;
        let mut rng = OsRng;
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    pub fn verify_keypair(&self, identifier: &str, public_key_bytes: &[u8]) -> Result<bool, String> {
        let signing_key = self.keypairs.get(identifier)
            .ok_or("Keypair not found")?;

        let stored_public_key = signing_key.verifying_key().to_bytes();
        Ok(stored_public_key.as_slice() == public_key_bytes)
    }

    pub fn get_public_key(&self, identifier: &str) -> Result<Vec<u8>, String> {
        let signing_key = self.keypairs.get(identifier)
            .ok_or("Keypair not found")?;

        Ok(signing_key.verifying_key().to_bytes().to_vec())
    }

    pub fn import_keypair(&mut self, identifier: &str, private_key_bytes: &[u8]) -> Result<VerifyingKey, String> {
        let private_key_array: [u8; 32] = private_key_bytes.try_into()
            .map_err(|_| "Invalid private key length")?;

        let signing_key = SigningKey::from_bytes(&private_key_array);
        let verifying_key = signing_key.verifying_key();
        
        self.keypairs.insert(identifier.to_string(), signing_key);
        Ok(verifying_key)
    }

    pub fn export_private_key(&self, identifier: &str) -> Result<Vec<u8>, String> {
        let signing_key = self.keypairs.get(identifier)
            .ok_or("Keypair not found")?;

        Ok(signing_key.to_bytes().to_vec())
    }

    pub fn clear_keypair(&mut self, identifier: &str) -> bool {
        self.keypairs.remove(identifier).is_some()
    }

    pub fn list_keypairs(&self) -> Vec<String> {
        self.keypairs.keys().cloned().collect()
    }

    pub fn create_shared_secret(&self, our_private_key: &[u8], their_public_key: &[u8]) -> Result<Vec<u8>, String> {
        // Simple implementation using hash combination
        // In production, use proper ECDH
        let mut combined = Vec::new();
        combined.extend_from_slice(our_private_key);
        combined.extend_from_slice(their_public_key);
        Ok(self.hash_data(&combined))
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new(data: Vec<Vec<u8>>) -> Self {
        let crypto = CryptoManager::new();
        crypto.create_merkle_tree(data)
    }

    pub fn new_from_hashes(hashes: Vec<String>) -> Self {
        if hashes.is_empty() {
            return MerkleTree {
                root: String::new(),
                leaves: vec![],
                nodes: vec![],
            };
        }

        let mut current_level = hashes.clone();
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
                let hash = CryptoManager::hash_sha256(combined.as_bytes());
                next_level.push(hash);
            }

            all_nodes.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level.into_iter().next().unwrap_or_default();

        MerkleTree {
            root,
            leaves: hashes,
            nodes: all_nodes,
        }
    }

    pub fn get_proof(&self, index: usize) -> Vec<String> {
        let mut proof = Vec::new();
        let mut current_index = index;

        for level in &self.nodes {
            if level.len() <= 1 {
                break;
            }

            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                proof.push(level[sibling_index].clone());
            }

            current_index /= 2;
        }

        proof
    }

    pub fn verify_proof(&self, leaf: &str, proof: &[String], index: usize) -> bool {
        let mut current_hash = leaf.to_string();
        let mut current_index = index;

        for sibling in proof {
            let combined = if current_index % 2 == 0 {
                format!("{}{}", current_hash, sibling)
            } else {
                format!("{}{}", sibling, current_hash)
            };

            current_hash = CryptoManager::hash_sha256(combined.as_bytes());
            current_index /= 2;
        }

        current_hash == self.root
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

    #[test]
    fn test_merkle_proof() {
        let hashes = vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
            "hash4".to_string(),
        ];

        let tree = MerkleTree::new_from_hashes(hashes.clone());
        let proof = tree.get_proof(0);
        let is_valid = tree.verify_proof(&hashes[0], &proof, 0);
        assert!(is_valid);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = CryptoManager::new();
        let data = b"secret data";
        let key = CryptoManager::generate_random_bytes(32);

        let encrypted = crypto.encrypt_data(data, &key).unwrap();
        let decrypted = crypto.decrypt_data(&encrypted, &key).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let crypto = CryptoManager::new();
        let seed = b"master seed";
        let path1 = "m/44'/0'/0'/0/0";
        let path2 = "m/44'/0'/0'/0/1";

        let key1 = crypto.derive_key(seed, path1);
        let key2 = crypto.derive_key(seed, path2);

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_keypair_import_export() {
        let mut crypto = CryptoManager::new();
        let original_public = crypto.generate_keypair("test").unwrap();
        
        let private_key = crypto.export_private_key("test").unwrap();
        crypto.clear_keypair("test");
        
        let imported_public = crypto.import_keypair("test_imported", &private_key).unwrap();
        assert_eq!(original_public.to_bytes(), imported_public.to_bytes());
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = CryptoManager::generate_random_bytes(32);
        let bytes2 = CryptoManager::generate_random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Very unlikely to be the same
    }

    #[test]
    fn test_shared_secret() {
        let crypto = CryptoManager::new();
        let private_key1 = CryptoManager::generate_random_bytes(32);
        let private_key2 = CryptoManager::generate_random_bytes(32);
        let public_key1 = CryptoManager::generate_random_bytes(32);
        let public_key2 = CryptoManager::generate_random_bytes(32);

        let secret1 = crypto.create_shared_secret(&private_key1, &public_key2).unwrap();
        let secret2 = crypto.create_shared_secret(&private_key2, &public_key1).unwrap();
        
        assert_eq!(secret1.len(), 32);
        assert_eq!(secret2.len(), 32);
    }
}