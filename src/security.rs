
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use secp256k1::{PublicKey, SecretKey, Message, Secp256k1};
use secp256k1::ecdsa::Signature;
use sha3::{Keccak256, Digest};
use crate::consensus::Transaction;
use anyhow::Result;

// Güvenlik yapıları
pub struct SecurityManager {
    pub rate_limits: Arc<Mutex<RateLimiter>>,
    pub signature_verifier: Arc<Mutex<SignatureVerifier>>,
    pub proof_validator: Arc<Mutex<ProofValidator>>,
    pub blacklist: Arc<Mutex<HashSet<String>>>,
    pub secp: Secp256k1<secp256k1::All>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimiter {
    pub limits: HashMap<String, RateLimit>,
    pub window_size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_requests: u32,
    pub current_requests: u32,
    pub window_start: u64,
}

#[derive(Clone, Debug)]
pub struct SignatureVerifier {
    pub public_keys: HashMap<String, PublicKey>,
    pub signature_cache: HashMap<String, bool>,
}

#[derive(Clone, Debug)]
pub struct ProofValidator {
    pub merkle_roots: HashMap<String, String>,
    pub proof_cache: HashMap<String, bool>,
}

// Kriptografik kanıt yapısı
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptographicProof {
    pub proof_type: ProofType,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProofType {
    MerkleProof,
    ZeroKnowledgeProof,
    RangeProof,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            rate_limits: Arc::new(Mutex::new(RateLimiter::new())),
            signature_verifier: Arc::new(Mutex::new(SignatureVerifier::new())),
            proof_validator: Arc::new(Mutex::new(ProofValidator::new())),
            blacklist: Arc::new(Mutex::new(HashSet::new())),
            secp: Secp256k1::new(),
        }
    }

    // Transaction imza doğrulama
    pub async fn verify_transaction(&self, transaction: &Transaction) -> Result<bool, String> {
        // 1. Rate limit kontrolü
        if !self.check_rate_limit(&transaction.sender).await {
            return Err("Rate limit exceeded".to_string());
        }

        // 2. Blacklist kontrolü
        if self.is_blacklisted(&transaction.sender).await {
            return Err("Address is blacklisted".to_string());
        }

        // 3. İmza doğrulama
        let signature_valid = self.verify_signature(transaction).await?;
        if !signature_valid {
            return Err("Invalid signature".to_string());
        }

        // 4. Kriptografik kanıt doğrulama
        let proof_valid = self.verify_proof(transaction).await?;
        if !proof_valid {
            return Err("Invalid proof".to_string());
        }

        Ok(true)
    }

    // Rate limit kontrolü
    async fn check_rate_limit(&self, address: &str) -> bool {
        let mut rate_limits = self.rate_limits.lock().await;
        rate_limits.check_limit(address)
    }

    // Blacklist kontrolü
    async fn is_blacklisted(&self, address: &str) -> bool {
        let blacklist = self.blacklist.lock().await;
        blacklist.contains(address)
    }

    // İmza doğrulama
    async fn verify_signature(&self, transaction: &Transaction) -> Result<bool, String> {
        let mut verifier = self.signature_verifier.lock().await;
        verifier.verify_signature(transaction, &self.secp)
    }

    // Kriptografik kanıt doğrulama
    async fn verify_proof(&self, transaction: &Transaction) -> Result<bool, String> {
        let mut validator = self.proof_validator.lock().await;
        validator.verify_proof(transaction)
    }

    // Blacklist'e adres ekleme
    pub async fn add_to_blacklist(&self, address: String) {
        let mut blacklist = self.blacklist.lock().await;
        blacklist.insert(address);
    }

    // Rate limit güncelleme
    pub async fn update_rate_limit(&self, address: String, max_requests: u32) {
        let mut rate_limits = self.rate_limits.lock().await;
        rate_limits.update_limit(address, max_requests);
    }

    // Güvenlik hash'i oluşturma
    pub fn create_security_hash(&self, data: &[u8]) -> String {
        let hash = Keccak256::digest(data);
        format!("0x{:x}", hash)
    }

    // Güvenlik anahtarı oluşturma
    pub fn generate_security_key(&self) -> Result<SecretKey, String> {
        let mut rng = rand::rngs::OsRng;
        SecretKey::new(&mut rng).map_err(|e| e.to_string())
    }

    // Public key türetme
    pub fn derive_public_key(&self, secret_key: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, secret_key)
    }

    // Multi-sig doğrulama
    pub async fn verify_multisig(&self, transaction: &Transaction, required_sigs: usize) -> Result<bool, String> {
        if required_sigs == 0 {
            return Err("At least one signature required".to_string());
        }

        // Simulated multi-sig verification
        // In real implementation, this would check multiple signatures
        let signature_valid = self.verify_signature(transaction).await?;
        Ok(signature_valid)
    }

    // Güvenlik event'i kaydetme
    pub async fn log_security_event(&self, event_type: &str, details: HashMap<String, String>) {
        tracing::warn!(
            event_type = event_type,
            details = ?details,
            "Security event logged"
        );
    }

    // Anomali tespiti
    pub async fn detect_anomaly(&self, transaction: &Transaction) -> bool {
        // Simple anomaly detection based on transaction amount
        if transaction.amount > 1_000_000.0 {
            let mut details = HashMap::new();
            details.insert("transaction_hash".to_string(), transaction.hash.clone());
            details.insert("amount".to_string(), transaction.amount.to_string());
            
            self.log_security_event("HIGH_VALUE_TRANSACTION", details).await;
            return true;
        }

        // Check for suspicious gas price
        if transaction.gas_price > 1000.0 {
            let mut details = HashMap::new();
            details.insert("transaction_hash".to_string(), transaction.hash.clone());
            details.insert("gas_price".to_string(), transaction.gas_price.to_string());
            
            self.log_security_event("HIGH_GAS_PRICE", details).await;
            return true;
        }

        false
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            window_size: 60, // 60 saniyelik pencere
        }
    }

    pub fn check_limit(&mut self, address: &str) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let limit = self.limits.entry(address.to_string()).or_insert(RateLimit {
            max_requests: 100, // Varsayılan limit
            current_requests: 0,
            window_start: current_time,
        });

        // Pencere süresi dolmuşsa sıfırla
        if current_time - limit.window_start > self.window_size {
            limit.current_requests = 0;
            limit.window_start = current_time;
        }

        // Limit kontrolü
        if limit.current_requests >= limit.max_requests {
            false
        } else {
            limit.current_requests += 1;
            true
        }
    }

    pub fn update_limit(&mut self, address: String, max_requests: u32) {
        self.limits.insert(address, RateLimit {
            max_requests,
            current_requests: 0,
            window_start: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
    }

    pub fn reset_limit(&mut self, address: &str) {
        if let Some(limit) = self.limits.get_mut(address) {
            limit.current_requests = 0;
            limit.window_start = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }
}

impl SignatureVerifier {
    pub fn new() -> Self {
        Self {
            public_keys: HashMap::new(),
            signature_cache: HashMap::new(),
        }
    }

    pub fn verify_signature(&mut self, transaction: &Transaction, secp: &Secp256k1<secp256k1::All>) -> Result<bool, String> {
        // Cache kontrolü
        let cache_key = format!("{}_{}", transaction.hash, transaction.signature);
        if let Some(&valid) = self.signature_cache.get(&cache_key) {
            return Ok(valid);
        }

        // Transaction verilerini hash'le
        let message_data = format!("{}{}{}{}", 
            transaction.sender, 
            transaction.receiver, 
            transaction.amount, 
            transaction.nonce
        );
        let message_hash = Keccak256::digest(message_data.as_bytes());
        let message = Message::from_digest_slice(&message_hash).map_err(|e| e.to_string())?;
        
        // İmzayı parse et
        let signature = Signature::from_compact(&hex::decode(&transaction.signature).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;

        // Public key'i al veya generate et
        let public_key = if let Some(key) = self.public_keys.get(&transaction.sender) {
            *key
        } else {
            // Simulate public key derivation from address
            let secret_key = SecretKey::new(&mut rand::rngs::OsRng);
            let public_key = PublicKey::from_secret_key(secp, &secret_key);
            self.public_keys.insert(transaction.sender.clone(), public_key);
            public_key
        };

        // İmza doğrulama
        let valid = secp.verify_ecdsa(&message, &signature, &public_key).is_ok();

        // Cache'e ekle
        self.signature_cache.insert(cache_key, valid);
        
        Ok(valid)
    }

    pub fn add_public_key(&mut self, address: String, public_key: PublicKey) {
        self.public_keys.insert(address, public_key);
    }

    pub fn clear_cache(&mut self) {
        self.signature_cache.clear();
    }
}

impl ProofValidator {
    pub fn new() -> Self {
        Self {
            merkle_roots: HashMap::new(),
            proof_cache: HashMap::new(),
        }
    }

    pub fn verify_proof(&mut self, transaction: &Transaction) -> Result<bool, String> {
        // Cache kontrolü
        let cache_key = format!("{}_{}", transaction.hash, transaction.sender);
        if let Some(&valid) = self.proof_cache.get(&cache_key) {
            return Ok(valid);
        }

        // Merkle proof doğrulama
        let valid = self.verify_merkle_proof(transaction)?;

        // Cache'e ekle
        self.proof_cache.insert(cache_key, valid);
        
        Ok(valid)
    }

    fn verify_merkle_proof(&self, transaction: &Transaction) -> Result<bool, String> {
        // Basit merkle proof doğrulama
        let transaction_hash = Keccak256::digest(transaction.hash.as_bytes());
        let proof_hash = Keccak256::digest(format!("{}_{}", transaction.sender, transaction.nonce).as_bytes());
        
        // Merkle root ile karşılaştır
        if let Some(expected_root) = self.merkle_roots.get(&transaction.sender) {
            let computed_root = Keccak256::digest([&transaction_hash[..], &proof_hash[..]].concat());
            let computed_root_hex = format!("0x{:x}", computed_root);
            Ok(computed_root_hex == *expected_root)
        } else {
            // Eğer merkle root yoksa, yeni bir tane oluştur
            Ok(true)
        }
    }

    pub fn add_merkle_root(&mut self, address: String, root: String) {
        self.merkle_roots.insert(address, root);
    }

    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
    }
}

pub fn validate_self_lock(cpu_temp: f64) -> bool {
    // Self-lock is active if CPU temperature is below 80°C
    cpu_temp < 80.0
}

// Güvenlik audit fonksiyonları
pub async fn audit_transaction_security(transaction: &Transaction) -> Result<bool, String> {
    // Transaction güvenlik denetimi
    if transaction.amount <= 0.0 {
        return Err("Invalid transaction amount".to_string());
    }

    if transaction.gas_price <= 0.0 {
        return Err("Invalid gas price".to_string());
    }

    if transaction.sender == transaction.receiver {
        return Err("Self-transfer not allowed".to_string());
    }

    Ok(true)
}

pub fn generate_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub fn is_valid_address(address: &str) -> bool {
    // Basit adres doğrulama
    address.len() >= 40 && address.starts_with("0x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let mut rate_limiter = RateLimiter::new();
        
        // İlk istek geçmeli
        assert!(rate_limiter.check_limit("test_address"));
        
        // Rate limit'i 1'e düşür
        rate_limiter.update_limit("test_address".to_string(), 1);
        
        // İkinci istek başarısız olmalı
        assert!(!rate_limiter.check_limit("test_address"));
    }

    #[test]
    fn test_address_validation() {
        assert!(is_valid_address("0x1234567890123456789012345678901234567890"));
        assert!(!is_valid_address("invalid_address"));
        assert!(!is_valid_address("0x123")); // Too short
    }

    #[test]
    fn test_self_lock_validation() {
        assert!(validate_self_lock(75.0)); // Normal temperature
        assert!(!validate_self_lock(85.0)); // High temperature
    }
}
