use std::sync::Arc;
use tokio::sync::Mutex;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, Signature};
use sha2::{Sha256, Sha512, Digest};
use sha3::{Keccak256, Keccak512};
use blake2::{Blake2b, Blake2s, digest::{consts::U32, consts::U64}};
use ripemd::{Ripemd160, Ripemd320};
use rand::{rngs::OsRng, RngCore};
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;
use zeroize::Zeroize;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureData {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigWallet {
    pub address: String,
    pub owners: Vec<String>,
    pub threshold: u32,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigTransaction {
    pub wallet_address: String,
    pub destination: String,
    pub value: u64,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub signatures: Vec<SignatureData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment: CompressedRistretto,
    pub blinding_factor: Scalar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroKnowledgeProof {
    pub proof: RangeProof,
    pub commitment: PedersenCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: [u8; 32],
    pub leaves: Vec<[u8; 32]>,
    pub levels: Vec<Vec<[u8; 32]>>,
}

pub struct CryptoManager {
    secp: Secp256k1<secp256k1::All>,
    key_pairs: Arc<Mutex<Vec<KeyPair>>>,
    bulletproof_gens: BulletproofGens,
    pedersen_gens: PedersenGens,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
            key_pairs: Arc::new(Mutex::new(Vec::new())),
            bulletproof_gens: BulletproofGens::new(64, 1),
            pedersen_gens: PedersenGens::default(),
        }
    }

    pub async fn generate_key_pair(&self) -> Result<KeyPair, CryptoError> {
        let mut rng = OsRng;
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&self.secp, &secret_key);
        let address = self.public_key_to_address(&public_key)?;

        let key_pair = KeyPair {
            private_key: secret_key,
            public_key,
            address,
        };

        let mut key_pairs = self.key_pairs.lock().await;
        key_pairs.push(key_pair.clone());

        Ok(key_pair)
    }

    pub fn sign(&self, message: &[u8], private_key: &SecretKey) -> Result<SignatureData, CryptoError> {
        let msg = Message::from_slice(message)?;
        let signature = self.secp.sign_ecdsa(&msg, private_key);
        
        let (r, s) = signature.serialize_compact();
        let v = signature.serialize_compact()[64];

        Ok(SignatureData { r, s, v })
    }

    pub fn verify(&self, message: &[u8], signature: &SignatureData, public_key: &PublicKey) -> Result<bool, CryptoError> {
        let msg = Message::from_slice(message)?;
        let sig = Signature::from_compact(&[&signature.r[..], &signature.s[..]].concat())?;
        
        Ok(self.secp.verify_ecdsa(&msg, &sig, public_key).is_ok())
    }

    pub fn create_multisig_wallet(&self, owners: Vec<String>, threshold: u32) -> Result<MultisigWallet, CryptoError> {
        if threshold > owners.len() as u32 {
            return Err(CryptoError::InvalidThreshold);
        }

        let address = self.generate_multisig_address(&owners)?;

        Ok(MultisigWallet {
            address,
            owners,
            threshold,
            nonce: 0,
        })
    }

    pub fn create_multisig_transaction(
        &self,
        wallet: &MultisigWallet,
        destination: String,
        value: u64,
        data: Vec<u8>,
    ) -> Result<MultisigTransaction, CryptoError> {
        Ok(MultisigTransaction {
            wallet_address: wallet.address.clone(),
            destination,
            value,
            data,
            nonce: wallet.nonce,
            signatures: Vec::new(),
        })
    }

    pub fn sign_multisig_transaction(
        &self,
        transaction: &mut MultisigTransaction,
        private_key: &SecretKey,
    ) -> Result<(), CryptoError> {
        let message = self.hash_multisig_transaction(transaction)?;
        let signature = self.sign(&message, private_key)?;
        transaction.signatures.push(signature);
        Ok(())
    }

    pub fn verify_multisig_transaction(
        &self,
        transaction: &MultisigTransaction,
        wallet: &MultisigWallet,
    ) -> Result<bool, CryptoError> {
        if transaction.signatures.len() < wallet.threshold as usize {
            return Ok(false);
        }

        let message = self.hash_multisig_transaction(transaction)?;
        let mut valid_signatures = 0;

        for signature in &transaction.signatures {
            for owner in &wallet.owners {
                let public_key = self.address_to_public_key(owner)?;
                if self.verify(&message, signature, &public_key)? {
                    valid_signatures += 1;
                    break;
                }
            }
        }

        Ok(valid_signatures >= wallet.threshold as usize)
    }

    pub fn create_pedersen_commitment(&self, value: u64) -> Result<PedersenCommitment, CryptoError> {
        let mut rng = OsRng;
        let blinding_factor = Scalar::random(&mut rng);
        let value_scalar = Scalar::from(value);
        
        let commitment = self.pedersen_gens.commit(value_scalar, blinding_factor);
        
        Ok(PedersenCommitment {
            commitment: commitment.compress(),
            blinding_factor,
        })
    }

    pub fn verify_pedersen_commitment(
        &self,
        commitment: &PedersenCommitment,
        value: u64,
    ) -> Result<bool, CryptoError> {
        let value_scalar = Scalar::from(value);
        let expected_commitment = self.pedersen_gens.commit(value_scalar, commitment.blinding_factor);
        
        Ok(commitment.commitment == expected_commitment.compress())
    }

    pub fn create_zero_knowledge_proof(
        &self,
        value: u64,
        commitment: &PedersenCommitment,
    ) -> Result<ZeroKnowledgeProof, CryptoError> {
        let mut transcript = Transcript::new(b"ZeroKnowledgeProof");
        let mut rng = OsRng;
        
        let proof = RangeProof::prove_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            value,
            commitment.blinding_factor,
            &mut rng,
        )?;

        Ok(ZeroKnowledgeProof {
            proof,
            commitment: commitment.clone(),
        })
    }

    pub fn verify_zero_knowledge_proof(
        &self,
        proof: &ZeroKnowledgeProof,
    ) -> Result<bool, CryptoError> {
        let mut transcript = Transcript::new(b"ZeroKnowledgeProof");
        
        Ok(proof.proof.verify_single(
            &self.bulletproof_gens,
            &self.pedersen_gens,
            &mut transcript,
            &proof.commitment.commitment,
            None,
        ).is_ok())
    }

    pub fn create_merkle_tree(&self, leaves: Vec<[u8; 32]>) -> Result<MerkleTree, CryptoError> {
        if leaves.is_empty() {
            return Err(CryptoError::EmptyLeaves);
        }

        let mut levels = vec![leaves.clone()];
        let mut current_level = leaves;

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(self.hash_pair(chunk[0], chunk[1]));
                } else {
                    next_level.push(chunk[0]);
                }
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }

        Ok(MerkleTree {
            root: current_level[0],
            leaves,
            levels,
        })
    }

    pub fn verify_merkle_proof(
        &self,
        root: [u8; 32],
        leaf: [u8; 32],
        proof: Vec<[u8; 32]>,
    ) -> Result<bool, CryptoError> {
        let mut current = leaf;
        for sibling in proof {
            current = self.hash_pair(current, sibling);
        }
        Ok(current == root)
    }

    pub fn encrypt_aes_gcm(&self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        cipher.encrypt(nonce, data).map_err(|_| CryptoError::EncryptionError)
    }

    pub fn decrypt_aes_gcm(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|_| CryptoError::DecryptionError)
    }

    pub fn hash_sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_sha512(&self, data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_keccak256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_keccak512(&self, data: &[u8]) -> [u8; 64] {
        let mut hasher = Keccak512::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_blake2b(&self, data: &[u8]) -> [u8; 64] {
        let mut hasher = Blake2b::<U64>::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_blake2s(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2s::<U32>::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_ripemd160(&self, data: &[u8]) -> [u8; 20] {
        let mut hasher = Ripemd160::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_ripemd320(&self, data: &[u8]) -> [u8; 40] {
        let mut hasher = Ripemd320::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn public_key_to_address(&self, public_key: &PublicKey) -> Result<String, CryptoError> {
        let public_key_bytes = public_key.serialize_uncompressed();
        let hash = self.hash_keccak256(&public_key_bytes[1..]);
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    fn address_to_public_key(&self, address: &str) -> Result<PublicKey, CryptoError> {
        // This is a placeholder - in a real implementation, you would need to store
        // the mapping between addresses and public keys
        Err(CryptoError::AddressNotFound)
    }

    fn generate_multisig_address(&self, owners: &[String]) -> Result<String, CryptoError> {
        let mut data = Vec::new();
        for owner in owners {
            data.extend_from_slice(owner.as_bytes());
        }
        let hash = self.hash_keccak256(&data);
        Ok(format!("0x{}", hex::encode(&hash[12..])))
    }

    fn hash_multisig_transaction(&self, transaction: &MultisigTransaction) -> Result<Vec<u8>, CryptoError> {
        let mut data = Vec::new();
        data.extend_from_slice(transaction.wallet_address.as_bytes());
        data.extend_from_slice(transaction.destination.as_bytes());
        data.extend_from_slice(&transaction.value.to_le_bytes());
        data.extend_from_slice(&transaction.data);
        data.extend_from_slice(&transaction.nonce.to_le_bytes());
        Ok(self.hash_keccak256(&data).to_vec())
    }

    fn hash_pair(&self, a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&a);
        data.extend_from_slice(&b);
        self.hash_keccak256(&data)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid threshold")]
    InvalidThreshold,
    #[error("Address not found")]
    AddressNotFound,
    #[error("Empty leaves")]
    EmptyLeaves,
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid commitment")]
    InvalidCommitment,
}

impl From<secp256k1::Error> for CryptoError {
    fn from(_: secp256k1::Error) -> Self {
        CryptoError::InvalidSignature
    }
}

impl From<bulletproofs::ProofError> for CryptoError {
    fn from(_: bulletproofs::ProofError) -> Self {
        CryptoError::InvalidProof
    }
} 