use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use chrono::{DateTime, Utc};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes_gcm::{
    aead::{Aead, generic_array::GenericArray}, KeyInit, Key, Nonce};
use aes_gcm::{Aes256Gcm};
use flate2::{Compression, write::GzEncoder, read::GzDecoder};
use std::io::{Write, Read};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub local_path: PathBuf,
    pub ipfs_api_url: String,
    pub chunk_size: usize,
    pub max_file_size: u64,
    pub retention_period: Duration,
    pub encryption_enabled: bool,
    pub compression_enabled: bool,
    pub encryption_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredData {
    pub id: String,
    pub name: String,
    pub content_type: String,
    pub size: u64,
    pub hash: String,
    pub ipfs_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub is_encrypted: bool,
    pub is_compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_files: u64,
    pub total_size: u64,
    pub ipfs_files: u64,
    pub local_files: u64,
    pub encrypted_files: u64,
    pub compressed_files: u64,
    pub last_sync: Option<DateTime<Utc>>,
}

pub struct StorageManager {
    config: StorageConfig,
    data: Arc<Mutex<HashMap<String, StoredData>>>,
    stats: Arc<Mutex<StorageStats>>,
    encryption_cipher: Option<Aes256Gcm>,
}

impl StorageManager {
    pub async fn new(config: StorageConfig) -> Result<Self, StorageError> {
        // Yerel depolama dizinini oluştur
        fs::create_dir_all(&config.local_path).await?;

        // Şifreleme anahtarını hazırla
        let encryption_cipher = if config.encryption_enabled {
            if let Some(key_str) = &config.encryption_key {
                let key_bytes = hex::decode(key_str)
                    .map_err(|_| StorageError::EncryptionError("Invalid encryption key format".to_string()))?;
                if key_bytes.len() != 32 {
                    return Err(StorageError::EncryptionError("Encryption key must be 32 bytes".to_string()));
                }
                let key = Key::from_slice(&key_bytes);
                Some(Aes256Gcm::new(key))
            } else {
                // Rastgele anahtar oluştur
                let mut key_bytes = [0u8; 32];
                OsRng.fill_bytes(&mut key_bytes);
                let key = Key::from_slice(&key_bytes);
                tracing::warn!("Generated random encryption key - data may not be recoverable");
                Some(Aes256Gcm::new(key))
            }
        } else {
            None
        };

        Ok(Self {
            config,
            data: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(StorageStats {
                total_files: 0,
                total_size: 0,
                ipfs_files: 0,
                local_files: 0,
                encrypted_files: 0,
                compressed_files: 0,
                last_sync: None,
            })),
            encryption_cipher,
        })
    }

    pub async fn store_data(
        &self,
        name: &str,
        content_type: &str,
        data: Vec<u8>,
        metadata: HashMap<String, String>,
    ) -> Result<StoredData, StorageError> {
        // Dosya boyutu kontrolü
        if data.len() as u64 > self.config.max_file_size {
            return Err(StorageError::FileTooLarge);
        }

        let mut processed_data = data;
        let mut is_compressed = false;
        let mut is_encrypted = false;

        // Veriyi sıkıştır (eğer etkinse)
        if self.config.compression_enabled {
            processed_data = self.compress_data(&processed_data)?;
            is_compressed = true;
        }

        // Veriyi şifrele (eğer etkinse)
        if self.config.encryption_enabled {
            processed_data = self.encrypt_data(&processed_data)?;
            is_encrypted = true;
        }

        // Veri hash'ini hesapla
        let hash = self.calculate_hash(&processed_data);

        // Veriyi yerel depolamaya kaydet
        let local_path = self.config.local_path.join(&hash);
        let mut file = File::create(&local_path).await?;
        file.write_all(&processed_data).await?;

        // Veri kaydını oluştur
        let stored_data = StoredData {
            id: hash.clone(),
            name: name.to_string(),
            content_type: content_type.to_string(),
            size: processed_data.len() as u64,
            hash,
            ipfs_hash: None, // IPFS entegrasyonu kaldırıldı
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata,
            is_encrypted,
            is_compressed,
        };

        // Veriyi kaydet
        let mut data_map = self.data.lock().await;
        data_map.insert(stored_data.id.clone(), stored_data.clone());

        // İstatistikleri güncelle
        self.update_stats(true, stored_data.size, is_encrypted, is_compressed).await?;

        tracing::info!("Stored data: {} ({})", stored_data.name, stored_data.id);
        Ok(stored_data)
    }

    pub async fn retrieve_data(&self, id: &str) -> Result<Vec<u8>, StorageError> {
        let stored_data = {
            let data_map = self.data.lock().await;
            data_map.get(id).ok_or(StorageError::DataNotFound)?.clone()
        };

        // Veriyi yerel depolamadan oku
        let local_path = self.config.local_path.join(&stored_data.hash);
        let mut file = File::open(&local_path).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;

        // Veriyi şifresini çöz (eğer şifrelenmişse)
        if stored_data.is_encrypted {
            data = self.decrypt_data(&data)?;
        }

        // Veriyi çöz (eğer sıkıştırılmışsa)
        if stored_data.is_compressed {
            data = self.decompress_data(&data)?;
        }

        tracing::debug!("Retrieved data: {} ({})", stored_data.name, stored_data.id);
        Ok(data)
    }

    pub async fn delete_data(&self, id: &str) -> Result<(), StorageError> {
        let stored_data = {
            let data_map = self.data.lock().await;
            data_map.get(id).ok_or(StorageError::DataNotFound)?.clone()
        };

        // Yerel dosyayı sil
        let local_path = self.config.local_path.join(&stored_data.hash);
        if local_path.exists() {
            fs::remove_file(local_path).await?;
        }

        // Veriyi kayıtlardan sil
        {
            let mut data_map = self.data.lock().await;
            data_map.remove(id);
        }

        // İstatistikleri güncelle
        self.update_stats(false, stored_data.size, stored_data.is_encrypted, stored_data.is_compressed).await?;

        tracing::info!("Deleted data: {} ({})", stored_data.name, stored_data.id);
        Ok(())
    }

    pub async fn get_data_info(&self, id: &str) -> Result<StoredData, StorageError> {
        let data_map = self.data.lock().await;
        let stored_data = data_map.get(id).ok_or(StorageError::DataNotFound)?.clone();
        Ok(stored_data)
    }

    pub async fn list_data(&self) -> Vec<StoredData> {
        let data_map = self.data.lock().await;
        data_map.values().cloned().collect()
    }

    pub async fn get_storage_stats(&self) -> StorageStats {
        self.stats.lock().await.clone()
    }

    pub async fn cleanup_expired_data(&self) -> Result<u64, StorageError> {
        let mut removed_count = 0;
        let retention_threshold = Utc::now() - chrono::Duration::from_std(self.config.retention_period)
            .map_err(|_| StorageError::ConfigError("Invalid retention period".to_string()))?;

        let expired_ids: Vec<String> = {
            let data_map = self.data.lock().await;
            data_map.iter()
                .filter(|(_, data)| data.created_at < retention_threshold)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for id in expired_ids {
            if let Err(e) = self.delete_data(&id).await {
                tracing::warn!("Failed to delete expired data {}: {}", id, e);
            } else {
                removed_count += 1;
            }
        }

        tracing::info!("Cleaned up {} expired files", removed_count);
        Ok(removed_count)
    }

    fn calculate_hash(&self, data: &[u8]) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if let Some(cipher) = &self.encryption_cipher {
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher.encrypt(nonce, data)
                .map_err(|e| StorageError::EncryptionError(format!("Encryption failed: {}", e)))?;

            // Nonce'u şifreli verinin başına ekle
            let mut result = nonce_bytes.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(result)
        } else {
            Err(StorageError::EncryptionError("Encryption not enabled".to_string()))
        }
    }

    fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if let Some(cipher) = &self.encryption_cipher {
            if data.len() < 12 {
                return Err(StorageError::EncryptionError("Invalid encrypted data".to_string()));
            }

            let nonce = Nonce::from_slice(&data[0..12]);
            let ciphertext = &data[12..];

            cipher.decrypt(nonce, ciphertext)
                .map_err(|e| StorageError::EncryptionError(format!("Decryption failed: {}", e)))
        } else {
            Err(StorageError::EncryptionError("Encryption not enabled".to_string()))
        }
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)
            .map_err(|e| StorageError::CompressionError(format!("Compression failed: {}", e)))?;
        encoder.finish()
            .map_err(|e| StorageError::CompressionError(format!("Compression finalization failed: {}", e)))
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| StorageError::CompressionError(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }

    async fn update_stats(
        &self,
        is_add: bool,
        size: u64,
        is_encrypted: bool,
        is_compressed: bool,
    ) -> Result<(), StorageError> {
        let mut stats = self.stats.lock().await;
        if is_add {
            stats.total_files += 1;
            stats.total_size += size;
            stats.local_files += 1;
            if is_encrypted {
                stats.encrypted_files += 1;
            }
            if is_compressed {
                stats.compressed_files += 1;
            }
        } else {
            stats.total_files = stats.total_files.saturating_sub(1);
            stats.total_size = stats.total_size.saturating_sub(size);
            stats.local_files = stats.local_files.saturating_sub(1);
            if is_encrypted {
                stats.encrypted_files = stats.encrypted_files.saturating_sub(1);
            }
            if is_compressed {
                stats.compressed_files = stats.compressed_files.saturating_sub(1);
            }
        }
        stats.last_sync = Some(Utc::now());
        Ok(())
    }

    pub async fn sync_with_peers(&self) -> Result<(), StorageError> {
        // Peer'lar ile senkronizasyon işlemi
        tracing::info!("Starting peer synchronization");

        // Burada gerçek peer senkronizasyon mantığı olacak
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut stats = self.stats.lock().await;
        stats.last_sync = Some(Utc::now());

        tracing::info!("Peer synchronization completed");
        Ok(())
    }

    pub async fn get_storage_health(&self) -> Result<HashMap<String, String>, StorageError> {
        let mut health = HashMap::new();
        let stats = self.get_storage_stats().await;

        health.insert("status".to_string(), "healthy".to_string());
        health.insert("total_files".to_string(), stats.total_files.to_string());
        health.insert("total_size".to_string(), stats.total_size.to_string());
        health.insert("local_files".to_string(), stats.local_files.to_string());
        health.insert("encrypted_files".to_string(), stats.encrypted_files.to_string());
        health.insert("compressed_files".to_string(), stats.compressed_files.to_string());

        if let Some(last_sync) = stats.last_sync {
            health.insert("last_sync".to_string(), last_sync.to_rfc3339());
        }

        // Disk alanı kontrolü
        let disk_usage = self.calculate_disk_usage().await?;
        health.insert("disk_usage_mb".to_string(), (disk_usage / 1024 / 1024).to_string());

        Ok(health)
    }

    async fn calculate_disk_usage(&self) -> Result<u64, StorageError> {
        let mut total_size = 0u64;
        let mut dir = fs::read_dir(&self.config.local_path).await?;

        while let Some(entry) = dir.next_entry().await? {
            if let Ok(metadata) = entry.metadata().await {
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Data not found")]
    DataNotFound,
    #[error("File too large")]
    FileTooLarge,
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Compression error: {0}")]
    CompressionError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Network error: {0}")]
    NetworkError(String),
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            local_path: PathBuf::from("./data/storage"),
            ipfs_api_url: "http://127.0.0.1:5001".to_string(),
            chunk_size: 1024 * 1024, // 1MB
            max_file_size: 100 * 1024 * 1024, // 100MB
            retention_period: Duration::from_secs(30 * 24 * 60 * 60), // 30 gün
            encryption_enabled: true,
            compression_enabled: true,
            encryption_key: None,
        }
    }
}