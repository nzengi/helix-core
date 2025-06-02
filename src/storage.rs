use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use chrono::{DateTime, Utc};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::StreamExt;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient};
use ipfs_api_backend_hyper::TryFromUri;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub local_path: PathBuf,
    pub ipfs_api_url: String,
    pub chunk_size: usize,
    pub max_file_size: u64,
    pub retention_period: Duration,
    pub encryption_enabled: bool,
    pub compression_enabled: bool,
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
    ipfs_client: IpfsClient,
    data: Arc<Mutex<HashMap<String, StoredData>>>,
    stats: Arc<Mutex<StorageStats>>,
}

impl StorageManager {
    pub async fn new(config: StorageConfig) -> Result<Self, StorageError> {
        // IPFS istemcisini başlat
        let ipfs_client = IpfsClient::from_str(&config.ipfs_api_url)
            .map_err(|e| StorageError::ConfigError(e.to_string()))?;

        // Yerel depolama dizinini oluştur
        fs::create_dir_all(&config.local_path).await?;

        Ok(Self {
            config,
            ipfs_client,
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

        // Veriyi şifrele (eğer etkinse)
        let (processed_data, is_encrypted) = if self.config.encryption_enabled {
            (self.encrypt_data(&data)?, true)
        } else {
            (data, false)
        };

        // Veriyi sıkıştır (eğer etkinse)
        let (processed_data, is_compressed) = if self.config.compression_enabled {
            (self.compress_data(&processed_data)?, true)
        } else {
            (processed_data, false)
        };

        // Veri hash'ini hesapla
        let hash = self.calculate_hash(&processed_data);

        // Veriyi IPFS'e yükle
        let ipfs_hash = self.upload_to_ipfs(&processed_data).await?;

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
            ipfs_hash: Some(ipfs_hash),
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

        Ok(stored_data)
    }

    pub async fn retrieve_data(&self, id: &str) -> Result<Vec<u8>, StorageError> {
        let data_map = self.data.lock().await;
        let stored_data = data_map.get(id).ok_or(StorageError::DataNotFound)?;

        // Veriyi yerel depolamadan oku
        let local_path = self.config.local_path.join(&stored_data.hash);
        let mut file = File::open(&local_path).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;

        // Veriyi çöz (eğer sıkıştırılmışsa)
        let data = if stored_data.is_compressed {
            self.decompress_data(&data)?
        } else {
            data
        };

        // Veriyi şifresini çöz (eğer şifrelenmişse)
        let data = if stored_data.is_encrypted {
            self.decrypt_data(&data)?
        } else {
            data
        };

        Ok(data)
    }

    pub async fn delete_data(&self, id: &str) -> Result<(), StorageError> {
        let mut data_map = self.data.lock().await;
        let stored_data = data_map.get(id).ok_or(StorageError::DataNotFound)?;

        // IPFS'ten sil
        if let Some(ipfs_hash) = &stored_data.ipfs_hash {
            self.ipfs_client.pin_rm(ipfs_hash, false).await?;
        }

        // Yerel dosyayı sil
        let local_path = self.config.local_path.join(&stored_data.hash);
        fs::remove_file(local_path).await?;

        // Veriyi kayıtlardan sil
        data_map.remove(id);

        // İstatistikleri güncelle
        self.update_stats(false, stored_data.size, stored_data.is_encrypted, stored_data.is_compressed).await?;

        Ok(())
    }

    pub async fn get_data_info(&self, id: &str) -> Result<StoredData, StorageError> {
        let data_map = self.data.lock().await;
        let stored_data = data_map.get(id).ok_or(StorageError::DataNotFound)?.clone();
        Ok(stored_data)
    }

    pub async fn get_storage_stats(&self) -> StorageStats {
        self.stats.lock().await.clone()
    }

    async fn upload_to_ipfs(&self, data: &[u8]) -> Result<String, StorageError> {
        let data_owned = data.to_vec();
        let cursor = std::io::Cursor::new(data_owned);
        let response = self.ipfs_client.add(cursor).await?;
        Ok(response.hash)
    }

    async fn download_from_ipfs(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        use futures::TryStreamExt;
        let stream = self.ipfs_client.cat(hash);
        let data: Vec<u8> = stream.try_collect().await?;
        Ok(data)
    }

    fn calculate_hash(&self, data: &[u8]) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        // TODO: Implement encryption
        Ok(data.to_vec())
    }

    fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        // TODO: Implement decryption
        Ok(data.to_vec())
    }

    fn compress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        // TODO: Implement compression
        Ok(data.to_vec())
    }

    fn decompress_data(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        // TODO: Implement decompression
        Ok(data.to_vec())
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
            if is_encrypted {
                stats.encrypted_files += 1;
            }
            if is_compressed {
                stats.compressed_files += 1;
            }
        } else {
            stats.total_files -= 1;
            stats.total_size -= size;
            if is_encrypted {
                stats.encrypted_files -= 1;
            }
            if is_compressed {
                stats.compressed_files -= 1;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Data not found")]
    DataNotFound,
    #[error("File too large")]
    FileTooLarge,
    #[error("Invalid IPFS URL")]
    InvalidIpfsUrl,
    #[error("IPFS error: {0}")]
    IpfsError(#[from] ipfs_api_backend_hyper::Error),
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
} 