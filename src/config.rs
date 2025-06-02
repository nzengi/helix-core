use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use config::{Config, ConfigError, File, Environment};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub sharding: ShardingConfig,
    pub database: DatabaseConfig,
    pub api: ApiConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    pub host: String,
    pub port: u16,
    pub bootstrap_nodes: Vec<String>,
    pub max_peers: u32,
    pub peer_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConsensusConfig {
    pub validator_address: String,
    pub min_validators: u32,
    pub block_time: u64,
    pub max_block_size: u32,
    pub gas_limit: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShardingConfig {
    pub total_shards: u32,
    pub shard_size: u32,
    pub cross_shard_timeout: u64,
    pub shard_sync_interval: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_connections: u32,
    pub cache_size: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub rate_limit: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
    pub max_size: u64,
    pub max_files: u32,
}

impl NodeConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let config_path = std::env::var("HELIX_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config/default.toml"));

        let config = Config::builder()
            // Varsayılan değerler
            .add_source(File::from_str(
                include_str!("../config/default.toml"),
                config::FileFormat::Toml,
            ))
            // Konfigürasyon dosyası
            .add_source(File::from(config_path))
            // Ortam değişkenleri
            .add_source(Environment::with_prefix("HELIX"))
            .build()?;

        config.try_deserialize()
    }

    pub fn save(&self, path: &str) -> Result<(), ConfigError> {
        let config_str = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Message(e.to_string()))?;
        
        std::fs::write(path, config_str)
            .map_err(|e| ConfigError::Message(e.to_string()))?;
        
        Ok(())
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                host: "0.0.0.0".to_string(),
                port: 8000,
                bootstrap_nodes: vec![],
                max_peers: 100,
                peer_timeout: 30,
            },
            consensus: ConsensusConfig {
                validator_address: String::new(),
                min_validators: 4,
                block_time: 2,
                max_block_size: 1000000,
                gas_limit: 1000000,
            },
            sharding: ShardingConfig {
                total_shards: 16,
                shard_size: 1000,
                cross_shard_timeout: 60,
                shard_sync_interval: 10,
            },
            database: DatabaseConfig {
                path: "helix.db".to_string(),
                max_connections: 10,
                cache_size: 1000000,
            },
            api: ApiConfig {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 8080,
                cors_origins: vec!["*".to_string()],
                rate_limit: 100,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: Some("helix.log".to_string()),
                max_size: 10000000,
                max_files: 5,
            },
        }
    }
}

// Configuration hata yönetimi
#[derive(Debug)]
pub enum ConfigError {
    FileError(String),
    ParseError(String),
    ValidationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileError(e) => write!(f, "File error: {}", e),
            ConfigError::ParseError(e) => write!(f, "Parse error: {}", e),
            ConfigError::ValidationError(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {} 