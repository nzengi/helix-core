use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub wallet: WalletConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_peers: usize,
    pub bootstrap_nodes: Vec<String>,
    pub chain_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub min_validators: usize,
    pub block_time_ms: u64,
    pub max_block_size: u32,
    pub min_stake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
    pub rate_limit_per_minute: u32,
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub audit_enabled: bool,
    pub rate_limiting: bool,
    pub encryption_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub seed: String,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
    pub console: bool,
    pub enable_metrics: bool,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: vec![],
                chain_id: "helix-mainnet-1".to_string(),
            },
            consensus: ConsensusConfig {
                min_validators: 3,
                block_time_ms: 5000,
                max_block_size: 1024 * 1024,
                min_stake: 1000,
            },
            api: ApiConfig {
                port: 3000,
                rate_limit_per_minute: 100,
                max_request_size: 1024 * 1024,
            },
            database: DatabaseConfig {
                url: "sqlite:helix.db".to_string(),
                max_connections: 10,
                timeout_seconds: 30,
            },
            security: SecurityConfig {
                audit_enabled: true,
                rate_limiting: true,
                encryption_enabled: true,
            },
            wallet: WalletConfig {
                seed: "".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            },
        }
    }
}