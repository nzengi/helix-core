use serde::{Deserialize, Serialize};
use std::fs;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub database: DatabaseConfig,
    pub api: ApiConfig,
    pub security: SecurityConfig,
    pub wallet: WalletConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_peers: usize,
    pub bootstrap_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub min_validators: usize,
    pub block_time_ms: u64,
    pub max_block_size: usize,
    pub min_stake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub port: u16,
    pub rate_limit_per_minute: u32,
    pub max_request_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_audit: bool,
    pub max_failed_attempts: u32,
    pub blacklist_duration_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub seed: String,
    pub derivation_path: String,
}

use std::fs;
use serde::{Serialize, Deserialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub consensus: ConsensusConfig,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub max_peers: u32,
    pub port: u16,
    pub bootstrap_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub min_validators: u32,
    pub block_time_ms: u64,
    pub max_block_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub rate_limit_per_minute: u32,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.network.max_peers == 0 {
            anyhow::bail!("max_peers must be greater than 0");
        }

        if self.consensus.min_validators == 0 {
            anyhow::bail!("min_validators must be greater than 0");
        }

        if self.consensus.block_time_ms < 1000 {
            anyhow::bail!("block_time_ms must be at least 1000ms");
        }

        if self.api.rate_limit_per_minute == 0 {
            anyhow::bail!("rate_limit_per_minute must be greater than 0");
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: vec![],
            },
            consensus: ConsensusConfig {
                min_validators: 3,
                block_time_ms: 2000,
                max_block_size: 1024 * 1024, // 1MB
                min_stake: 1000,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/helix".to_string(),
                max_connections: 10,
                timeout_seconds: 30,
            },
            api: ApiConfig {
                port: 5000,
                rate_limit_per_minute: 100,
                max_request_size: 1024 * 1024, // 1MB
            },
            security: SecurityConfig {
                enable_audit: true,
                max_failed_attempts: 5,
                blacklist_duration_hours: 24,
            },
            wallet: WalletConfig {
                seed: "test_seed_do_not_use_in_production".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            },
        }
    }
}