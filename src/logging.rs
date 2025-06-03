
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug, Level};
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    prelude::*,
    EnvFilter,
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use metrics::{Counter, Gauge, Histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use crate::config::LoggingConfig;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
pub struct Logger {
    config: Arc<Mutex<LoggingConfig>>,
    metrics: Arc<Metrics>,
    log_history: Arc<Mutex<Vec<LogEntry>>>,
    max_history_size: usize,
}

#[derive(Clone)]
pub struct Metrics {
    pub block_height_name: String,
    pub transaction_count_name: String,
    pub peer_count_name: String,
    pub block_time_name: String,
    pub shard_load_name: String,
    pub network_latency_name: String,
    pub error_count_name: String,
    pub warning_count_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: String,
    pub message: String,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub min_level: String,
    pub modules: Vec<String>,
    pub keywords: Vec<String>,
    pub time_range: Option<(u64, u64)>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("block_height", &self.block_height_name)
            .field("transaction_count", &self.transaction_count_name)
            .field("peer_count", &self.peer_count_name)
            .field("block_time", &self.block_time_name)
            .field("shard_load", &self.shard_load_name)
            .field("network_latency", &self.network_latency_name)
            .field("error_count", &self.error_count_name)
            .field("warning_count", &self.warning_count_name)
            .finish()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            block_height_name: "block_height".to_string(),
            transaction_count_name: "transaction_count".to_string(),
            peer_count_name: "peer_count".to_string(),
            block_time_name: "block_time".to_string(),
            shard_load_name: "shard_load".to_string(),
            network_latency_name: "network_latency".to_string(),
            error_count_name: "error_count".to_string(),
            warning_count_name: "warning_count".to_string(),
        }
    }

    pub fn increment_counter(&self, name: &str) {
        let name_owned = name.to_string();
        metrics::increment_counter!(name_owned);
    }

    pub fn record_histogram(&self, name: &str, value: f64) {
        let name_owned = name.to_string();
        metrics::histogram!(name_owned, value);
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let name_owned = name.to_string();
        metrics::gauge!(name_owned, value);
    }
}

impl LogEntry {
    pub fn new(level: String, message: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            timestamp,
            level,
            message,
            module: None,
            file: None,
            line: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_module(mut self, module: String) -> Self {
        self.module = Some(module);
        self
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl Logger {
    pub fn new(config: LoggingConfig) -> Result<Self, LoggingError> {
        // Log dizinini oluştur
        std::fs::create_dir_all("logs")
            .map_err(|e| LoggingError::InitializationError(e.to_string()))?;

        // Logging yapılandırması
        let file_appender = if let Some(file) = &config.file {
            RollingFileAppender::new(
                Rotation::DAILY,
                "logs",
                file,
            )
        } else {
            return Err(LoggingError::ConfigurationError("Log file not specified".to_string()));
        };

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // Log seviyesini parse et
        let log_level = config.level.parse::<Level>()
            .map_err(|_| LoggingError::ConfigurationError(format!("Invalid log level: {}", config.level)))?;

        // Logging subscriber'ı oluştur
        let env_filter = EnvFilter::try_from_default_env()
            .or_else(|_| EnvFilter::try_new(&config.level))
            .map_err(|e| LoggingError::ConfigurationError(e.to_string()))?;

        let subscriber = tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer()
                .with_timer(UtcTime::rfc_3339())
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(non_blocking)
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
                .with_file(true)
            );

        // Subscriber'ı ayarla
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| LoggingError::InitializationError(e.to_string()))?;

        // Metrics yapılandırması
        let metrics = Metrics::new();

        // Prometheus exporter'ı başlat
        if config.enable_metrics {
            PrometheusBuilder::new()
                .with_http_listener(([127, 0, 0, 1], 9000))
                .install()
                .map_err(|e| LoggingError::MetricsError(e.to_string()))?;
        }

        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            metrics: Arc::new(metrics),
            log_history: Arc::new(Mutex::new(Vec::new())),
            max_history_size: 1000,
        })
    }

    // Logging metodları
    pub async fn info(&self, message: &str) {
        info!("{}", message);
        self.add_to_history("INFO".to_string(), message.to_string()).await;
    }

    pub async fn warn(&self, message: &str) {
        warn!("{}", message);
        self.add_to_history("WARN".to_string(), message.to_string()).await;
        self.metrics.increment_counter(&self.metrics.warning_count_name);
    }

    pub async fn error(&self, message: &str) {
        error!("{}", message);
        self.add_to_history("ERROR".to_string(), message.to_string()).await;
        self.metrics.increment_counter(&self.metrics.error_count_name);
    }

    pub async fn debug(&self, message: &str) {
        debug!("{}", message);
        self.add_to_history("DEBUG".to_string(), message.to_string()).await;
    }

    pub async fn log_with_metadata(&self, level: &str, message: &str, metadata: HashMap<String, String>) {
        let entry = LogEntry::new(level.to_string(), message.to_string())
            .with_metadata("extra".to_string(), serde_json::to_string(&metadata).unwrap_or_default());

        match level {
            "ERROR" => {
                error!("{} - {:?}", message, metadata);
                self.metrics.increment_counter(&self.metrics.error_count_name);
            },
            "WARN" => {
                warn!("{} - {:?}", message, metadata);
                self.metrics.increment_counter(&self.metrics.warning_count_name);
            },
            "INFO" => info!("{} - {:?}", message, metadata),
            "DEBUG" => debug!("{} - {:?}", message, metadata),
            _ => info!("{} - {:?}", message, metadata),
        }

        let mut history = self.log_history.lock().await;
        history.push(entry);
        if history.len() > self.max_history_size {
            history.remove(0);
        }
    }

    async fn add_to_history(&self, level: String, message: String) {
        let entry = LogEntry::new(level, message);
        let mut history = self.log_history.lock().await;
        history.push(entry);
        if history.len() > self.max_history_size {
            history.remove(0);
        }
    }

    // Metrics metodları
    pub fn record_block(&self, height: u64, time_ms: f64) {
        self.metrics.set_gauge(&self.metrics.block_height_name, height as f64);
        self.metrics.record_histogram(&self.metrics.block_time_name, time_ms);
    }

    pub fn record_transaction(&self) {
        self.metrics.increment_counter(&self.metrics.transaction_count_name);
    }

    pub fn update_peer_count(&self, count: f64) {
        self.metrics.set_gauge(&self.metrics.peer_count_name, count);
    }

    pub fn update_shard_load(&self, load: f64) {
        self.metrics.set_gauge(&self.metrics.shard_load_name, load);
    }

    pub fn record_network_latency(&self, latency_ms: f64) {
        self.metrics.record_histogram(&self.metrics.network_latency_name, latency_ms);
    }

    // Log seviyesini güncelle
    pub async fn set_log_level(&self, level: Level) -> Result<(), LoggingError> {
        let mut config = self.config.lock().await;
        config.level = level.to_string();
        Ok(())
    }

    // Log geçmişini al
    pub async fn get_log_history(&self) -> Vec<LogEntry> {
        self.log_history.lock().await.clone()
    }

    // Log geçmişini filtrele
    pub async fn get_filtered_logs(&self, filter: LogFilter) -> Vec<LogEntry> {
        let history = self.log_history.lock().await;
        
        history.iter()
            .filter(|entry| {
                // Seviye filtresi
                let level_match = match filter.min_level.as_str() {
                    "ERROR" => matches!(entry.level.as_str(), "ERROR"),
                    "WARN" => matches!(entry.level.as_str(), "ERROR" | "WARN"),
                    "INFO" => matches!(entry.level.as_str(), "ERROR" | "WARN" | "INFO"),
                    "DEBUG" => true,
                    _ => true,
                };

                // Modül filtresi
                let module_match = if filter.modules.is_empty() {
                    true
                } else {
                    entry.module.as_ref()
                        .map(|m| filter.modules.iter().any(|fm| m.contains(fm)))
                        .unwrap_or(false)
                };

                // Anahtar kelime filtresi
                let keyword_match = if filter.keywords.is_empty() {
                    true
                } else {
                    filter.keywords.iter().any(|kw| entry.message.contains(kw))
                };

                // Zaman aralığı filtresi
                let time_match = if let Some((start, end)) = filter.time_range {
                    entry.timestamp >= start && entry.timestamp <= end
                } else {
                    true
                };

                level_match && module_match && keyword_match && time_match
            })
            .cloned()
            .collect()
    }

    // Log geçmişini temizle
    pub async fn clear_history(&self) {
        self.log_history.lock().await.clear();
    }

    // Metrics verilerini al
    pub async fn get_metrics_summary(&self) -> HashMap<String, f64> {
        let mut summary = HashMap::new();
        
        // Bu gerçek bir implementasyon olmalı - metrics crate'den veri alınmalı
        // Şimdilik boş döndürüyoruz
        summary.insert("total_logs".to_string(), self.log_history.lock().await.len() as f64);
        
        summary
    }

    // Logger yapılandırmasını güncelle
    pub async fn update_config(&self, new_config: LoggingConfig) -> Result<(), LoggingError> {
        let mut config = self.config.lock().await;
        *config = new_config;
        Ok(())
    }

    // Logger'ı kapat
    pub async fn shutdown(&self) -> Result<(), LoggingError> {
        self.info("Logger shutting down").await;
        Ok(())
    }
}

// Logging hata yönetimi
#[derive(Debug)]
pub enum LoggingError {
    InitializationError(String),
    ConfigurationError(String),
    MetricsError(String),
    IoError(String),
}

impl std::fmt::Display for LoggingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoggingError::InitializationError(e) => write!(f, "Initialization error: {}", e),
            LoggingError::ConfigurationError(e) => write!(f, "Configuration error: {}", e),
            LoggingError::MetricsError(e) => write!(f, "Metrics error: {}", e),
            LoggingError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for LoggingError {}

// Test helper functions
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LoggingConfig;

    #[tokio::test]
    async fn test_logger_creation() {
        let config = LoggingConfig {
            level: "INFO".to_string(),
            file: Some("test.log".to_string()),
            enable_metrics: false,
        };

        let logger = Logger::new(config);
        assert!(logger.is_ok());
    }

    #[tokio::test]
    async fn test_log_filtering() {
        let config = LoggingConfig {
            level: "DEBUG".to_string(),
            file: Some("test.log".to_string()),
            enable_metrics: false,
        };

        let logger = Logger::new(config).unwrap();
        
        logger.info("Test info message").await;
        logger.error("Test error message").await;

        let filter = LogFilter {
            min_level: "ERROR".to_string(),
            modules: vec![],
            keywords: vec![],
            time_range: None,
        };

        let filtered_logs = logger.get_filtered_logs(filter).await;
        assert_eq!(filtered_logs.len(), 1);
        assert_eq!(filtered_logs[0].level, "ERROR");
    }
}
