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

#[derive(Clone, Debug)]
pub struct Logger {
    config: Arc<Mutex<LoggingConfig>>,
    metrics: Arc<Metrics>,
}

#[derive(Clone)]
pub struct Metrics {
    pub block_height_name: String,
    pub transaction_count_name: String,
    pub peer_count_name: String,
    pub block_time_name: String,
    pub shard_load_name: String,
    pub network_latency_name: String,
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
        }
    }
}

impl Logger {
    pub fn new(config: LoggingConfig) -> Result<Self, String> {
        // Logging yapılandırması
        let file_appender = if let Some(file) = &config.file {
            RollingFileAppender::new(
                Rotation::DAILY,
                "logs",
                file,
            )
        } else {
            return Err("Log file not specified".to_string());
        };

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // Logging subscriber'ı oluştur
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::from_default_env())
            .with(tracing_subscriber::fmt::layer()
                .with_timer(UtcTime::rfc_3339())
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(non_blocking)
            );

        // Subscriber'ı ayarla
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| e.to_string())?;

        // Metrics yapılandırması
        let metrics = Metrics::new();

        // Prometheus exporter'ı başlat
        PrometheusBuilder::new()
            .with_http_listener(([127, 0, 0, 1], 9000))
            .install()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            metrics: Arc::new(metrics),
        })
    }

    // Logging metodları
    pub fn info(&self, message: &str) {
        info!(message);
    }

    pub fn warn(&self, message: &str) {
        warn!(message);
    }

    pub fn error(&self, message: &str) {
        error!(message);
    }

    pub fn debug(&self, message: &str) {
        debug!(message);
    }

    // Metrics metodları
    pub fn record_block(&self, _height: u64, time_ms: f64) {
        metrics::increment_counter!("block_height");
        metrics::histogram!("block_time", time_ms);
    }

    pub fn record_transaction(&self) {
        metrics::increment_counter!("transaction_count");
    }

    pub fn update_peer_count(&self, count: f64) {
        metrics::gauge!("peer_count", count);
    }

    pub fn update_shard_load(&self, load: f64) {
        metrics::gauge!("shard_load", load);
    }

    pub fn record_network_latency(&self, latency_ms: f64) {
        metrics::histogram!("network_latency", latency_ms);
    }

    // Log seviyesini güncelle
    pub async fn set_log_level(&self, level: Level) {
        let mut config = self.config.lock().await;
        config.level = level.to_string();
    }
}

// Logging hata yönetimi
#[derive(Debug)]
pub enum LoggingError {
    InitializationError(String),
    ConfigurationError(String),
    MetricsError(String),
}

impl std::fmt::Display for LoggingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoggingError::InitializationError(e) => write!(f, "Initialization error: {}", e),
            LoggingError::ConfigurationError(e) => write!(f, "Configuration error: {}", e),
            LoggingError::MetricsError(e) => write!(f, "Metrics error: {}", e),
        }
    }
}

impl std::error::Error for LoggingError {}