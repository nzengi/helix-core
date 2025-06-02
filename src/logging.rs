use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error, debug, Level};
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    prelude::*,
    EnvFilter,
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::{Serialize, Deserialize};
use crate::config::LoggingConfig;

#[derive(Clone, Debug)]
pub struct Logger {
    config: Arc<Mutex<LoggingConfig>>,
    metrics: Arc<Metrics>,
}

#[derive(Clone, Debug)]
pub struct Metrics {
    pub block_height: counter::Counter,
    pub transaction_count: counter::Counter,
    pub peer_count: gauge::Gauge,
    pub block_time: histogram::Histogram,
    pub shard_load: gauge::Gauge,
    pub network_latency: histogram::Histogram,
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
        let metrics = Metrics {
            block_height: counter!("block_height", "Current block height"),
            transaction_count: counter!("transaction_count", "Total transaction count"),
            peer_count: gauge!("peer_count", "Number of connected peers"),
            block_time: histogram!("block_time", "Block creation time"),
            shard_load: gauge!("shard_load", "Current shard load"),
            network_latency: histogram!("network_latency", "Network latency"),
        };

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
    pub fn record_block(&self, height: u64, time_ms: f64) {
        self.metrics.block_height.increment(1);
        self.metrics.block_time.record(time_ms);
    }

    pub fn record_transaction(&self) {
        self.metrics.transaction_count.increment(1);
    }

    pub fn update_peer_count(&self, count: f64) {
        self.metrics.peer_count.set(count);
    }

    pub fn update_shard_load(&self, load: f64) {
        self.metrics.shard_load.set(load);
    }

    pub fn record_network_latency(&self, latency_ms: f64) {
        self.metrics.network_latency.record(latency_ms);
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