use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use chrono::{DateTime, Utc};
use prometheus::{Counter, Gauge, Histogram, Registry, Opts};
use prometheus::core::{AtomicF64, AtomicU64};
use prometheus::proto::MetricFamily;
use prometheus::Encoder;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub metric_type: MetricType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricConfig {
    pub name: String,
    pub description: String,
    pub metric_type: MetricType,
    pub labels: Vec<String>,
    pub interval: Duration,
    pub retention_period: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub name: String,
    pub description: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub last_triggered: Option<DateTime<Utc>>,
    pub last_resolved: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    Threshold {
        metric: String,
        operator: ThresholdOperator,
        value: f64,
        duration: Duration,
    },
    Rate {
        metric: String,
        operator: ThresholdOperator,
        value: f64,
        window: Duration,
    },
    Anomaly {
        metric: String,
        deviation: f64,
        window: Duration,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdOperator {
    GreaterThan,
    LessThan,
    EqualTo,
    NotEqualTo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    Firing,
    Resolved,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_in: f64,
    pub network_out: f64,
    pub active_connections: u64,
    pub transaction_throughput: f64,
    pub block_time: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub peer_count: u64,
    pub message_count: u64,
    pub bandwidth_usage: f64,
    pub latency_ms: f64,
    pub dropped_connections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainMetrics {
    pub block_height: u64,
    pub pending_transactions: u64,
    pub confirmed_transactions: u64,
    pub validator_count: u64,
    pub staking_ratio: f64,
    pub gas_price: f64,
}

pub struct MetricsManager {
    metrics: Arc<Mutex<HashMap<String, VecDeque<Metric>>>>,
    configs: Arc<Mutex<HashMap<String, MetricConfig>>>,
    alerts: Arc<Mutex<HashMap<String, Alert>>>,
    registry: Registry,
    counters: Arc<Mutex<HashMap<String, Counter>>>,
    gauges: Arc<Mutex<HashMap<String, Gauge>>>,
    histograms: Arc<Mutex<HashMap<String, Histogram>>>,
    alert_handlers: Arc<Mutex<Vec<Box<dyn AlertHandler>>>>,
    performance_metrics: Arc<Mutex<PerformanceMetrics>>,
    network_metrics: Arc<Mutex<NetworkMetrics>>,
    blockchain_metrics: Arc<Mutex<BlockchainMetrics>>,
}

impl MetricsManager {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(HashMap::new())),
            configs: Arc::new(Mutex::new(HashMap::new())),
            alerts: Arc::new(Mutex::new(HashMap::new())),
            registry: Registry::new(),
            counters: Arc::new(Mutex::new(HashMap::new())),
            gauges: Arc::new(Mutex::new(HashMap::new())),
            histograms: Arc::new(Mutex::new(HashMap::new())),
            alert_handlers: Arc::new(Mutex::new(Vec::new())),
            performance_metrics: Arc::new(Mutex::new(PerformanceMetrics {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                disk_usage: 0.0,
                network_in: 0.0,
                network_out: 0.0,
                active_connections: 0,
                transaction_throughput: 0.0,
                block_time: 0.0,
            })),
            network_metrics: Arc::new(Mutex::new(NetworkMetrics {
                peer_count: 0,
                message_count: 0,
                bandwidth_usage: 0.0,
                latency_ms: 0.0,
                dropped_connections: 0,
            })),
            blockchain_metrics: Arc::new(Mutex::new(BlockchainMetrics {
                block_height: 0,
                pending_transactions: 0,
                confirmed_transactions: 0,
                validator_count: 0,
                staking_ratio: 0.0,
                gas_price: 0.0,
            })),
        }
    }

    pub async fn register_metric(&self, config: MetricConfig) -> Result<(), MetricsError> {
        let mut configs = self.configs.lock().await;
        configs.insert(config.name.clone(), config.clone());

        match config.metric_type {
            MetricType::Counter => {
                let counter = Counter::with_opts(Opts::new(&config.name, &config.description))?;
                self.registry.register(Box::new(counter.clone()))?;
                let mut counters = self.counters.lock().await;
                counters.insert(config.name, counter);
            }
            MetricType::Gauge => {
                let gauge = Gauge::with_opts(Opts::new(&config.name, &config.description))?;
                self.registry.register(Box::new(gauge.clone()))?;
                let mut gauges = self.gauges.lock().await;
                gauges.insert(config.name, gauge);
            }
            MetricType::Histogram => {
                let histogram = Histogram::with_opts(Opts::new(&config.name, &config.description))?;
                self.registry.register(Box::new(histogram.clone()))?;
                let mut histograms = self.histograms.lock().await;
                histograms.insert(config.name, histogram);
            }
        }

        Ok(())
    }

    pub async fn record_metric(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<(), MetricsError> {
        let configs = self.configs.lock().await;
        let config = configs.get(name).ok_or(MetricsError::MetricNotFound)?;

        let metric = Metric {
            name: name.to_string(),
            value,
            timestamp: Utc::now(),
            labels,
            metric_type: config.metric_type.clone(),
        };

        // Metriği kaydet
        let mut metrics = self.metrics.lock().await;
        let metric_queue = metrics.entry(name.to_string())
            .or_insert_with(|| VecDeque::with_capacity(1000));
        metric_queue.push_back(metric);

        // Retention period kontrolü
        while let Some(old_metric) = metric_queue.front() {
            if Utc::now() - old_metric.timestamp > chrono::Duration::from_std(config.retention_period).unwrap_or_default() {
                metric_queue.pop_front();
            } else {
                break;
            }
        }

        // Prometheus metriğini güncelle
        match config.metric_type {
            MetricType::Counter => {
                let counters = self.counters.lock().await;
                if let Some(counter) = counters.get(name) {
                    counter.inc_by(value);
                }
            }
            MetricType::Gauge => {
                let gauges = self.gauges.lock().await;
                if let Some(gauge) = gauges.get(name) {
                    gauge.set(value);
                }
            }
            MetricType::Histogram => {
                let histograms = self.histograms.lock().await;
                if let Some(histogram) = histograms.get(name) {
                    histogram.observe(value);
                }
            }
        }

        // Alert kontrolü
        self.check_alerts(name, value).await?;

        Ok(())
    }

    pub async fn register_alert(&self, alert: Alert) -> Result<(), MetricsError> {
        let mut alerts = self.alerts.lock().await;
        alerts.insert(alert.name.clone(), alert);
        Ok(())
    }

    pub async fn add_alert_handler(&self, handler: Box<dyn AlertHandler>) {
        let mut handlers = self.alert_handlers.lock().await;
        handlers.push(handler);
    }

    pub async fn get_metric_history(
        &self,
        name: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
    ) -> Result<Vec<Metric>, MetricsError> {
        let metrics = self.metrics.lock().await;
        let metric_queue = metrics.get(name).ok_or(MetricsError::MetricNotFound)?;

        let history: Vec<Metric> = metric_queue.iter()
            .filter(|metric| metric.timestamp >= start_time && metric.timestamp <= end_time)
            .cloned()
            .collect();

        Ok(history)
    }

    pub async fn get_alert_status(&self, name: &str) -> Result<Alert, MetricsError> {
        let alerts = self.alerts.lock().await;
        let alert = alerts.get(name).ok_or(MetricsError::AlertNotFound)?.clone();
        Ok(alert)
    }

    pub async fn get_all_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.lock().await;
        alerts.values().cloned().collect()
    }

    pub async fn export_metrics(&self) -> Result<Vec<u8>, MetricsError> {
        let mut buffer = vec![];
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }

    pub async fn update_performance_metrics(&self, metrics: PerformanceMetrics) {
        let mut perf = self.performance_metrics.lock().await;
        *perf = metrics;
    }

    pub async fn update_network_metrics(&self, metrics: NetworkMetrics) {
        let mut net = self.network_metrics.lock().await;
        *net = metrics;
    }

    pub async fn update_blockchain_metrics(&self, metrics: BlockchainMetrics) {
        let mut bc = self.blockchain_metrics.lock().await;
        *bc = metrics;
    }

    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.lock().await.clone()
    }

    pub async fn get_network_metrics(&self) -> NetworkMetrics {
        self.network_metrics.lock().await.clone()
    }

    pub async fn get_blockchain_metrics(&self) -> BlockchainMetrics {
        self.blockchain_metrics.lock().await.clone()
    }

    pub async fn get_system_health(&self) -> SystemHealth {
        let perf = self.get_performance_metrics().await;
        let net = self.get_network_metrics().await;
        let bc = self.get_blockchain_metrics().await;

        let mut health_score = 1.0;

        // CPU kullanımı kontrolü
        if perf.cpu_usage > 80.0 {
            health_score -= 0.2;
        }

        // Memory kullanımı kontrolü
        if perf.memory_usage > 85.0 {
            health_score -= 0.2;
        }

        // Network latency kontrolü
        if net.latency_ms > 1000.0 {
            health_score -= 0.2;
        }

        // Peer count kontrolü
        if net.peer_count < 3 {
            health_score -= 0.2;
        }

        // Block time kontrolü
        if perf.block_time > 15000.0 {
            health_score -= 0.2;
        }

        health_score = health_score.max(0.0);

        SystemHealth {
            score: health_score,
            status: if health_score >= 0.8 {
                HealthStatus::Healthy
            } else if health_score >= 0.5 {
                HealthStatus::Warning
            } else {
                HealthStatus::Critical
            },
            last_check: Utc::now(),
            issues: self.detect_issues(&perf, &net, &bc).await,
        }
    }

    async fn detect_issues(&self, perf: &PerformanceMetrics, net: &NetworkMetrics, _bc: &BlockchainMetrics) -> Vec<String> {
        let mut issues = Vec::new();

        if perf.cpu_usage > 80.0 {
            issues.push("High CPU usage detected".to_string());
        }

        if perf.memory_usage > 85.0 {
            issues.push("High memory usage detected".to_string());
        }

        if net.latency_ms > 1000.0 {
            issues.push("High network latency detected".to_string());
        }

        if net.peer_count < 3 {
            issues.push("Low peer count".to_string());
        }

        if perf.block_time > 15000.0 {
            issues.push("Slow block production".to_string());
        }

        issues
    }

    async fn check_alerts(&self, metric_name: &str, value: f64) -> Result<(), MetricsError> {
        let mut alerts = self.alerts.lock().await;
        let alert_names: Vec<String> = alerts.keys().cloned().collect();

        for alert_name in alert_names {
            if let Some(alert) = alerts.get(&alert_name) {
                let alert_clone = alert.clone();
                if let AlertCondition::Threshold { metric, operator, value: threshold, duration: _ } = &alert_clone.condition {
                    if metric == metric_name {
                        let triggered = match operator {
                            ThresholdOperator::GreaterThan => value > *threshold,
                            ThresholdOperator::LessThan => value < *threshold,
                            ThresholdOperator::EqualTo => (value - threshold).abs() < f64::EPSILON,
                            ThresholdOperator::NotEqualTo => (value - threshold).abs() > f64::EPSILON,
                        };

                        if triggered {
                            if let Some(alert) = alerts.get_mut(&alert_name) {
                                alert.status = AlertStatus::Firing;
                                alert.last_triggered = Some(Utc::now());
                            }
                            self.handle_alert(&alert_clone, value).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_alert(&self, alert: &Alert, value: f64) -> Result<(), MetricsError> {
        // Alert handler'ları çağır
        let handlers = self.alert_handlers.lock().await;
        for handler in handlers.iter() {
            handler.handle_alert(alert, value).await?;
        }

        tracing::warn!(
            alert_name = alert.name,
            alert_severity = ?alert.severity,
            metric_value = value,
            "Alert triggered"
        );

        Ok(())
    }

    pub async fn start_monitoring(&self) -> Result<(), MetricsError> {
        let metrics_manager = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                // System metrics toplama
                if let Ok(cpu_usage) = Self::get_cpu_usage().await {
                    let _ = metrics_manager.record_metric(
                        "system_cpu_usage",
                        cpu_usage,
                        HashMap::new(),
                    ).await;
                }

                if let Ok(memory_usage) = Self::get_memory_usage().await {
                    let _ = metrics_manager.record_metric(
                        "system_memory_usage",
                        memory_usage,
                        HashMap::new(),
                    ).await;
                }
            }
        });

        Ok(())
    }

    async fn get_cpu_usage() -> Result<f64, MetricsError> {
        // CPU kullanımını sistem çağrıları ile al
        // Basit implementasyon - gerçekte /proc/stat okuma yapılabilir
        Ok(std::process::Command::new("sh")
            .arg("-c")
            .arg("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
            .output()
            .map_err(|e| MetricsError::SystemError(e.to_string()))?
            .stdout
            .iter()
            .take_while(|&&b| b != b'\n')
            .map(|&b| b as char)
            .collect::<String>()
            .parse()
            .unwrap_or(0.0))
    }

    async fn get_memory_usage() -> Result<f64, MetricsError> {
        // Memory kullanımını sistem çağrıları ile al
        Ok(std::process::Command::new("sh")
            .arg("-c")
            .arg("free | grep Mem | awk '{printf \"%.2f\", $3/$2 * 100.0}'")
            .output()
            .map_err(|e| MetricsError::SystemError(e.to_string()))?
            .stdout
            .iter()
            .take_while(|&&b| b != b'\n')
            .map(|&b| b as char)
            .collect::<String>()
            .parse()
            .unwrap_or(0.0))
    }
}

impl Clone for MetricsManager {
    fn clone(&self) -> Self {
        Self {
            metrics: Arc::clone(&self.metrics),
            configs: Arc::clone(&self.configs),
            alerts: Arc::clone(&self.alerts),
            registry: Registry::new(),
            counters: Arc::clone(&self.counters),
            gauges: Arc::clone(&self.gauges),
            histograms: Arc::clone(&self.histograms),
            alert_handlers: Arc::clone(&self.alert_handlers),
            performance_metrics: Arc::clone(&self.performance_metrics),
            network_metrics: Arc::clone(&self.network_metrics),
            blockchain_metrics: Arc::clone(&self.blockchain_metrics),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub score: f64,
    pub status: HealthStatus,
    pub last_check: DateTime<Utc>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

#[async_trait::async_trait]
pub trait AlertHandler: Send + Sync {
    async fn handle_alert(&self, alert: &Alert, value: f64) -> Result<(), MetricsError>;
}

pub struct ConsoleAlertHandler;

#[async_trait::async_trait]
impl AlertHandler for ConsoleAlertHandler {
    async fn handle_alert(&self, alert: &Alert, value: f64) -> Result<(), MetricsError> {
        println!(
            "[ALERT] {} - {} (Value: {}) - Severity: {:?}",
            alert.name,
            alert.description,
            value,
            alert.severity
        );
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Metric not found")]
    MetricNotFound,
    #[error("Alert not found")]
    AlertNotFound,
    #[error("Invalid metric type")]
    InvalidMetricType,
    #[error("Invalid alert condition")]
    InvalidAlertCondition,
    #[error("Invalid threshold operator")]
    InvalidThresholdOperator,
    #[error("Invalid alert severity")]
    InvalidAlertSeverity,
    #[error("Invalid alert status")]
    InvalidAlertStatus,
    #[error("System error: {0}")]
    SystemError(String),
    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

impl Default for MetricsManager {
    fn default() -> Self {
        Self::new()
    }
}