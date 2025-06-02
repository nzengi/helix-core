use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use chrono::{DateTime, Utc};
use prometheus::{Counter, Gauge, Histogram, Registry};
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

pub struct MetricsManager {
    metrics: Arc<Mutex<HashMap<String, VecDeque<Metric>>>>,
    configs: Arc<Mutex<HashMap<String, MetricConfig>>>,
    alerts: Arc<Mutex<HashMap<String, Alert>>>,
    registry: Registry,
    counters: Arc<Mutex<HashMap<String, Counter>>>,
    gauges: Arc<Mutex<HashMap<String, Gauge>>>,
    histograms: Arc<Mutex<HashMap<String, Histogram>>>,
    alert_handlers: Arc<Mutex<Vec<Box<dyn AlertHandler>>>>,
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
        }
    }

    pub async fn register_metric(&self, config: MetricConfig) -> Result<(), MetricsError> {
        let mut configs = self.configs.lock().await;
        configs.insert(config.name.clone(), config.clone());

        match config.metric_type {
            MetricType::Counter => {
                let counter = Counter::new(&config.name, &config.description)?;
                self.registry.register(Box::new(counter.clone()))?;
                let mut counters = self.counters.lock().await;
                counters.insert(config.name, counter);
            }
            MetricType::Gauge => {
                let gauge = Gauge::new(&config.name, &config.description)?;
                self.registry.register(Box::new(gauge.clone()))?;
                let mut gauges = self.gauges.lock().await;
                gauges.insert(config.name, gauge);
            }
            MetricType::Histogram => {
                let histogram = Histogram::with_opts(
                    prometheus::opts!(&config.name, &config.description)
                )?;
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
            if Utc::now() - old_metric.timestamp > config.retention_period {
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

    pub async fn export_metrics(&self) -> Result<Vec<u8>, MetricsError> {
        let mut buffer = vec![];
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(buffer)
    }

    async fn check_alerts(&self, metric_name: &str, value: f64) -> Result<(), MetricsError> {
        let alerts = self.alerts.lock().await;
        for alert in alerts.values() {
            if let AlertCondition::Threshold { metric, operator, value: threshold, duration } = &alert.condition {
                if metric == metric_name {
                    let triggered = match operator {
                        ThresholdOperator::GreaterThan => value > *threshold,
                        ThresholdOperator::LessThan => value < *threshold,
                        ThresholdOperator::EqualTo => value == *threshold,
                        ThresholdOperator::NotEqualTo => value != *threshold,
                    };

                    if triggered {
                        self.handle_alert(alert, value).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_alert(&self, alert: &Alert, value: f64) -> Result<(), MetricsError> {
        let mut alerts = self.alerts.lock().await;
        if let Some(alert) = alerts.get_mut(&alert.name) {
            alert.status = AlertStatus::Firing;
            alert.last_triggered = Some(Utc::now());

            // Alert handler'ları çağır
            let handlers = self.alert_handlers.lock().await;
            for handler in handlers.iter() {
                handler.handle_alert(alert, value).await?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait AlertHandler: Send + Sync {
    async fn handle_alert(&self, alert: &Alert, value: f64) -> Result<(), MetricsError>;
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
    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
} 