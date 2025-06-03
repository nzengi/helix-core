
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use reqwest::Client;
use tokio::time::sleep;
use rand::{rngs::OsRng, RngCore};
use sha3::{Keccak256, Digest};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Oracle {
    pub address: String,
    pub name: String,
    pub description: String,
    pub data_sources: Vec<DataSource>,
    pub validators: Vec<String>,
    pub min_validators: u32,
    pub update_interval: Duration,
    pub last_update: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub parser: DataParser,
    pub weight: u32,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataParser {
    pub parser_type: ParserType,
    pub path: String,
    pub data_type: DataType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParserType {
    Json,
    Xml,
    Csv,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    Number,
    String,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub oracle_address: String,
    pub timestamp: u64,
    pub value: String,
    pub signatures: Vec<Signature>,
    pub round_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub validator: String,
    pub signature: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFRequest {
    pub seed: [u8; 32],
    pub callback_address: String,
    pub callback_function: String,
    pub num_words: u32,
    pub request_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFResponse {
    pub request_id: u64,
    pub proof: Vec<u8>,
    pub random_words: Vec<[u8; 32]>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VRFProof {
    pub gamma: Vec<u8>,
    pub c: Vec<u8>,
    pub s: Vec<u8>,
}

pub struct OracleManager {
    oracles: Arc<Mutex<HashMap<String, Oracle>>>,
    data_points: Arc<Mutex<HashMap<String, Vec<DataPoint>>>>,
    vrf_requests: Arc<Mutex<HashMap<u64, VRFRequest>>>,
    vrf_responses: Arc<Mutex<HashMap<u64, VRFResponse>>>,
    client: Client,
}

impl OracleManager {
    pub fn new() -> Self {
        Self {
            oracles: Arc::new(Mutex::new(HashMap::new())),
            data_points: Arc::new(Mutex::new(HashMap::new())),
            vrf_requests: Arc::new(Mutex::new(HashMap::new())),
            vrf_responses: Arc::new(Mutex::new(HashMap::new())),
            client: Client::new(),
        }
    }

    pub async fn create_oracle(
        &self,
        name: String,
        description: String,
        data_sources: Vec<DataSource>,
        validators: Vec<String>,
        min_validators: u32,
        update_interval: Duration,
    ) -> Result<Oracle, OracleError> {
        if validators.len() < min_validators as usize {
            return Err(OracleError::InvalidData);
        }

        let address = self.generate_oracle_address(&name)?;

        let oracle = Oracle {
            address: address.clone(),
            name,
            description,
            data_sources,
            validators,
            min_validators,
            update_interval,
            last_update: 0,
            active: true,
        };

        let mut oracles = self.oracles.lock().await;
        oracles.insert(address.clone(), oracle.clone());

        tracing::info!("Created oracle {} with address {}", oracle.name, address);
        Ok(oracle)
    }

    pub async fn get_oracle(&self, address: &str) -> Result<Oracle, OracleError> {
        let oracles = self.oracles.lock().await;
        oracles.get(address)
            .cloned()
            .ok_or(OracleError::OracleNotFound)
    }

    pub async fn update_data(&self, oracle_address: &str) -> Result<DataPoint, OracleError> {
        let oracles = self.oracles.lock().await;
        let oracle = oracles.get(oracle_address)
            .ok_or(OracleError::OracleNotFound)?;

        if !oracle.active {
            return Err(OracleError::ServiceUnavailable);
        }

        let mut values = Vec::new();
        let mut weights = Vec::new();

        // Fetch data from all sources
        for source in &oracle.data_sources {
            match self.fetch_data(source).await {
                Ok(value) => {
                    values.push(value);
                    weights.push(source.weight);
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch data from source {}: {}", source.url, e);
                }
            }
        }

        if values.is_empty() {
            return Err(OracleError::NoDataAvailable);
        }

        // Calculate weighted average
        let weighted_value = self.calculate_weighted_average(&values, &weights)?;

        // Create new data point
        let data_point = DataPoint {
            oracle_address: oracle_address.to_string(),
            timestamp: Utc::now().timestamp() as u64,
            value: weighted_value,
            signatures: Vec::new(),
            round_id: self.get_next_round_id(oracle_address).await?,
        };

        // Store data point
        let mut data_points = self.data_points.lock().await;
        data_points.entry(oracle_address.to_string())
            .or_insert_with(Vec::new)
            .push(data_point.clone());

        tracing::info!("Updated data for oracle {}", oracle_address);
        Ok(data_point)
    }

    pub async fn get_latest_data(&self, oracle_address: &str) -> Result<DataPoint, OracleError> {
        let data_points = self.data_points.lock().await;
        let points = data_points.get(oracle_address)
            .ok_or(OracleError::OracleNotFound)?;

        points.last()
            .cloned()
            .ok_or(OracleError::NoDataAvailable)
    }

    pub async fn request_vrf(
        &self,
        seed: [u8; 32],
        callback_address: String,
        callback_function: String,
        num_words: u32,
    ) -> Result<VRFRequest, OracleError> {
        let request_id = self.generate_request_id()?;

        let request = VRFRequest {
            seed,
            callback_address,
            callback_function,
            num_words,
            request_id,
        };

        let mut requests = self.vrf_requests.lock().await;
        requests.insert(request_id, request.clone());

        // Start VRF calculation
        self.start_vrf_calculation(request_id, seed, num_words).await?;

        tracing::info!("Created VRF request {}", request_id);
        Ok(request)
    }

    pub async fn get_vrf_response(&self, request_id: u64) -> Result<VRFResponse, OracleError> {
        let responses = self.vrf_responses.lock().await;
        responses.get(&request_id)
            .cloned()
            .ok_or(OracleError::RequestNotFound)
    }

    pub async fn verify_vrf_response(
        &self,
        response: &VRFResponse,
    ) -> Result<bool, OracleError> {
        let requests = self.vrf_requests.lock().await;
        let request = requests.get(&response.request_id)
            .ok_or(OracleError::RequestNotFound)?;

        // Verify VRF proof
        self.verify_vrf_proof(&response.proof, &request.seed)?;

        // Verify random words count
        if response.random_words.len() != request.num_words as usize {
            return Err(OracleError::VrfVerificationFailed);
        }

        // Verify signature
        self.verify_signature(&response.signature, &response.random_words)?;

        Ok(true)
    }

    async fn fetch_data(&self, source: &DataSource) -> Result<String, OracleError> {
        let mut request_builder = match source.method.as_str() {
            "GET" => self.client.get(&source.url),
            "POST" => self.client.post(&source.url),
            "PUT" => self.client.put(&source.url),
            "DELETE" => self.client.delete(&source.url),
            _ => self.client.get(&source.url),
        };

        // Add headers
        for (key, value) in &source.headers {
            request_builder = request_builder.header(key, value);
        }

        let response = request_builder
            .timeout(source.timeout)
            .send()
            .await
            .map_err(|e| OracleError::NetworkError(e))?;

        if !response.status().is_success() {
            return Err(OracleError::HttpError(format!("HTTP {}", response.status())));
        }

        let data = response.text().await
            .map_err(|e| OracleError::NetworkError(e))?;

        self.parse_data(&data, &source.parser)
    }

    fn parse_data(&self, data: &str, parser: &DataParser) -> Result<String, OracleError> {
        match parser.parser_type {
            ParserType::Json => {
                let json: serde_json::Value = serde_json::from_str(data)
                    .map_err(|e| OracleError::ParseFailure(e.to_string()))?;
                
                let value = json.pointer(&parser.path)
                    .ok_or(OracleError::ParseError)?;
                
                Ok(match parser.data_type {
                    DataType::Number => value.as_f64().unwrap_or(0.0).to_string(),
                    DataType::String => value.as_str().unwrap_or("").to_string(),
                    DataType::Boolean => value.as_bool().unwrap_or(false).to_string(),
                    _ => value.to_string(),
                })
            }
            ParserType::Xml => {
                // Basic XML parsing implementation
                if parser.path.is_empty() {
                    return Ok(data.to_string());
                }
                
                // Simple tag extraction
                let tag = &parser.path;
                if let Some(start) = data.find(&format!("<{}>", tag)) {
                    if let Some(end) = data.find(&format!("</{}>", tag)) {
                        let start_pos = start + tag.len() + 2;
                        if start_pos < end {
                            return Ok(data[start_pos..end].to_string());
                        }
                    }
                }
                
                Err(OracleError::ParseError)
            }
            ParserType::Csv => {
                // Basic CSV parsing implementation
                let lines: Vec<&str> = data.lines().collect();
                if lines.is_empty() {
                    return Err(OracleError::ParseError);
                }
                
                // Parse path as "row,column"
                let parts: Vec<&str> = parser.path.split(',').collect();
                if parts.len() != 2 {
                    return Err(OracleError::ParseError);
                }
                
                let row: usize = parts[0].parse().map_err(|_| OracleError::ParseError)?;
                let col: usize = parts[1].parse().map_err(|_| OracleError::ParseError)?;
                
                if row >= lines.len() {
                    return Err(OracleError::ParseError);
                }
                
                let columns: Vec<&str> = lines[row].split(',').collect();
                if col >= columns.len() {
                    return Err(OracleError::ParseError);
                }
                
                Ok(columns[col].trim().to_string())
            }
            ParserType::Custom(ref script) => {
                // Basic custom parsing - simple string replacement/extraction
                if script.starts_with("extract:") {
                    let pattern = &script[8..];
                    if let Some(pos) = data.find(pattern) {
                        let start = pos + pattern.len();
                        let end = data[start..].find(' ').unwrap_or(data.len() - start) + start;
                        return Ok(data[start..end].to_string());
                    }
                }
                
                Err(OracleError::NotImplemented)
            }
        }
    }

    fn calculate_weighted_average(
        &self,
        values: &[String],
        weights: &[u32],
    ) -> Result<String, OracleError> {
        if values.len() != weights.len() || values.is_empty() {
            return Err(OracleError::InvalidData);
        }

        let mut total_weight = 0u64;
        let mut weighted_sum = 0f64;

        for (value, &weight) in values.iter().zip(weights) {
            let num_value: f64 = value.parse()
                .map_err(|e: std::num::ParseFloatError| OracleError::DataError(e.to_string()))?;
            weighted_sum += num_value * weight as f64;
            total_weight += weight as u64;
        }

        if total_weight == 0 {
            return Err(OracleError::InvalidData);
        }

        Ok((weighted_sum / total_weight as f64).to_string())
    }

    async fn start_vrf_calculation(&self, request_id: u64, seed: [u8; 32], num_words: u32) -> Result<(), OracleError> {
        // Generate VRF proof and random words
        let proof = self.generate_vrf_proof(&seed)?;
        let random_words = self.generate_random_words(&seed, num_words)?;
        let signature = self.sign_vrf_output(&random_words)?;

        let response = VRFResponse {
            request_id,
            proof,
            random_words,
            signature,
        };

        let mut responses = self.vrf_responses.lock().await;
        responses.insert(request_id, response);

        tracing::info!("Generated VRF response for request {}", request_id);
        Ok(())
    }

    fn generate_vrf_proof(&self, seed: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        // Simplified VRF proof generation
        let mut hasher = Keccak256::new();
        hasher.update(seed);
        hasher.update(b"vrf_proof");
        Ok(hasher.finalize().to_vec())
    }

    fn generate_random_words(&self, seed: &[u8; 32], num_words: u32) -> Result<Vec<[u8; 32]>, OracleError> {
        let mut words = Vec::new();
        
        for i in 0..num_words {
            let mut hasher = Keccak256::new();
            hasher.update(seed);
            hasher.update(&i.to_be_bytes());
            hasher.update(b"random_word");
            
            let hash = hasher.finalize();
            let mut word = [0u8; 32];
            word.copy_from_slice(&hash);
            words.push(word);
        }
        
        Ok(words)
    }

    fn sign_vrf_output(&self, words: &[[u8; 32]]) -> Result<String, OracleError> {
        let mut hasher = Keccak256::new();
        for word in words {
            hasher.update(word);
        }
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    fn verify_vrf_proof(&self, proof: &[u8], seed: &[u8; 32]) -> Result<(), OracleError> {
        // Verify the proof was generated from the seed
        let mut hasher = Keccak256::new();
        hasher.update(seed);
        hasher.update(b"vrf_proof");
        let expected = hasher.finalize();

        if proof == expected.as_slice() {
            Ok(())
        } else {
            Err(OracleError::VrfVerificationFailed)
        }
    }

    fn verify_random_words(&self, words: &[[u8; 32]], _proof: &[u8]) -> Result<(), OracleError> {
        // Verify words are properly formatted
        if words.is_empty() {
            return Err(OracleError::VrfVerificationFailed);
        }
        Ok(())
    }

    fn verify_signature(&self, signature: &str, data: &[[u8; 32]]) -> Result<(), OracleError> {
        // Verify signature matches the data
        let mut hasher = Keccak256::new();
        for word in data {
            hasher.update(word);
        }
        let expected = hex::encode(hasher.finalize());

        if signature == expected {
            Ok(())
        } else {
            Err(OracleError::InvalidSignature)
        }
    }

    fn generate_oracle_address(&self, name: &str) -> Result<String, OracleError> {
        let mut hasher = Keccak256::new();
        hasher.update(name.as_bytes());
        hasher.update(&Utc::now().timestamp().to_be_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&result[12..])))
    }

    async fn get_next_round_id(&self, oracle_address: &str) -> Result<u64, OracleError> {
        let data_points = self.data_points.lock().await;
        let empty_vec = Vec::new();
        let points = data_points.get(oracle_address).unwrap_or(&empty_vec);
        Ok(points.len() as u64 + 1)
    }

    fn generate_request_id(&self) -> Result<u64, OracleError> {
        let mut rng = OsRng;
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        Ok(u64::from_be_bytes(bytes))
    }

    pub async fn deactivate_oracle(&self, address: &str) -> Result<(), OracleError> {
        let mut oracles = self.oracles.lock().await;
        if let Some(oracle) = oracles.get_mut(address) {
            oracle.active = false;
            tracing::info!("Deactivated oracle {}", address);
            Ok(())
        } else {
            Err(OracleError::OracleNotFound)
        }
    }

    pub async fn list_oracles(&self) -> Vec<Oracle> {
        let oracles = self.oracles.lock().await;
        oracles.values().cloned().collect()
    }

    pub async fn get_oracle_history(&self, address: &str, limit: Option<usize>) -> Result<Vec<DataPoint>, OracleError> {
        let data_points = self.data_points.lock().await;
        let points = data_points.get(address)
            .ok_or(OracleError::OracleNotFound)?;

        let mut history = points.clone();
        history.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            history.truncate(limit);
        }

        Ok(history)
    }
}

impl Default for OracleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("Oracle not found")]
    OracleNotFound,
    #[error("Request not found")]
    RequestNotFound,
    #[error("No data available")]
    NoDataAvailable,
    #[error("Invalid data")]
    InvalidData,
    #[error("Parse error")]
    ParseError,
    #[error("Not implemented")]
    NotImplemented,
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Invalid method: {0}")]
    InvalidMethod(String),
    #[error("Timeout")]
    Timeout,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Data error: {0}")]
    DataError(String),
    #[error("Authorization failed")]
    Unauthorized,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Service unavailable")]
    ServiceUnavailable,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("VRF verification failed")]
    VrfVerificationFailed,
    #[error("Network connection error: {0}")]
    ConnectionError(String),
    #[error("HTTP error: {0}")]
    HttpError(String),
    #[error("Parse failure: {0}")]
    ParseFailure(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_oracle_creation() {
        let manager = OracleManager::new();
        
        let oracle = manager.create_oracle(
            "Test Oracle".to_string(),
            "Test Description".to_string(),
            vec![],
            vec!["validator1".to_string()],
            1,
            Duration::from_secs(60),
        ).await.unwrap();

        assert_eq!(oracle.name, "Test Oracle");
        assert!(oracle.active);
    }

    #[tokio::test]
    async fn test_vrf_request() {
        let manager = OracleManager::new();
        let seed = [1u8; 32];
        
        let request = manager.request_vrf(
            seed,
            "callback_address".to_string(),
            "callback_function".to_string(),
            3,
        ).await.unwrap();

        assert_eq!(request.num_words, 3);
        assert_eq!(request.seed, seed);
    }

    #[tokio::test]
    async fn test_weighted_average() {
        let manager = OracleManager::new();
        let values = vec!["10.0".to_string(), "20.0".to_string()];
        let weights = vec![1, 3];
        
        let result = manager.calculate_weighted_average(&values, &weights).unwrap();
        let expected = (10.0 * 1.0 + 20.0 * 3.0) / 4.0;
        
        assert_eq!(result, expected.to_string());
    }
}
