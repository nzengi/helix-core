
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use crate::consensus::{Block, Transaction};

// Network yapıları
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkState {
    #[serde(skip)]
    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    #[serde(skip)]
    pub bootstrap_nodes: Arc<Mutex<Vec<String>>>,
    #[serde(skip)]
    pub node_info: Arc<Mutex<NodeInfo>>,
    #[serde(skip)]
    pub connection_manager: Arc<Mutex<ConnectionManager>>,
    #[serde(skip)]
    pub listener: Arc<Mutex<Option<TcpListener>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub port: u16,
    pub last_seen: u64,
    pub latency: u64,
    pub version: String,
    pub capabilities: HashSet<String>,
    pub failed_attempts: u32,
    pub reputation: f64,
    pub uptime: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeInfo {
    pub address: String,
    pub port: u16,
    pub version: String,
    pub capabilities: HashSet<String>,
    pub last_sync: u64,
    pub node_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionManager {
    pub active_connections: HashMap<String, Connection>,
    pub connection_pool: HashMap<String, Connection>,
    pub max_connections: u32,
    pub connection_timeout: Duration,
    pub reconnect_attempts: u32,
    pub bandwidth_limit: u64,
}

#[derive(Clone, Debug)]
pub struct Connection {
    pub peer_id: String,
    pub address: SocketAddr,
    pub last_activity: u64,
    pub status: ConnectionStatus,
    pub retry_count: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_time: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionStatus {
    Connected,
    Connecting,
    Disconnected,
    Failed,
    Handshaking,
    Authenticated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Handshake {
        version: String,
        node_id: String,
        capabilities: HashSet<String>,
    },
    HandshakeResponse {
        accepted: bool,
        reason: Option<String>,
    },
    Ping {
        timestamp: u64,
        nonce: u64,
    },
    Pong {
        timestamp: u64,
        nonce: u64,
    },
    Transaction(Transaction),
    Block(Block),
    BlockRequest {
        hash: String,
    },
    BlockResponse {
        block: Option<Block>,
    },
    PeerDiscovery {
        peers: Vec<PeerInfo>,
    },
    SyncRequest {
        from_height: u64,
        to_height: Option<u64>,
    },
    SyncResponse {
        blocks: Vec<Block>,
        has_more: bool,
    },
    Disconnect {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub uptime: u64,
    pub network_health: f64,
}

impl NetworkState {
    pub fn new() -> Self {
        let mut capabilities = HashSet::new();
        capabilities.insert("consensus".to_string());
        capabilities.insert("blockchain".to_string());
        capabilities.insert("p2p".to_string());

        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            bootstrap_nodes: Arc::new(Mutex::new(Vec::new())),
            node_info: Arc::new(Mutex::new(NodeInfo {
                address: "0.0.0.0".to_string(),
                port: 8000,
                version: "1.0.0".to_string(),
                capabilities,
                last_sync: 0,
                node_id: Self::generate_node_id(),
                public_key: String::new(),
            })),
            connection_manager: Arc::new(Mutex::new(ConnectionManager::new())),
            listener: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start_listening(&self, port: u16) -> Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        
        {
            let mut node_info = self.node_info.lock().await;
            node_info.port = port;
            node_info.address = "0.0.0.0".to_string();
        }

        {
            let mut listener_guard = self.listener.lock().await;
            *listener_guard = Some(listener);
        }

        tracing::info!("Network listening on {}", addr);
        
        // Start accepting connections
        self.accept_connections().await?;
        
        Ok(())
    }

    pub async fn stop_listening(&self) -> Result<()> {
        let mut listener_guard = self.listener.lock().await;
        *listener_guard = None;
        tracing::info!("Network stopped listening");
        Ok(())
    }

    async fn accept_connections(&self) -> Result<()> {
        let listener_clone = self.listener.clone();
        let peers_clone = self.peers.clone();
        let connection_manager_clone = self.connection_manager.clone();

        tokio::spawn(async move {
            loop {
                let listener_guard = listener_clone.lock().await;
                if let Some(ref listener) = *listener_guard {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            drop(listener_guard);
                            let peer_id = addr.to_string();
                            
                            // Create connection
                            let connection = Connection {
                                peer_id: peer_id.clone(),
                                address: addr,
                                last_activity: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                status: ConnectionStatus::Connected,
                                retry_count: 0,
                                bytes_sent: 0,
                                bytes_received: 0,
                                connection_time: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                            };

                            // Add to connection manager
                            {
                                let mut cm = connection_manager_clone.lock().await;
                                cm.active_connections.insert(peer_id.clone(), connection);
                            }

                            // Handle the connection
                            Self::handle_incoming_connection(stream, peer_id, peers_clone.clone()).await;
                        }
                        Err(e) => {
                            tracing::error!("Failed to accept connection: {}", e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn handle_incoming_connection(
        mut stream: TcpStream,
        peer_id: String,
        peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    ) {
        let mut buffer = [0; 4096];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    tracing::info!("Peer {} disconnected", peer_id);
                    break;
                }
                Ok(n) => {
                    // Process received data
                    let data = &buffer[..n];
                    if let Err(e) = Self::process_received_data(&peer_id, data, &peers).await {
                        tracing::error!("Error processing data from {}: {}", peer_id, e);
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from {}: {}", peer_id, e);
                    break;
                }
            }
        }

        // Remove peer when disconnected
        let mut peers_guard = peers.lock().await;
        peers_guard.remove(&peer_id);
    }

    async fn process_received_data(
        peer_id: &str,
        data: &[u8],
        peers: &Arc<Mutex<HashMap<String, PeerInfo>>>,
    ) -> Result<()> {
        // Try to deserialize the message
        if let Ok(message) = serde_json::from_slice::<NetworkMessage>(data) {
            match message {
                NetworkMessage::Handshake { version, node_id, capabilities } => {
                    // Process handshake
                    let peer_info = PeerInfo {
                        address: peer_id.split(':').next().unwrap_or("unknown").to_string(),
                        port: peer_id.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(0),
                        last_seen: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        latency: 0,
                        version,
                        capabilities,
                        failed_attempts: 0,
                        reputation: 1.0,
                        uptime: 0,
                    };

                    let mut peers_guard = peers.lock().await;
                    peers_guard.insert(peer_id.to_string(), peer_info);
                    
                    tracing::info!("Received handshake from peer {}", peer_id);
                }
                NetworkMessage::Ping { timestamp, nonce } => {
                    // Respond with pong
                    tracing::debug!("Received ping from {}", peer_id);
                }
                NetworkMessage::Transaction(tx) => {
                    tracing::info!("Received transaction {} from {}", tx.hash, peer_id);
                }
                NetworkMessage::Block(block) => {
                    tracing::info!("Received block {} from {}", block.hash, peer_id);
                }
                _ => {
                    tracing::debug!("Received message from {}", peer_id);
                }
            }
        }

        Ok(())
    }

    // Node keşfi
    pub async fn discover_nodes(&self) -> Result<()> {
        let bootstrap_nodes = self.bootstrap_nodes.lock().await.clone();
        
        for node in bootstrap_nodes.iter() {
            if let Ok(peer_info) = self.connect_and_handshake(node).await {
                let mut peers = self.peers.lock().await;
                peers.insert(node.clone(), peer_info);
            }
        }
        
        Ok(())
    }

    async fn connect_and_handshake(&self, address: &str) -> Result<PeerInfo> {
        let stream = TcpStream::connect(address).await?;
        
        // Send handshake
        let node_info = self.node_info.lock().await;
        let handshake = NetworkMessage::Handshake {
            version: node_info.version.clone(),
            node_id: node_info.node_id.clone(),
            capabilities: node_info.capabilities.clone(),
        };
        drop(node_info);

        let handshake_data = serde_json::to_vec(&handshake)?;
        let mut stream = stream;
        stream.write_all(&handshake_data).await?;

        // Create peer info
        let parts: Vec<&str> = address.split(':').collect();
        let peer_info = PeerInfo {
            address: parts[0].to_string(),
            port: parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(8000),
            last_seen: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            latency: 0,
            version: "unknown".to_string(),
            capabilities: HashSet::new(),
            failed_attempts: 0,
            reputation: 1.0,
            uptime: 0,
        };

        Ok(peer_info)
    }

    // Peer yönetimi
    pub async fn add_peer(&self, peer_info: PeerInfo) -> Result<()> {
        let mut peers = self.peers.lock().await;
        let peer_key = format!("{}:{}", peer_info.address, peer_info.port);
        peers.insert(peer_key, peer_info);
        Ok(())
    }

    pub async fn remove_peer(&self, address: &str) -> Result<()> {
        let mut peers = self.peers.lock().await;
        peers.remove(address);
        
        // Also remove from connection manager
        let mut connection_manager = self.connection_manager.lock().await;
        connection_manager.active_connections.remove(address);
        
        Ok(())
    }

    // Bağlantı yönetimi
    pub async fn connect_to_peer(&self, address: &str, port: u16) -> Result<()> {
        let mut connection_manager = self.connection_manager.lock().await;
        connection_manager.connect(address, port).await
    }

    pub async fn disconnect_from_peer(&self, address: &str) -> Result<()> {
        let mut connection_manager = self.connection_manager.lock().await;
        connection_manager.disconnect(address).await
    }

    // Mesaj yönetimi
    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.lock().await;
        let message_data = serde_json::to_vec(&message)?;
        
        for (peer_id, _peer) in peers.iter() {
            if let Err(e) = self.send_raw_message_to_peer(peer_id, &message_data).await {
                tracing::warn!("Failed to send message to peer {}: {}", peer_id, e);
            }
        }
        Ok(())
    }

    pub async fn send_message_to_peer(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        let message_data = serde_json::to_vec(&message)?;
        self.send_raw_message_to_peer(peer_id, &message_data).await
    }

    async fn send_raw_message_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        // In a real implementation, this would send data over TCP
        // For now, we'll simulate the sending
        let connection_manager = self.connection_manager.lock().await;
        if let Some(connection) = connection_manager.active_connections.get(peer_id) {
            if connection.status == ConnectionStatus::Connected {
                // Simulate sending
                tracing::debug!("Sent {} bytes to peer {}", data.len(), peer_id);
                return Ok(());
            }
        }
        
        Err(anyhow::anyhow!("Peer {} not connected", peer_id))
    }

    pub async fn ping_all_peers(&self) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let ping = NetworkMessage::Ping {
            timestamp,
            nonce: timestamp, // Use timestamp as nonce for simplicity
        };
        
        self.broadcast_message(ping).await
    }

    pub async fn sync_with_peers(&self, from_height: u64) -> Result<Vec<Block>> {
        let sync_request = NetworkMessage::SyncRequest {
            from_height,
            to_height: None,
        };
        
        self.broadcast_message(sync_request).await?;
        
        // In a real implementation, we would wait for responses
        // For now, return empty vec
        Ok(Vec::new())
    }

    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        let peers = self.peers.lock().await;
        let connection_manager = self.connection_manager.lock().await;
        
        let total_peers = peers.len();
        let connected_peers = connection_manager.active_connections.len();
        
        let (bytes_sent, bytes_received) = connection_manager
            .active_connections
            .values()
            .fold((0u64, 0u64), |(sent, received), conn| {
                (sent + conn.bytes_sent, received + conn.bytes_received)
            });

        let network_health = if total_peers > 0 {
            (connected_peers as f64 / total_peers as f64) * 100.0
        } else {
            0.0
        };

        Ok(NetworkStats {
            total_peers,
            connected_peers,
            bytes_sent,
            bytes_received,
            messages_sent: 0, // TODO: Implement message counting
            messages_received: 0, // TODO: Implement message counting
            uptime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            network_health,
        })
    }

    pub async fn add_bootstrap_node(&self, address: String) -> Result<()> {
        let mut bootstrap_nodes = self.bootstrap_nodes.lock().await;
        bootstrap_nodes.push(address);
        Ok(())
    }

    pub async fn get_peer_count(&self) -> usize {
        let peers = self.peers.lock().await;
        peers.len()
    }

    pub async fn get_connected_peer_count(&self) -> usize {
        let connection_manager = self.connection_manager.lock().await;
        connection_manager.active_connections.len()
    }

    pub async fn is_connected(&self) -> bool {
        let connection_manager = self.connection_manager.lock().await;
        !connection_manager.active_connections.is_empty()
    }

    fn generate_node_id() -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        format!("node_{:x}", hasher.finish())
    }
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            active_connections: HashMap::new(),
            connection_pool: HashMap::new(),
            max_connections: 100,
            connection_timeout: Duration::from_secs(30),
            reconnect_attempts: 3,
            bandwidth_limit: 1024 * 1024, // 1MB/s
        }
    }

    pub async fn connect(&mut self, address: &str, port: u16) -> Result<()> {
        if self.active_connections.len() >= self.max_connections as usize {
            return Err(anyhow::anyhow!("Maximum connections reached"));
        }

        let peer_id = format!("{}:{}", address, port);
        let socket_addr = format!("{}:{}", address, port).parse::<SocketAddr>()?;

        // Try to establish TCP connection
        match TcpStream::connect(socket_addr).await {
            Ok(_stream) => {
                let connection = Connection {
                    peer_id: peer_id.clone(),
                    address: socket_addr,
                    last_activity: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    status: ConnectionStatus::Connected,
                    retry_count: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    connection_time: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                self.active_connections.insert(peer_id.clone(), connection);
                tracing::info!("Successfully connected to peer: {}", peer_id);
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to connect to {}: {}", peer_id, e);
                Err(anyhow::anyhow!("Connection failed: {}", e))
            }
        }
    }

    pub async fn disconnect(&mut self, address: &str) -> Result<()> {
        if let Some(mut connection) = self.active_connections.remove(address) {
            connection.status = ConnectionStatus::Disconnected;
            tracing::info!("Disconnected from peer: {}", address);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Connection not found"))
        }
    }

    pub async fn check_connections(&mut self) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut to_remove = Vec::new();
        let mut to_retry = Vec::new();

        for (peer_id, connection) in &self.active_connections {
            if current_time - connection.last_activity > self.connection_timeout.as_secs() {
                if connection.retry_count < self.reconnect_attempts {
                    to_retry.push((peer_id.clone(), connection.clone()));
                } else {
                    to_remove.push(peer_id.clone());
                }
            }
        }

        // Remove timed out connections
        for peer_id in to_remove {
            self.active_connections.remove(&peer_id);
            tracing::warn!("Removed timed out connection: {}", peer_id);
        }

        // Retry connections
        for (peer_id, mut connection) in to_retry {
            connection.retry_count += 1;
            connection.status = ConnectionStatus::Connecting;
            self.connection_pool.insert(peer_id.clone(), connection);
            self.active_connections.remove(&peer_id);
            tracing::info!("Moved connection {} to retry pool", peer_id);
        }
    }

    pub fn get_connection_stats(&self) -> (usize, usize, u64, u64) {
        let active_count = self.active_connections.len();
        let pool_count = self.connection_pool.len();
        
        let (total_sent, total_received) = self.active_connections
            .values()
            .fold((0u64, 0u64), |(sent, received), conn| {
                (sent + conn.bytes_sent, received + conn.bytes_received)
            });

        (active_count, pool_count, total_sent, total_received)
    }

    pub fn update_connection_activity(&mut self, peer_id: &str, bytes_sent: u64, bytes_received: u64) {
        if let Some(connection) = self.active_connections.get_mut(peer_id) {
            connection.last_activity = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            connection.bytes_sent += bytes_sent;
            connection.bytes_received += bytes_received;
        }
    }
}

// Network hata yönetimi
#[derive(Debug)]
pub enum NetworkError {
    ConnectionFailed(String),
    Timeout,
    InvalidAddress,
    MaxConnectionsReached,
    PeerNotFound,
    MessageSendFailed,
    SerializationError,
    DeserializationError,
    HandshakeError,
    ProtocolError,
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            NetworkError::Timeout => write!(f, "Connection timeout"),
            NetworkError::InvalidAddress => write!(f, "Invalid address"),
            NetworkError::MaxConnectionsReached => write!(f, "Maximum connections reached"),
            NetworkError::PeerNotFound => write!(f, "Peer not found"),
            NetworkError::MessageSendFailed => write!(f, "Failed to send message"),
            NetworkError::SerializationError => write!(f, "Message serialization error"),
            NetworkError::DeserializationError => write!(f, "Message deserialization error"),
            NetworkError::HandshakeError => write!(f, "Handshake error"),
            NetworkError::ProtocolError => write!(f, "Protocol error"),
        }
    }
}

impl std::error::Error for NetworkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_state_creation() {
        let network = NetworkState::new();
        assert_eq!(network.get_peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_management() {
        let network = NetworkState::new();
        
        let peer = PeerInfo {
            address: "127.0.0.1".to_string(),
            port: 8001,
            last_seen: 0,
            latency: 0,
            version: "1.0.0".to_string(),
            capabilities: HashSet::new(),
            failed_attempts: 0,
            reputation: 1.0,
            uptime: 0,
        };

        network.add_peer(peer).await.unwrap();
        assert_eq!(network.get_peer_count().await, 1);

        network.remove_peer("127.0.0.1:8001").await.unwrap();
        assert_eq!(network.get_peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_connection_manager() {
        let mut cm = ConnectionManager::new();
        assert_eq!(cm.active_connections.len(), 0);
        
        // Test max connections
        assert_eq!(cm.max_connections, 100);
        assert_eq!(cm.connection_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_bootstrap_nodes() {
        let network = NetworkState::new();
        
        network.add_bootstrap_node("127.0.0.1:8001".to_string()).await.unwrap();
        network.add_bootstrap_node("127.0.0.1:8002".to_string()).await.unwrap();
        
        let bootstrap_nodes = network.bootstrap_nodes.lock().await;
        assert_eq!(bootstrap_nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_network_stats() {
        let network = NetworkState::new();
        let stats = network.get_network_stats().await.unwrap();
        
        assert_eq!(stats.total_peers, 0);
        assert_eq!(stats.connected_peers, 0);
        assert_eq!(stats.network_health, 0.0);
    }
}
