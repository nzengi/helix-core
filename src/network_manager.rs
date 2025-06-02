use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub address: SocketAddr,
    pub node_id: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub last_seen: u64,
    pub latency: Duration,
    pub score: i32,
    pub is_validator: bool,
    pub is_trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub active_peers: usize,
    pub total_connections: usize,
    pub active_connections: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub average_latency: Duration,
    pub uptime: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub peer: Peer,
    pub stream: TcpStream,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub timestamp: u64,
    pub sender: String,
    pub recipient: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Handshake,
    Ping,
    Pong,
    GetPeers,
    Peers,
    NewBlock,
    NewTransaction,
    RequestBlock,
    BlockData,
    RequestTransaction,
    TransactionData,
}

pub struct NetworkManager {
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    stats: Arc<Mutex<NetworkStats>>,
    trusted_peers: Arc<Mutex<HashSet<String>>>,
    banned_peers: Arc<Mutex<HashSet<String>>>,
    max_peers: usize,
    max_connections: usize,
    handshake_timeout: Duration,
    ping_interval: Duration,
    ban_duration: Duration,
    min_peer_score: i32,
}

impl NetworkManager {
    pub fn new(
        max_peers: usize,
        max_connections: usize,
        handshake_timeout: Duration,
        ping_interval: Duration,
        ban_duration: Duration,
        min_peer_score: i32,
    ) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(Mutex::new(NetworkStats {
                total_peers: 0,
                active_peers: 0,
                total_connections: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                messages_sent: 0,
                messages_received: 0,
                average_latency: Duration::from_millis(0),
                uptime: Duration::from_secs(0),
            })),
            trusted_peers: Arc::new(Mutex::new(HashSet::new())),
            banned_peers: Arc::new(Mutex::new(HashSet::new())),
            max_peers,
            max_connections,
            handshake_timeout,
            ping_interval,
            ban_duration,
            min_peer_score,
        }
    }

    pub async fn start(&self, listen_addr: SocketAddr) -> Result<(), NetworkError> {
        let listener = TcpListener::bind(listen_addr).await?;
        println!("Network manager listening on {}", listen_addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let peer_id = self.generate_peer_id(&addr)?;

            // Ban kontrolü
            if self.is_peer_banned(&peer_id).await {
                stream.shutdown().await?;
                continue;
            }

            // Bağlantı limiti kontrolü
            if self.get_active_connections().await >= self.max_connections {
                stream.shutdown().await?;
                continue;
            }

            // Yeni bağlantıyı işle
            let network_manager = self.clone();
            tokio::spawn(async move {
                if let Err(e) = network_manager.handle_connection(stream, addr, peer_id).await {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }

    pub async fn connect_to_peer(&self, addr: SocketAddr) -> Result<(), NetworkError> {
        let peer_id = self.generate_peer_id(&addr)?;

        // Ban kontrolü
        if self.is_peer_banned(&peer_id).await {
            return Err(NetworkError::PeerBanned);
        }

        // Bağlantı limiti kontrolü
        if self.get_active_connections().await >= self.max_connections {
            return Err(NetworkError::MaxConnectionsReached);
        }

        // Bağlantıyı kur
        let stream = TcpStream::connect(addr).await?;
        self.handle_connection(stream, addr, peer_id).await?;

        Ok(())
    }

    pub async fn broadcast_message(&self, message: Message) -> Result<(), NetworkError> {
        let connections = self.connections.lock().await;
        for connection in connections.values() {
            self.send_message(&connection.stream, &message).await?;
        }
        Ok(())
    }

    pub async fn get_network_stats(&self) -> NetworkStats {
        self.stats.lock().await.clone()
    }

    pub async fn get_peer_info(&self, peer_id: &str) -> Result<Peer, NetworkError> {
        let peers = self.peers.lock().await;
        let peer = peers.get(peer_id)
            .ok_or(NetworkError::PeerNotFound)?
            .clone();
        Ok(peer)
    }

    async fn handle_connection(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        peer_id: String,
    ) -> Result<(), NetworkError> {
        // Handshake
        let handshake = self.perform_handshake(&mut stream).await?;
        let peer = Peer {
            address: addr,
            node_id: peer_id.clone(),
            version: handshake.version,
            capabilities: handshake.capabilities,
            last_seen: chrono::Utc::now().timestamp() as u64,
            latency: Duration::from_millis(0),
            score: 100,
            is_validator: handshake.is_validator,
            is_trusted: self.is_peer_trusted(&peer_id).await,
        };

        // Peer'i kaydet
        let mut peers = self.peers.lock().await;
        peers.insert(peer_id.clone(), peer.clone());

        // Bağlantıyı kaydet
        let connection = Connection {
            peer: peer.clone(),
            stream: stream.try_clone().await?,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
        };
        let mut connections = self.connections.lock().await;
        connections.insert(peer_id.clone(), connection);

        // İstatistikleri güncelle
        self.update_stats(true).await?;

        // Ping-pong döngüsü
        let network_manager = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(network_manager.ping_interval).await;
                if let Err(e) = network_manager.send_ping(&mut stream).await {
                    eprintln!("Ping error: {}", e);
                    break;
                }
            }
        });

        // Mesaj dinleme döngüsü
        let mut buffer = vec![0; 1024];
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let message = self.decode_message(&buffer[..n])?;
            self.handle_message(message).await?;
        }

        // Bağlantıyı temizle
        self.cleanup_connection(&peer_id).await?;

        Ok(())
    }

    async fn perform_handshake(&self, stream: &mut TcpStream) -> Result<Handshake, NetworkError> {
        // TODO: Implement handshake protocol
        Ok(Handshake {
            version: "1.0.0".to_string(),
            capabilities: vec!["block_sync".to_string(), "transaction_relay".to_string()],
            is_validator: false,
        })
    }

    async fn send_ping(&self, stream: &mut TcpStream) -> Result<(), NetworkError> {
        let message = Message {
            message_type: MessageType::Ping,
            payload: vec![],
            timestamp: chrono::Utc::now().timestamp() as u64,
            sender: self.get_node_id()?,
            recipient: "broadcast".to_string(),
        };
        self.send_message(stream, &message).await
    }

    async fn handle_message(&self, message: Message) -> Result<(), NetworkError> {
        match message.message_type {
            MessageType::Ping => {
                // Pong yanıtı gönder
                let pong = Message {
                    message_type: MessageType::Pong,
                    payload: message.payload,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    sender: self.get_node_id()?,
                    recipient: message.sender,
                };
                self.broadcast_message(pong).await?;
            }
            MessageType::Pong => {
                // Latency hesapla
                let latency = chrono::Utc::now().timestamp() as u64 - message.timestamp;
                self.update_peer_latency(&message.sender, Duration::from_millis(latency as u64)).await?;
            }
            MessageType::GetPeers => {
                // Peer listesini gönder
                let peers = self.get_peer_list().await?;
                let response = Message {
                    message_type: MessageType::Peers,
                    payload: serde_json::to_vec(&peers)?,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    sender: self.get_node_id()?,
                    recipient: message.sender,
                };
                self.broadcast_message(response).await?;
            }
            _ => {
                // Diğer mesaj tipleri için işlem yap
            }
        }
        Ok(())
    }

    async fn send_message(&self, stream: &mut TcpStream, message: &Message) -> Result<(), NetworkError> {
        let data = serde_json::to_vec(message)?;
        stream.write_all(&data).await?;
        Ok(())
    }

    async fn decode_message(&self, data: &[u8]) -> Result<Message, NetworkError> {
        let message = serde_json::from_slice(data)?;
        Ok(message)
    }

    async fn update_peer_latency(&self, peer_id: &str, latency: Duration) -> Result<(), NetworkError> {
        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.latency = latency;
            peer.last_seen = chrono::Utc::now().timestamp() as u64;
        }
        Ok(())
    }

    async fn update_stats(&self, is_connection: bool) -> Result<(), NetworkError> {
        let mut stats = self.stats.lock().await;
        if is_connection {
            stats.active_connections += 1;
            stats.total_connections += 1;
        } else {
            stats.active_connections -= 1;
        }
        Ok(())
    }

    async fn cleanup_connection(&self, peer_id: &str) -> Result<(), NetworkError> {
        let mut connections = self.connections.lock().await;
        connections.remove(peer_id);
        self.update_stats(false).await?;
        Ok(())
    }

    async fn is_peer_banned(&self, peer_id: &str) -> bool {
        let banned_peers = self.banned_peers.lock().await;
        banned_peers.contains(peer_id)
    }

    async fn is_peer_trusted(&self, peer_id: &str) -> bool {
        let trusted_peers = self.trusted_peers.lock().await;
        trusted_peers.contains(peer_id)
    }

    async fn get_active_connections(&self) -> usize {
        let connections = self.connections.lock().await;
        connections.len()
    }

    async fn get_peer_list(&self) -> Result<Vec<Peer>, NetworkError> {
        let peers = self.peers.lock().await;
        Ok(peers.values().cloned().collect())
    }

    fn get_node_id(&self) -> Result<String, NetworkError> {
        // TODO: Implement node ID generation
        Ok("node_1".to_string())
    }

    fn generate_peer_id(&self, addr: &SocketAddr) -> Result<String, NetworkError> {
        let mut hasher = Keccak256::new();
        hasher.update(addr.to_string().as_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&result[..8])))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Handshake {
    version: String,
    capabilities: Vec<String>,
    is_validator: bool,
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Peer not found")]
    PeerNotFound,
    #[error("Peer banned")]
    PeerBanned,
    #[error("Max connections reached")]
    MaxConnectionsReached,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Handshake failed")]
    HandshakeFailed,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Invalid peer")]
    InvalidPeer,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Invalid capability")]
    InvalidCapability,
    #[error("Invalid node ID")]
    InvalidNodeId,
    #[error("Invalid handshake")]
    InvalidHandshake,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid payload")]
    InvalidPayload,
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    #[error("Invalid sender")]
    InvalidSender,
    #[error("Invalid recipient")]
    InvalidRecipient,
} 