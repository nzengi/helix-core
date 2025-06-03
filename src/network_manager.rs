
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::config::Config;
use crate::consensus::{Block, Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub connected: bool,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    PeerDiscovery { peers: Vec<Peer> },
    SyncRequest { from_height: u64 },
    SyncResponse { blocks: Vec<Block> },
    Ping { timestamp: u64 },
    Pong { timestamp: u64 },
    Handshake { node_id: String, version: String },
    HandshakeAck { accepted: bool },
}

#[derive(Clone)]
pub struct NetworkManager {
    config: Config,
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    message_handlers: Arc<RwLock<Vec<Box<dyn MessageHandler + Send + Sync>>>>,
    is_running: Arc<RwLock<bool>>,
    listener: Arc<RwLock<Option<TcpListener>>>,
    node_id: String,
}

#[async_trait::async_trait]
pub trait MessageHandler {
    async fn handle_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()>;
}

impl NetworkManager {
    pub async fn new(config: Config) -> Result<Self> {
        let node_id = format!("node_{}", uuid::Uuid::new_v4());
        
        Ok(Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_handlers: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
            listener: Arc::new(RwLock::new(None)),
            node_id,
        })
    }

    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        *is_running = true;

        // Start TCP listener
        self.start_tcp_listener().await?;

        // Start peer discovery
        self.start_peer_discovery().await?;

        // Start periodic tasks
        self.start_periodic_tasks().await?;

        tracing::info!("Network manager started on {}:{}", 
            self.config.network.listen_addr, 
            self.config.network.listen_port);

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;

        // Close listener
        let mut listener = self.listener.write().await;
        *listener = None;

        tracing::info!("Network manager stopped");
        Ok(())
    }

    async fn start_tcp_listener(&self) -> Result<()> {
        let addr = format!("{}:{}", 
            self.config.network.listen_addr, 
            self.config.network.listen_port);

        let listener = TcpListener::bind(&addr).await?;
        
        {
            let mut listener_guard = self.listener.write().await;
            *listener_guard = Some(listener);
        }

        // Accept incoming connections
        let listener_clone = self.listener.clone();
        let peers_clone = self.peers.clone();
        let handlers_clone = self.message_handlers.clone();
        let is_running_clone = self.is_running.clone();
        let node_id = self.node_id.clone();

        tokio::spawn(async move {
            loop {
                let is_running = *is_running_clone.read().await;
                if !is_running {
                    break;
                }

                let listener_guard = listener_clone.read().await;
                if let Some(ref listener) = *listener_guard {
                    match listener.accept().await {
                        Ok((stream, addr)) => {
                            let peer_id = addr.to_string();
                            tracing::info!("New connection from: {}", peer_id);

                            // Handle connection in separate task
                            let peers = peers_clone.clone();
                            let handlers = handlers_clone.clone();
                            let node_id = node_id.clone();
                            
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, peer_id, peers, handlers, node_id).await {
                                    tracing::error!("Connection handling error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Failed to accept connection: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                } else {
                    break;
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        peer_id: String,
        peers: Arc<RwLock<HashMap<String, Peer>>>,
        handlers: Arc<RwLock<Vec<Box<dyn MessageHandler + Send + Sync>>>>,
        node_id: String,
    ) -> Result<()> {
        // Send handshake
        let handshake = NetworkMessage::Handshake {
            node_id: node_id.clone(),
            version: "1.0.0".to_string(),
        };

        Self::send_message(&mut stream, &handshake).await?;

        // Add peer
        let parts: Vec<&str> = peer_id.split(':').collect();
        let peer = Peer {
            id: peer_id.clone(),
            address: parts[0].to_string(),
            port: parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0),
            connected: true,
            last_seen: chrono::Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
        };

        {
            let mut peers_guard = peers.write().await;
            peers_guard.insert(peer_id.clone(), peer);
        }

        // Message handling loop
        let mut buffer = vec![0u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    tracing::info!("Peer {} disconnected", peer_id);
                    break;
                }
                Ok(n) => {
                    let data = &buffer[..n];
                    
                    // Update bytes received
                    {
                        let mut peers_guard = peers.write().await;
                        if let Some(peer) = peers_guard.get_mut(&peer_id) {
                            peer.bytes_received += n as u64;
                            peer.last_seen = chrono::Utc::now();
                        }
                    }

                    // Try to deserialize message
                    if let Ok(message) = bincode::deserialize::<NetworkMessage>(data) {
                        // Forward to handlers
                        let handlers_guard = handlers.read().await;
                        for handler in handlers_guard.iter() {
                            if let Err(e) = handler.handle_message(&peer_id, message.clone()).await {
                                tracing::error!("Handler error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from {}: {}", peer_id, e);
                    break;
                }
            }
        }

        // Remove peer on disconnect
        {
            let mut peers_guard = peers.write().await;
            peers_guard.remove(&peer_id);
        }

        Ok(())
    }

    async fn send_message(stream: &mut TcpStream, message: &NetworkMessage) -> Result<()> {
        let data = bincode::serialize(message)?;
        stream.write_all(&data).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn start_peer_discovery(&self) -> Result<()> {
        // Connect to bootstrap nodes
        for bootstrap_node in &self.config.network.bootstrap_nodes {
            if let Err(e) = self.connect_to_peer(bootstrap_node).await {
                tracing::warn!("Failed to connect to bootstrap node {}: {}", bootstrap_node, e);
            }
        }

        Ok(())
    }

    async fn start_periodic_tasks(&self) -> Result<()> {
        let peers_clone = self.peers.clone();
        let is_running_clone = self.is_running.clone();

        // Cleanup task
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                let is_running = *is_running_clone.read().await;
                if !is_running {
                    break;
                }

                // Clean up inactive peers
                let mut peers = peers_clone.write().await;
                let now = chrono::Utc::now();
                let timeout = chrono::Duration::minutes(5);

                peers.retain(|peer_id, peer| {
                    let is_active = now.signed_duration_since(peer.last_seen) < timeout;
                    if !is_active {
                        tracing::info!("Removing inactive peer: {}", peer_id);
                    }
                    is_active
                });
            }
        });

        Ok(())
    }

    pub async fn connect_to_peer(&self, address: &str) -> Result<()> {
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid peer address format: {}", address);
        }

        let host = parts[0];
        let port: u16 = parts[1].parse()?;

        // Try to connect
        match TcpStream::connect(address).await {
            Ok(mut stream) => {
                // Send handshake
                let handshake = NetworkMessage::Handshake {
                    node_id: self.node_id.clone(),
                    version: "1.0.0".to_string(),
                };

                Self::send_message(&mut stream, &handshake).await?;

                // Add peer
                let peer = Peer {
                    id: address.to_string(),
                    address: host.to_string(),
                    port,
                    connected: true,
                    last_seen: chrono::Utc::now(),
                    bytes_sent: 0,
                    bytes_received: 0,
                };

                {
                    let mut peers = self.peers.write().await;
                    peers.insert(address.to_string(), peer);
                }

                // Handle connection
                let peers = self.peers.clone();
                let handlers = self.message_handlers.clone();
                let node_id = self.node_id.clone();
                let peer_id = address.to_string();

                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(stream, peer_id, peers, handlers, node_id).await {
                        tracing::error!("Outbound connection error: {}", e);
                    }
                });

                tracing::info!("Connected to peer: {}", address);
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to connect to {}: {}", address, e);
                Err(e.into())
            }
        }
    }

    pub async fn disconnect_from_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        if peers.remove(peer_id).is_some() {
            tracing::info!("Disconnected from peer: {}", peer_id);
        }
        Ok(())
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;
        let data = bincode::serialize(&message)?;
        
        for (peer_id, peer) in peers.iter() {
            if peer.connected {
                if let Err(e) = self.send_message_to_peer_by_id(peer_id, &data).await {
                    tracing::warn!("Failed to send message to peer {}: {}", peer_id, e);
                }
            }
        }

        Ok(())
    }

    async fn send_message_to_peer_by_id(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        // In a real implementation, we would maintain active connections
        // For now, try to establish a new connection each time
        match TcpStream::connect(peer_id).await {
            Ok(mut stream) => {
                stream.write_all(data).await?;
                stream.flush().await?;

                // Update bytes sent
                {
                    let mut peers = self.peers.write().await;
                    if let Some(peer) = peers.get_mut(peer_id) {
                        peer.bytes_sent += data.len() as u64;
                    }
                }

                Ok(())
            }
            Err(e) => Err(e.into())
        }
    }

    pub async fn send_message_to_peer(&self, peer_id: &str, message: &NetworkMessage) -> Result<()> {
        let data = bincode::serialize(message)?;
        self.send_message_to_peer_by_id(peer_id, &data).await
    }

    pub async fn add_message_handler(&self, handler: Box<dyn MessageHandler + Send + Sync>) {
        let mut handlers = self.message_handlers.write().await;
        handlers.push(handler);
    }

    pub async fn get_peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<Peer>> {
        let peers = self.peers.read().await;
        Ok(peers.values()
            .filter(|p| p.connected)
            .cloned()
            .collect())
    }

    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> Result<()> {
        let message = NetworkMessage::Transaction(transaction.clone());
        self.broadcast_message(message).await
    }

    pub async fn broadcast_block(&self, block: &Block) -> Result<()> {
        let message = NetworkMessage::Block(block.clone());
        self.broadcast_message(message).await
    }

    pub async fn sync_with_peers(&self, from_height: u64) -> Result<Vec<Block>> {
        let sync_request = NetworkMessage::SyncRequest { from_height };
        self.broadcast_message(sync_request).await?;

        // In a real implementation, we would collect responses
        // For now, return empty vector
        Ok(Vec::new())
    }

    pub async fn is_connected_to_network(&self) -> bool {
        let peers = self.peers.read().await;
        peers.values().any(|p| p.connected)
    }

    pub async fn ping_all_peers(&self) -> Result<()> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let ping_message = NetworkMessage::Ping { timestamp };
        self.broadcast_message(ping_message).await?;
        Ok(())
    }

    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        let peers = self.peers.read().await;
        let connected_count = peers.values().filter(|p| p.connected).count();
        let total_count = peers.len();

        let (total_sent, total_received) = peers.values().fold((0u64, 0u64), |(sent, received), peer| {
            (sent + peer.bytes_sent, received + peer.bytes_received)
        });

        Ok(NetworkStats {
            total_peers: total_count,
            connected_peers: connected_count,
            is_connected: connected_count > 0,
            network_health: if total_count > 0 { 
                (connected_count as f64 / total_count as f64 * 100.0) 
            } else { 
                0.0 
            },
            bytes_sent: total_sent,
            bytes_received: total_received,
        })
    }
}

// Blockchain message handler
pub struct BlockchainMessageHandler {
    pub chain_state: Arc<crate::state::ChainState>,
}

#[async_trait::async_trait]
impl MessageHandler for BlockchainMessageHandler {
    async fn handle_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        match message {
            NetworkMessage::Transaction(tx) => {
                let state_tx = crate::state::Transaction {
                    id: tx.hash.clone(),
                    hash: tx.hash.clone(),
                    from: tx.from.clone(),
                    to: tx.to.clone(),
                    value: tx.amount,
                    amount: tx.amount,
                    fee: tx.gas_price * tx.gas_limit,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price,
                    gas_used: 0,
                    nonce: tx.nonce,
                    data: tx.data.clone(),
                    signature: tx.signature.clone(),
                    timestamp: tx.timestamp.timestamp() as u64,
                    block_height: 0,
                    status: crate::state::TransactionStatus::Pending,
                };

                if self.chain_state.validate_transaction(&state_tx).await.unwrap_or(false) {
                    self.chain_state.add_pending_transaction(state_tx).await?;
                    tracing::info!("Added transaction {} from peer {}", tx.hash, peer_id);
                }
            }
            NetworkMessage::Block(block) => {
                let state_block = crate::state::Block {
                    index: block.height,
                    timestamp: block.timestamp.timestamp() as u64,
                    previous_hash: block.previous_hash.clone(),
                    merkle_root: block.merkle_root.clone(),
                    transactions: block.transactions.iter().map(|tx| crate::state::Transaction {
                        id: tx.hash.clone(),
                        hash: tx.hash.clone(),
                        from: tx.from.clone(),
                        to: tx.to.clone(),
                        value: tx.amount,
                        amount: tx.amount,
                        fee: tx.gas_price * tx.gas_limit,
                        gas_limit: tx.gas_limit,
                        gas_price: tx.gas_price,
                        gas_used: 21000, // Default gas used
                        nonce: tx.nonce,
                        data: tx.data.clone(),
                        signature: tx.signature.clone(),
                        timestamp: tx.timestamp.timestamp() as u64,
                        block_height: block.height,
                        status: crate::state::TransactionStatus::Confirmed,
                    }).collect(),
                    hash: block.hash.clone(),
                    signatures: vec![block.signature.clone()],
                    validator: block.validator.clone(),
                    gas_limit: block.transactions.iter().map(|tx| tx.gas_limit).sum(),
                    gas_used: block.transactions.iter().map(|_| 21000u64).sum(),
                    size: 1024, // Default block size
                    nonce: 0,   // Default nonce
                };

                self.chain_state.add_block(&state_block).await?;
                tracing::info!("Added block {} from peer {}", block.height, peer_id);
            }
            NetworkMessage::SyncRequest { from_height } => {
                tracing::info!("Sync request from {} for height {}", peer_id, from_height);
                // Handle sync request - send blocks if available
            }
            NetworkMessage::SyncResponse { blocks } => {
                tracing::info!("Received {} blocks from {}", blocks.len(), peer_id);
                for block in blocks {
                    let state_block = crate::state::Block {
                        index: block.height,
                        timestamp: block.timestamp.timestamp() as u64,
                        previous_hash: block.previous_hash.clone(),
                        merkle_root: block.merkle_root.clone(),
                        transactions: block.transactions.iter().map(|tx| crate::state::Transaction {
                            id: tx.hash.clone(),
                            hash: tx.hash.clone(),
                            from: tx.from.clone(),
                            to: tx.to.clone(),
                            value: tx.amount,
                            amount: tx.amount,
                            fee: tx.gas_price * tx.gas_limit,
                            gas_limit: tx.gas_limit,
                            gas_price: tx.gas_price,
                            gas_used: 21000, // Default gas used
                            nonce: tx.nonce,
                            data: tx.data.clone(),
                            signature: tx.signature.clone(),
                            timestamp: tx.timestamp.timestamp() as u64,
                            block_height: block.height,
                            status: crate::state::TransactionStatus::Confirmed,
                        }).collect(),
                        hash: block.hash.clone(),
                        signatures: vec![block.signature.clone()],
                        validator: block.validator.clone(),
                        gas_limit: block.transactions.iter().map(|tx| tx.gas_limit).sum(),
                        gas_used: block.transactions.iter().map(|_| 21000u64).sum(),
                        size: 1024, // Default block size
                        nonce: 0,   // Default nonce
                    };
                    self.chain_state.add_block(&state_block).await?;
                }
            }
            NetworkMessage::Ping { timestamp } => {
                tracing::debug!("Ping from {} at {}", peer_id, timestamp);
                // Could respond with Pong
            }
            NetworkMessage::Pong { timestamp } => {
                tracing::debug!("Pong from {} at {}", peer_id, timestamp);
            }
            NetworkMessage::Handshake { node_id, version } => {
                tracing::info!("Handshake from {} ({})", node_id, version);
            }
            NetworkMessage::HandshakeAck { accepted } => {
                tracing::info!("Handshake ack from {}: {}", peer_id, accepted);
            }
            NetworkMessage::PeerDiscovery { peers } => {
                tracing::info!("Discovered {} peers from {}", peers.len(), peer_id);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub is_connected: bool,
    pub network_health: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
