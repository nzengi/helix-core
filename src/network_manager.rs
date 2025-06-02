
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Transaction(Transaction),
    Block(Block),
    PeerDiscovery { peers: Vec<Peer> },
    SyncRequest { from_height: u64 },
    SyncResponse { blocks: Vec<Block> },
    Ping,
    Pong,
}

#[derive(Clone, Debug)]
pub struct NetworkManager {
    config: Config,
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    message_handlers: Arc<RwLock<Vec<Box<dyn MessageHandler + Send + Sync>>>>,
    is_running: Arc<RwLock<bool>>,
}

#[async_trait::async_trait]
pub trait MessageHandler {
    async fn handle_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()>;
}

impl NetworkManager {
    pub async fn new(config: Config) -> Result<Self> {
        Ok(Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_handlers: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Ok(());
        }

        *is_running = true;

        // Start peer discovery
        self.start_peer_discovery().await?;

        // Start message handling
        self.start_message_handler().await?;

        tracing::info!("Network manager started on {}:{}", 
            self.config.network.listen_addr, 
            self.config.network.listen_port);

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;

        tracing::info!("Network manager stopped");
        Ok(())
    }

    async fn start_peer_discovery(&self) -> Result<()> {
        // Connect to bootstrap nodes
        for bootstrap_node in &self.config.network.bootstrap_nodes {
            if let Err(e) = self.connect_to_peer(bootstrap_node).await {
                tracing::warn!("Failed to connect to bootstrap node {}: {}", bootstrap_node, e);
            }
        }

        // Broadcast peer discovery
        let peers = self.peers.read().await;
        let peer_list: Vec<Peer> = peers.values().cloned().collect();

        if !peer_list.is_empty() {
            let discovery_message = NetworkMessage::PeerDiscovery { peers: peer_list };
            drop(peers); // Release the lock before broadcasting
            self.broadcast_message(discovery_message).await?;
        }

        Ok(())
    }

    async fn start_message_handler(&self) -> Result<()> {
        // Start listening for incoming connections
        let addr = format!("{}:{}", 
            self.config.network.listen_addr, 
            self.config.network.listen_port);

        tracing::info!("Starting to listen on {}", addr);

        // In a real implementation, this would start a TCP/UDP server
        // For now, just log that we're ready to accept connections

        Ok(())
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;
        let connected_peers: Vec<_> = peers.values()
            .filter(|p| p.connected)
            .collect();

        for peer in connected_peers {
            if let Err(e) = self.send_message_to_peer(&peer.id, &message).await {
                tracing::warn!("Failed to send message to peer {}: {}", peer.id, e);
            }
        }

        Ok(())
    }

    pub async fn send_message_to_peer(&self, peer_id: &str, message: &NetworkMessage) -> Result<()> {
        // In a real implementation, this would serialize and send the message
        tracing::debug!("📤 Sending message to peer {}: {:?}", peer_id, message);

        // Simulate message processing
        self.handle_received_message(peer_id, message.clone()).await?;

        Ok(())
    }

    pub async fn handle_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        let handlers = self.message_handlers.read().await;

        for handler in handlers.iter() {
            if let Err(e) = handler.handle_message(peer_id, message.clone()).await {
                tracing::error!("Message handler error: {}", e);
            }
        }

        Ok(())
    }

    pub async fn add_message_handler(&self, handler: Box<dyn MessageHandler + Send + Sync>) {
        let mut handlers = self.message_handlers.write().await;
        handlers.push(handler);
    }

    pub async fn connect_to_peer(&self, address: &str) -> Result<()> {
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid peer address format");
        }

        let host = parts[0];
        let port: u16 = parts[1].parse()?;

        let peer_id = format!("{}:{}", host, port);
        let peer = Peer {
            id: peer_id.clone(),
            address: host.to_string(),
            port,
            connected: true,
            last_seen: chrono::Utc::now(),
        };

        let mut peers = self.peers.write().await;
        peers.insert(peer_id.clone(), peer);

        tracing::info!("🔗 Connected to peer: {}", peer_id);
        Ok(())
    }

    pub async fn disconnect_from_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);
        tracing::info!("🔌 Disconnected from peer: {}", peer_id);
        Ok(())
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

    pub async fn handle_received_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        tracing::debug!("📥 Received message from peer {}: {:?}", peer_id, message);

        // Update peer last seen
        {
            let mut peers = self.peers.write().await;
            if let Some(peer) = peers.get_mut(peer_id) {
                peer.last_seen = chrono::Utc::now();
            }
        }

        // Process message based on type
        match message.clone() {
            NetworkMessage::PeerDiscovery { peers: new_peers } => {
                self.handle_peer_discovery(new_peers).await?;
            }
            NetworkMessage::Ping => {
                self.send_message_to_peer(peer_id, &NetworkMessage::Pong).await?;
            }
            NetworkMessage::Pong => {
                // Update peer connectivity
                let mut peers = self.peers.write().await;
                if let Some(peer) = peers.get_mut(peer_id) {
                    peer.last_seen = chrono::Utc::now();
                }
            }
            _ => {
                // Forward to registered handlers
                let handlers = self.message_handlers.read().await;
                for handler in handlers.iter() {
                    handler.handle_message(peer_id, message.clone()).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_peer_discovery(&self, new_peers: Vec<Peer>) -> Result<()> {
        let mut peers = self.peers.write().await;

        for new_peer in new_peers {
            if !peers.contains_key(&new_peer.id) && peers.len() < self.config.network.max_peers as usize {
                tracing::info!("🆕 Discovered new peer: {}", new_peer.id);
                peers.insert(new_peer.id.clone(), new_peer);
            }
        }

        Ok(())
    }

    pub async fn sync_with_peers(&self, from_height: u64) -> Result<Vec<Block>> {
        let sync_request = NetworkMessage::SyncRequest { from_height };
        self.broadcast_message(sync_request).await?;

        // In a real implementation, we would wait for responses and collect blocks
        // For now, return empty vector
        Ok(Vec::new())
    }

    pub async fn is_connected_to_network(&self) -> bool {
        let peers = self.peers.read().await;
        peers.values().any(|p| p.connected)
    }

    pub async fn handle_network_event(&self, event: NetworkEvent) -> Result<()> {
        match event {
            NetworkEvent::PeerConnected(peer_id) => {
                tracing::info!("🟢 Peer connected: {}", peer_id);
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                tracing::info!("🔴 Peer disconnected: {}", peer_id);
                self.disconnect_from_peer(&peer_id).await?;
            }
            NetworkEvent::MessageReceived(peer_id, message) => {
                self.handle_received_message(&peer_id, message).await?;
            }
        }
        Ok(())
    }

    pub async fn ping_all_peers(&self) -> Result<()> {
        let ping_message = NetworkMessage::Ping;
        self.broadcast_message(ping_message).await?;
        Ok(())
    }

    pub async fn get_network_stats(&self) -> Result<NetworkStats> {
        let peers = self.peers.read().await;
        let connected_count = peers.values().filter(|p| p.connected).count();
        let total_count = peers.len();

        Ok(NetworkStats {
            total_peers: total_count,
            connected_peers: connected_count,
            is_connected: connected_count > 0,
            network_health: if connected_count > 0 { 
                (connected_count as f64 / total_count as f64 * 100.0) 
            } else { 
                0.0 
            },
        })
    }

    pub async fn cleanup_disconnected_peers(&self) -> Result<()> {
        let mut peers = self.peers.write().await;
        let now = chrono::Utc::now();
        let timeout_duration = chrono::Duration::minutes(5);

        peers.retain(|_, peer| {
            let is_recent = now.signed_duration_since(peer.last_seen) < timeout_duration;
            if !is_recent {
                tracing::info!("🧹 Cleaning up inactive peer: {}", peer.id);
            }
            is_recent
        });

        Ok(())
    }
}

// Example message handler for blockchain events
pub struct BlockchainMessageHandler {
    pub chain_state: Arc<crate::state::ChainState>,
}

#[async_trait::async_trait]
impl MessageHandler for BlockchainMessageHandler {
    async fn handle_message(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        match message {
            NetworkMessage::Transaction(tx) => {
                // Convert consensus::Transaction to state::Transaction
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
                    nonce: tx.nonce,
                    data: tx.data.clone(),
                    signature: tx.signature.clone(),
                    timestamp: tx.timestamp.timestamp() as u64,
                };

                if self.chain_state.validate_transaction(&state_tx).await.unwrap_or(false) {
                    self.chain_state.add_pending_transaction(state_tx).await.unwrap_or(());
                    tracing::info!("📝 Added transaction to pool from peer {}", peer_id);
                }
            }
            NetworkMessage::Block(block) => {
                // Convert consensus::Block to state::Block for validation
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
                        nonce: tx.nonce,
                        data: tx.data.clone(),
                        signature: tx.signature.clone(),
                        timestamp: tx.timestamp.timestamp() as u64,
                    }).collect(),
                    hash: block.hash.clone(),
                    signatures: vec![block.signature.clone()],
                    validator: block.validator.clone(),
                };

                self.chain_state.add_block(&state_block).await.unwrap_or(());
                tracing::info!("📦 Received and processed block {} from peer {}", block.height, peer_id);
            }
            NetworkMessage::SyncRequest { from_height } => {
                tracing::info!("🔄 Received sync request from {} for height {}", peer_id, from_height);
                // In a real implementation, we would send blocks
            }
            NetworkMessage::SyncResponse { blocks } => {
                tracing::info!("📥 Received {} blocks in sync response from {}", blocks.len(), peer_id);
                // Process received blocks
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
                            nonce: tx.nonce,
                            data: tx.data.clone(),
                            signature: tx.signature.clone(),
                            timestamp: tx.timestamp.timestamp() as u64,
                        }).collect(),
                        hash: block.hash.clone(),
                        signatures: vec![block.signature.clone()],
                        validator: block.validator.clone(),
                    };
                    self.chain_state.add_block(&state_block).await.unwrap_or(());
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerConnected(String),
    PeerDisconnected(String),
    MessageReceived(String, NetworkMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub connected_peers: usize,
    pub is_connected: bool,
    pub network_health: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkConfig;

    #[tokio::test]
    async fn test_network_manager_creation() {
        let config = Config {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: Vec::new(),
            },
            consensus: Default::default(),
            database: Default::default(),
            api: Default::default(),
            security: Default::default(),
            wallet: Default::default(),
        };

        let network = NetworkManager::new(config).await.unwrap();
        assert!(!network.is_connected_to_network().await);
    }

    #[tokio::test]
    async fn test_peer_connection() {
        let config = Config {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: Vec::new(),
            },
            consensus: Default::default(),
            database: Default::default(),
            api: Default::default(),
            security: Default::default(),
            wallet: Default::default(),
        };

        let network = NetworkManager::new(config).await.unwrap();
        network.connect_to_peer("127.0.0.1:8081").await.unwrap();

        let peers = network.get_connected_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "127.0.0.1");
        assert_eq!(peers[0].port, 8081);
    }

    #[tokio::test]
    async fn test_message_broadcasting() {
        let config = Config {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: Vec::new(),
            },
            consensus: Default::default(),
            database: Default::default(),
            api: Default::default(),
            security: Default::default(),
            wallet: Default::default(),
        };

        let network = NetworkManager::new(config).await.unwrap();
        network.connect_to_peer("127.0.0.1:8081").await.unwrap();

        let ping_message = NetworkMessage::Ping;
        let result = network.broadcast_message(ping_message).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_network_stats() {
        let config = Config {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
                max_peers: 50,
                bootstrap_nodes: Vec::new(),
            },
            consensus: Default::default(),
            database: Default::default(),
            api: Default::default(),
            security: Default::default(),
            wallet: Default::default(),
        };

        let network = NetworkManager::new(config).await.unwrap();
        network.connect_to_peer("127.0.0.1:8081").await.unwrap();

        let stats = network.get_network_stats().await.unwrap();
        assert_eq!(stats.total_peers, 1);
        assert_eq!(stats.connected_peers, 1);
        assert!(stats.is_connected);
        assert_eq!(stats.network_health, 100.0);
    }
}
