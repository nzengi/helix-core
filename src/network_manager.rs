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

    pub async fn connect_to_peer(&self, address: &str) -> Result<()> {
        let peer_id = format!("peer_{}", uuid::Uuid::new_v4());
        let peer = Peer {
            id: peer_id.clone(),
            address: address.to_string(),
            port: self.config.network.listen_port,
            connected: true,
            last_seen: chrono::Utc::now(),
        };

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, peer);

        tracing::info!("Connected to peer: {}", address);
        Ok(())
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;

        for (peer_id, peer) in peers.iter() {
            if peer.connected {
                if let Err(e) = self.send_message_to_peer(peer_id, &message).await {
                    tracing::warn!("Failed to send message to peer {}: {}", peer_id, e);
                }
            }
        }

        Ok(())
    }

    async fn send_message_to_peer(&self, peer_id: &str, message: &NetworkMessage) -> Result<()> {
        // In a real implementation, this would serialize and send the message
        tracing::debug!("Sending message to peer {}: {:?}", peer_id, message);
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

    pub async fn start(&self) -> Result<()> {
        tracing::info!("🌐 Starting network manager...");

        {
            let mut running = self.is_running.write().await;
            *running = true;
        }

        // Connect to bootstrap nodes
        for bootstrap_node in &self.config.network.bootstrap_nodes {
            self.connect_to_peer(bootstrap_node).await?;
        }

        // Start peer discovery
        self.start_peer_discovery().await?;

        tracing::info!("✅ Network manager started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("🛑 Stopping network manager...");

        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        // Disconnect from all peers
        let mut peers = self.peers.write().await;
        for peer in peers.values_mut() {
            peer.connected = false;
        }

        tracing::info!("✅ Network manager stopped");
        Ok(())
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
        if let Some(peer) = peers.get_mut(peer_id) {
            peer.connected = false;
            tracing::info!("❌ Disconnected from peer: {}", peer_id);
        }
        Ok(())
    }

    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> Result<()> {
        let message = NetworkMessage::Transaction(transaction.clone());
        self.broadcast_message(message).await
    }

    pub async fn broadcast_block(&self, block: &Block) -> Result<()> {
        let message = NetworkMessage::Block(block.clone());
        self.broadcast_message(message).await
    }

    pub async fn broadcast_message(&self, message: NetworkMessage) -> Result<()> {
        let peers = self.peers.read().await;
        let connected_peers: Vec<_> = peers.values()
            .filter(|p| p.connected)
            .collect();

        for peer in connected_peers {
            self.send_message_to_peer(&peer.id, &message).await?;
        }

        Ok(())
    }

    pub async fn send_message_to_peer(&self, peer_id: &str, message: NetworkMessage) -> Result<()> {
        // In a real implementation, this would send the message over the network
        // For now, we'll just simulate message handling
        tracing::debug!("📤 Sending message to peer {}: {:?}", peer_id, message);

        // Simulate message processing
        self.handle_received_message(peer_id, message).await?;

        Ok(())
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
                self.send_message_to_peer(peer_id, NetworkMessage::Pong).await?;
            }
            NetworkMessage::Pong => {
                // Update peer connectivity
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
            if !peers.contains_key(&new_peer.id) {
                peers.insert(new_peer.id.clone(), new_peer);
            }
        }

        Ok(())
    }

    async fn start_peer_discovery(&self) -> Result<()> {
        let peers = self.peers.read().await;
        let peer_list: Vec<Peer> = peers.values().cloned().collect();

        if !peer_list.is_empty() {
            let discovery_message = NetworkMessage::PeerDiscovery { peers: peer_list };
            drop(peers); // Release the lock before broadcasting
            self.broadcast_message(discovery_message).await?;
        }

        Ok(())
    }

    pub async fn get_connected_peers(&self) -> Result<Vec<Peer>> {
        let peers = self.peers.read().await;
        Ok(peers.values()
            .filter(|p| p.connected)
            .cloned()
            .collect())
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
                    hash: tx.hash.clone(),
                    from: tx.from.clone(),
                    to: tx.to.clone(),
                    value: tx.amount,
                    gas_limit: tx.gas_limit,
                    gas_price: tx.gas_price,
                    nonce: tx.nonce,
                    data: tx.data.clone(),
                    signature: tx.signature.clone(),
                    timestamp: tx.timestamp.timestamp() as u64,
                    amount: tx.amount,
                };

                if self.chain_state.validate_transaction(&state_tx).await.unwrap_or(false) {
                    self.chain_state.add_pending_transaction(state_tx).await.unwrap_or(());
                    tracing::info!("📝 Added transaction to pool from peer {}", peer_id);
                }
            }
            NetworkMessage::Block(block) => {
                // In a real implementation, we would validate and potentially add the block
                tracing::info!("📦 Received block {} from peer {}", block.height, peer_id);
            }
            _ => {}
        }
        Ok(())
    }
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
}