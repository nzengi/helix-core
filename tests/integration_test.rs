use helix_core::{
    consensus::{Block, Transaction, ConsensusManager},
    network::{NetworkState, NodeInfo},
    state::State as ChainState,
    api::{ApiServer, ApiConfig},
    config::{NodeConfig, NetworkConfig, ConsensusConfig, DatabaseConfig},
    sharding::ShardManager,
    security::SecurityManager,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

// Test veritabanı yapılandırması
fn setup_test_db() -> DatabaseConfig {
    DatabaseConfig {
        path: ":memory:".to_string(),
        max_connections: 1,
        cache_size: 1024,
    }
}

// Test ağ yapılandırması
fn setup_test_network() -> NetworkConfig {
    NetworkConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // Rastgele port
        bootstrap_nodes: vec![],
        max_peers: 10,
        peer_timeout: 30,
    }
}

// Test konsensüs yapılandırması
fn setup_test_consensus() -> ConsensusConfig {
    ConsensusConfig {
        validator_address: "test_validator".to_string(),
        min_validators: 1,
        block_time: 1,
        max_block_size: 1024,
        gas_limit: 1000000,
    }
}

// Test node yapılandırması
fn setup_test_config() -> NodeConfig {
    NodeConfig {
        network: setup_test_network(),
        consensus: setup_test_consensus(),
        database: setup_test_db(),
        ..Default::default()
    }
}

// Test ortamı kurulumu
async fn setup_test_env() -> (
    Arc<Mutex<ChainState>>,
    Arc<Mutex<NetworkState>>,
    Arc<Mutex<ConsensusManager>>,
    Arc<Mutex<ShardManager>>,
    Arc<Mutex<SecurityManager>>,
) {
    let config = setup_test_config();
    
    let chain_state = Arc::new(Mutex::new(ChainState::new(config.database.clone()).await.unwrap()));
    let network_state = Arc::new(Mutex::new(NetworkState::new(config.network.clone())));
    let consensus_manager = Arc::new(Mutex::new(ConsensusManager::new(
        config.consensus.clone(),
        chain_state.clone(),
        network_state.clone(),
    )));
    let shard_manager = Arc::new(Mutex::new(ShardManager::new()));
    let security_manager = Arc::new(Mutex::new(SecurityManager::new()));

    (
        chain_state,
        network_state,
        consensus_manager,
        shard_manager,
        security_manager,
    )
}

#[tokio::test]
async fn test_block_creation_and_validation() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Test bloğu oluştur
    let block = Block {
        hash: "test_hash".to_string(),
        parent_hash: "parent_hash".to_string(),
        timestamp: chrono::Utc::now().timestamp(),
        transactions: vec![],
        validator: "test_validator".to_string(),
        signature: "test_signature".to_string(),
    };

    // Bloğu kaydet
    let mut state = chain_state.lock().await;
    assert!(state.save_block(block.clone()).await.is_ok());

    // Bloğu doğrula
    let consensus = consensus_manager.lock().await;
    assert!(consensus.validate_block(&block).await.is_ok());
}

#[tokio::test]
async fn test_transaction_processing() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Test işlemi oluştur
    let transaction = Transaction {
        hash: "test_tx_hash".to_string(),
        sender: "sender".to_string(),
        receiver: "receiver".to_string(),
        amount: 100.0,
        gas_price: 1.0,
        nonce: 1,
        signature: "test_signature".to_string(),
    };

    // İşlemi işle
    let consensus = consensus_manager.lock().await;
    assert!(consensus.process_transaction(&transaction).await.is_ok());
}

#[tokio::test]
async fn test_network_communication() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Test node bilgisi
    let node_info = NodeInfo {
        address: "127.0.0.1".to_string(),
        port: 8080,
        version: "1.0.0".to_string(),
        capabilities: vec!["consensus".to_string()],
        last_sync: chrono::Utc::now().timestamp(),
    };

    // Node'u ekle
    let mut network = network_state.lock().await;
    assert!(network.add_peer("test_peer".to_string(), node_info).is_ok());
}

#[tokio::test]
async fn test_api_endpoints() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // API sunucusunu başlat
    let api_config = ApiConfig {
        enabled: true,
        host: "127.0.0.1".to_string(),
        port: 0, // Rastgele port
        cors_origins: vec!["*".to_string()],
        rate_limit: 100,
    };

    let api_server = ApiServer::new(
        chain_state.lock().await.clone(),
        network_state.lock().await.clone(),
        api_config,
    );

    // API sunucusunu başlat ve test et
    let server_handle = tokio::spawn(async move {
        api_server.start().await.unwrap();
    });

    // Sunucunun başlaması için bekle
    sleep(Duration::from_millis(100)).await;

    // TODO: API endpoint'lerini test et
    // Örnek: HTTP istekleri gönder ve yanıtları doğrula

    server_handle.abort();
}

#[tokio::test]
async fn test_sharding() {
    let (chain_state, network_state, consensus_manager, shard_manager, _) = setup_test_env().await;
    
    // Test shard oluştur
    let mut shards = shard_manager.lock().await;
    assert!(shards.create_shard(1).is_ok());

    // Shard'a validator ekle
    assert!(shards.add_validator(1, "test_validator".to_string()).is_ok());
}

#[tokio::test]
async fn test_security_features() {
    let (chain_state, network_state, consensus_manager, _, security_manager) = setup_test_env().await;
    
    // Test işlemi oluştur
    let transaction = Transaction {
        hash: "test_tx_hash".to_string(),
        sender: "sender".to_string(),
        receiver: "receiver".to_string(),
        amount: 100.0,
        gas_price: 1.0,
        nonce: 1,
        signature: "test_signature".to_string(),
    };

    // İşlemi doğrula
    let security = security_manager.lock().await;
    assert!(security.verify_transaction(&transaction).is_ok());
}

// Performans testleri
#[tokio::test]
async fn test_performance() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Çok sayıda işlem oluştur
    let mut transactions = Vec::new();
    for i in 0..1000 {
        let transaction = Transaction {
            hash: format!("test_tx_hash_{}", i),
            sender: "sender".to_string(),
            receiver: "receiver".to_string(),
            amount: 100.0,
            gas_price: 1.0,
            nonce: i as u64,
            signature: "test_signature".to_string(),
        };
        transactions.push(transaction);
    }

    // İşlemleri işle ve performansı ölç
    let start = std::time::Instant::now();
    
    let consensus = consensus_manager.lock().await;
    for transaction in transactions {
        assert!(consensus.process_transaction(&transaction).await.is_ok());
    }

    let duration = start.elapsed();
    println!("1000 işlem işleme süresi: {:?}", duration);
}

// Hata durumu testleri
#[tokio::test]
async fn test_error_handling() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Geçersiz işlem
    let invalid_transaction = Transaction {
        hash: "invalid_tx".to_string(),
        sender: "sender".to_string(),
        receiver: "receiver".to_string(),
        amount: -100.0, // Geçersiz miktar
        gas_price: 0.0, // Geçersiz gas fiyatı
        nonce: 0,
        signature: "invalid_signature".to_string(),
    };

    // İşlemi işle ve hata durumunu kontrol et
    let consensus = consensus_manager.lock().await;
    assert!(consensus.process_transaction(&invalid_transaction).await.is_err());
}

// Eşzamanlılık testleri
#[tokio::test]
async fn test_concurrency() {
    let (chain_state, network_state, consensus_manager, _, _) = setup_test_env().await;
    
    // Çoklu işlem görevleri oluştur
    let mut handles = Vec::new();
    for i in 0..10 {
        let consensus = consensus_manager.clone();
        let handle = tokio::spawn(async move {
            let transaction = Transaction {
                hash: format!("concurrent_tx_{}", i),
                sender: "sender".to_string(),
                receiver: "receiver".to_string(),
                amount: 100.0,
                gas_price: 1.0,
                nonce: i as u64,
                signature: "test_signature".to_string(),
            };
            
            let consensus = consensus.lock().await;
            consensus.process_transaction(&transaction).await
        });
        handles.push(handle);
    }

    // Tüm görevlerin tamamlanmasını bekle
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }
} 