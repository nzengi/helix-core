
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use sha3::{Keccak256, Digest};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub token_type: TokenType,
    pub owner: String,
    pub created_at: u64,
    pub metadata: TokenMetadata,
    pub is_mintable: bool,
    pub is_burnable: bool,
    pub is_pausable: bool,
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    ERC20,
    ERC721,
    ERC1155,
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenMetadata {
    pub description: Option<String>,
    pub image: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Vec<TokenAttribute>,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAttribute {
    pub trait_type: String,
    pub value: String,
    pub display_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub token_address: String,
    pub owner: String,
    pub balance: u128,
    pub token_id: Option<u128>,
    pub frozen: bool,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub token_address: String,
    pub from: String,
    pub to: String,
    pub amount: u128,
    pub token_id: Option<u128>,
    pub timestamp: u64,
    pub transaction_hash: String,
    pub block_height: u64,
    pub fee: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenApproval {
    pub token_address: String,
    pub owner: String,
    pub spender: String,
    pub amount: u128,
    pub token_id: Option<u128>,
    pub timestamp: u64,
    pub expires_at: Option<u64>,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHolding {
    pub token_address: String,
    pub balance: u128,
    pub percentage: f64,
    pub value_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatistics {
    pub total_holders: u64,
    pub total_transfers: u64,
    pub market_cap: Option<f64>,
    pub price_usd: Option<f64>,
    pub volume_24h: Option<f64>,
    pub circulating_supply: u128,
}

pub struct TokenManager {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    balances: Arc<Mutex<HashMap<String, TokenBalance>>>,
    transfers: Arc<Mutex<Vec<TokenTransfer>>>,
    approvals: Arc<Mutex<HashMap<String, TokenApproval>>>,
    holders: Arc<Mutex<HashMap<String, Vec<String>>>>, // token_address -> holders
    token_statistics: Arc<Mutex<HashMap<String, TokenStatistics>>>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            balances: Arc::new(Mutex::new(HashMap::new())),
            transfers: Arc::new(Mutex::new(Vec::new())),
            approvals: Arc::new(Mutex::new(HashMap::new())),
            holders: Arc::new(Mutex::new(HashMap::new())),
            token_statistics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_token(
        &self,
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: u128,
        token_type: TokenType,
        owner: String,
        metadata: TokenMetadata,
        is_mintable: bool,
        is_burnable: bool,
        is_pausable: bool,
    ) -> Result<Token, TokenError> {
        if name.is_empty() || symbol.is_empty() {
            return Err(TokenError::InvalidTokenData);
        }

        if decimals > 18 {
            return Err(TokenError::InvalidDecimals);
        }

        let address = self.generate_token_address(&name, &symbol, &owner)?;
        
        let token = Token {
            address: address.clone(),
            name,
            symbol,
            decimals,
            total_supply,
            token_type,
            owner: owner.clone(),
            created_at: Utc::now().timestamp() as u64,
            metadata,
            is_mintable,
            is_burnable,
            is_pausable,
            paused: false,
        };

        let mut tokens = self.tokens.lock().await;
        tokens.insert(address.clone(), token.clone());

        // Initialize token statistics
        let mut stats = self.token_statistics.lock().await;
        stats.insert(address.clone(), TokenStatistics {
            total_holders: if total_supply > 0 { 1 } else { 0 },
            total_transfers: 0,
            market_cap: None,
            price_usd: None,
            volume_24h: None,
            circulating_supply: total_supply,
        });

        // If there's an initial supply, give it to the owner
        if total_supply > 0 {
            self.mint_internal(&address, owner, total_supply, None).await?;
        }

        Ok(token)
    }

    pub async fn mint(
        &self,
        token_address: &str,
        to: String,
        amount: u128,
        token_id: Option<u128>,
        minter: &str,
    ) -> Result<TokenTransfer, TokenError> {
        let mut tokens = self.tokens.lock().await;
        let token = tokens.get_mut(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if !token.is_mintable {
            return Err(TokenError::MintNotAllowed);
        }

        if token.owner != minter {
            return Err(TokenError::Unauthorized);
        }

        if token.paused {
            return Err(TokenError::TokenPaused);
        }

        // Validate based on token type
        self.validate_token_operation(&token.token_type, amount, token_id)?;

        drop(tokens); // Release lock before calling mint_internal

        self.mint_internal(token_address, to, amount, token_id).await
    }

    async fn mint_internal(
        &self,
        token_address: &str,
        to: String,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<TokenTransfer, TokenError> {
        // Update balance
        let mut balances = self.balances.lock().await;
        let balance_key = self.generate_balance_key(token_address, &to, token_id);
        
        let balance = balances.entry(balance_key.clone())
            .or_insert(TokenBalance {
                token_address: token_address.to_string(),
                owner: to.clone(),
                balance: 0,
                token_id,
                frozen: false,
                last_updated: Utc::now().timestamp() as u64,
            });

        balance.balance += amount;
        balance.last_updated = Utc::now().timestamp() as u64;

        // Update total supply
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get_mut(token_address) {
            token.total_supply += amount;
        }
        drop(tokens);

        // Update holders list
        let mut holders = self.holders.lock().await;
        let holder_list = holders.entry(token_address.to_string()).or_insert_with(Vec::new);
        if !holder_list.contains(&to) {
            holder_list.push(to.clone());
        }

        // Create transfer record
        let transfer = TokenTransfer {
            token_address: token_address.to_string(),
            from: "0x0000000000000000000000000000000000000000".to_string(),
            to,
            amount,
            token_id,
            timestamp: Utc::now().timestamp() as u64,
            transaction_hash: self.generate_transaction_hash()?,
            block_height: 0, // Should be set by the blockchain
            fee: 0,
        };

        let mut transfers = self.transfers.lock().await;
        transfers.push(transfer.clone());

        // Update statistics
        self.update_token_statistics(token_address).await?;

        Ok(transfer)
    }

    pub async fn burn(
        &self,
        token_address: &str,
        from: String,
        amount: u128,
        token_id: Option<u128>,
        burner: &str,
    ) -> Result<TokenTransfer, TokenError> {
        let tokens = self.tokens.lock().await;
        let token = tokens.get(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if !token.is_burnable {
            return Err(TokenError::BurnNotAllowed);
        }

        if token.owner != burner && from != burner {
            return Err(TokenError::Unauthorized);
        }

        if token.paused {
            return Err(TokenError::TokenPaused);
        }

        drop(tokens);

        // Check balance
        let mut balances = self.balances.lock().await;
        let from_key = self.generate_balance_key(token_address, &from, token_id);
        let from_balance = balances.get_mut(&from_key)
            .ok_or(TokenError::InsufficientBalance)?;

        if from_balance.balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        if from_balance.frozen {
            return Err(TokenError::BalanceFrozen);
        }

        // Update balance
        from_balance.balance -= amount;
        from_balance.last_updated = Utc::now().timestamp() as u64;

        // Update total supply
        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get_mut(token_address) {
            token.total_supply -= amount;
        }
        drop(tokens);

        // Create transfer record
        let transfer = TokenTransfer {
            token_address: token_address.to_string(),
            from,
            to: "0x0000000000000000000000000000000000000000".to_string(),
            amount,
            token_id,
            timestamp: Utc::now().timestamp() as u64,
            transaction_hash: self.generate_transaction_hash()?,
            block_height: 0,
            fee: 0,
        };

        let mut transfers = self.transfers.lock().await;
        transfers.push(transfer.clone());

        // Update statistics
        self.update_token_statistics(token_address).await?;

        Ok(transfer)
    }

    pub async fn transfer(
        &self,
        token_address: &str,
        from: String,
        to: String,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<TokenTransfer, TokenError> {
        if from == to {
            return Err(TokenError::SelfTransfer);
        }

        let tokens = self.tokens.lock().await;
        let token = tokens.get(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if token.paused {
            return Err(TokenError::TokenPaused);
        }

        self.validate_token_operation(&token.token_type, amount, token_id)?;
        drop(tokens);

        // Check and update balances
        let mut balances = self.balances.lock().await;
        let from_key = self.generate_balance_key(token_address, &from, token_id);
        let to_key = self.generate_balance_key(token_address, &to, token_id);

        let from_balance = balances.get_mut(&from_key)
            .ok_or(TokenError::InsufficientBalance)?;

        if from_balance.balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        if from_balance.frozen {
            return Err(TokenError::BalanceFrozen);
        }

        // Update balances
        from_balance.balance -= amount;
        from_balance.last_updated = Utc::now().timestamp() as u64;
        
        let to_balance = balances.entry(to_key)
            .or_insert(TokenBalance {
                token_address: token_address.to_string(),
                owner: to.clone(),
                balance: 0,
                token_id,
                frozen: false,
                last_updated: Utc::now().timestamp() as u64,
            });

        to_balance.balance += amount;
        to_balance.last_updated = Utc::now().timestamp() as u64;

        drop(balances);

        // Update holders list
        let mut holders = self.holders.lock().await;
        let holder_list = holders.entry(token_address.to_string()).or_insert_with(Vec::new);
        if !holder_list.contains(&to) {
            holder_list.push(to.clone());
        }

        // Create transfer record
        let transfer = TokenTransfer {
            token_address: token_address.to_string(),
            from,
            to,
            amount,
            token_id,
            timestamp: Utc::now().timestamp() as u64,
            transaction_hash: self.generate_transaction_hash()?,
            block_height: 0,
            fee: 0,
        };

        let mut transfers = self.transfers.lock().await;
        transfers.push(transfer.clone());

        // Update statistics
        self.update_token_statistics(token_address).await?;

        Ok(transfer)
    }

    pub async fn approve(
        &self,
        token_address: &str,
        owner: String,
        spender: String,
        amount: u128,
        token_id: Option<u128>,
        expires_at: Option<u64>,
    ) -> Result<TokenApproval, TokenError> {
        if owner == spender {
            return Err(TokenError::SelfApproval);
        }

        let tokens = self.tokens.lock().await;
        let token = tokens.get(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if token.paused {
            return Err(TokenError::TokenPaused);
        }
        drop(tokens);

        let approval = TokenApproval {
            token_address: token_address.to_string(),
            owner,
            spender,
            amount,
            token_id,
            timestamp: Utc::now().timestamp() as u64,
            expires_at,
            transaction_hash: self.generate_transaction_hash()?,
        };

        let mut approvals = self.approvals.lock().await;
        let approval_key = self.generate_approval_key(token_address, &approval.owner, &approval.spender, token_id);
        approvals.insert(approval_key, approval.clone());

        Ok(approval)
    }

    pub async fn transfer_from(
        &self,
        token_address: &str,
        spender: String,
        from: String,
        to: String,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<TokenTransfer, TokenError> {
        // Check approval
        let mut approvals = self.approvals.lock().await;
        let approval_key = self.generate_approval_key(token_address, &from, &spender, token_id);
        let approval = approvals.get_mut(&approval_key)
            .ok_or(TokenError::InsufficientApproval)?;

        if approval.amount < amount {
            return Err(TokenError::InsufficientApproval);
        }

        // Check if approval is expired
        if let Some(expires_at) = approval.expires_at {
            if Utc::now().timestamp() as u64 > expires_at {
                return Err(TokenError::ApprovalExpired);
            }
        }

        // Update approval
        approval.amount -= amount;
        drop(approvals);

        // Perform transfer
        self.transfer(token_address, from, to, amount, token_id).await
    }

    pub async fn get_balance(
        &self,
        token_address: &str,
        owner: &str,
        token_id: Option<u128>,
    ) -> Result<u128, TokenError> {
        let balances = self.balances.lock().await;
        let balance_key = self.generate_balance_key(token_address, owner, token_id);
        
        let balance = balances.get(&balance_key)
            .map(|b| b.balance)
            .unwrap_or(0);

        Ok(balance)
    }

    pub async fn get_approval(
        &self,
        token_address: &str,
        owner: &str,
        spender: &str,
        token_id: Option<u128>,
    ) -> Result<u128, TokenError> {
        let approvals = self.approvals.lock().await;
        let approval_key = self.generate_approval_key(token_address, owner, spender, token_id);
        
        let approval = approvals.get(&approval_key)
            .ok_or(TokenError::ApprovalNotFound)?;

        // Check if approval is expired
        if let Some(expires_at) = approval.expires_at {
            if Utc::now().timestamp() as u64 > expires_at {
                return Err(TokenError::ApprovalExpired);
            }
        }

        Ok(approval.amount)
    }

    pub async fn get_token(&self, token_address: &str) -> Result<Token, TokenError> {
        let tokens = self.tokens.lock().await;
        tokens.get(token_address)
            .cloned()
            .ok_or(TokenError::TokenNotFound)
    }

    pub async fn get_token_statistics(&self, token_address: &str) -> Result<TokenStatistics, TokenError> {
        let stats = self.token_statistics.lock().await;
        stats.get(token_address)
            .cloned()
            .ok_or(TokenError::TokenNotFound)
    }

    pub async fn get_holders(&self, token_address: &str) -> Result<Vec<String>, TokenError> {
        let holders = self.holders.lock().await;
        Ok(holders.get(token_address).cloned().unwrap_or_default())
    }

    pub async fn get_transfers(
        &self,
        token_address: Option<&str>,
        address: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<TokenTransfer>, TokenError> {
        let transfers = self.transfers.lock().await;
        let mut filtered_transfers: Vec<TokenTransfer> = transfers
            .iter()
            .filter(|t| {
                if let Some(token_addr) = token_address {
                    if t.token_address != token_addr {
                        return false;
                    }
                }
                if let Some(addr) = address {
                    if t.from != addr && t.to != addr {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by timestamp (newest first)
        filtered_transfers.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(limit) = limit {
            filtered_transfers.truncate(limit);
        }

        Ok(filtered_transfers)
    }

    pub async fn pause_token(&self, token_address: &str, pauser: &str) -> Result<(), TokenError> {
        let mut tokens = self.tokens.lock().await;
        let token = tokens.get_mut(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if !token.is_pausable {
            return Err(TokenError::PauseNotAllowed);
        }

        if token.owner != pauser {
            return Err(TokenError::Unauthorized);
        }

        token.paused = true;
        Ok(())
    }

    pub async fn unpause_token(&self, token_address: &str, pauser: &str) -> Result<(), TokenError> {
        let mut tokens = self.tokens.lock().await;
        let token = tokens.get_mut(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if token.owner != pauser {
            return Err(TokenError::Unauthorized);
        }

        token.paused = false;
        Ok(())
    }

    pub async fn freeze_balance(
        &self,
        token_address: &str,
        owner: &str,
        token_id: Option<u128>,
        freezer: &str,
    ) -> Result<(), TokenError> {
        let tokens = self.tokens.lock().await;
        let token = tokens.get(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if token.owner != freezer {
            return Err(TokenError::Unauthorized);
        }
        drop(tokens);

        let mut balances = self.balances.lock().await;
        let balance_key = self.generate_balance_key(token_address, owner, token_id);
        let balance = balances.get_mut(&balance_key)
            .ok_or(TokenError::BalanceNotFound)?;

        balance.frozen = true;
        balance.last_updated = Utc::now().timestamp() as u64;

        Ok(())
    }

    pub async fn unfreeze_balance(
        &self,
        token_address: &str,
        owner: &str,
        token_id: Option<u128>,
        unfreezer: &str,
    ) -> Result<(), TokenError> {
        let tokens = self.tokens.lock().await;
        let token = tokens.get(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        if token.owner != unfreezer {
            return Err(TokenError::Unauthorized);
        }
        drop(tokens);

        let mut balances = self.balances.lock().await;
        let balance_key = self.generate_balance_key(token_address, owner, token_id);
        let balance = balances.get_mut(&balance_key)
            .ok_or(TokenError::BalanceNotFound)?;

        balance.frozen = false;
        balance.last_updated = Utc::now().timestamp() as u64;

        Ok(())
    }

    async fn update_token_statistics(&self, token_address: &str) -> Result<(), TokenError> {
        let holders = self.holders.lock().await;
        let transfers = self.transfers.lock().await;
        
        let holder_count = holders.get(token_address).map(|h| h.len() as u64).unwrap_or(0);
        let transfer_count = transfers
            .iter()
            .filter(|t| t.token_address == token_address)
            .count() as u64;

        drop(holders);
        drop(transfers);

        let mut stats = self.token_statistics.lock().await;
        if let Some(token_stats) = stats.get_mut(token_address) {
            token_stats.total_holders = holder_count;
            token_stats.total_transfers = transfer_count;
        }

        Ok(())
    }

    fn validate_token_operation(
        &self,
        token_type: &TokenType,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<(), TokenError> {
        match token_type {
            TokenType::ERC20 | TokenType::Native => {
                if token_id.is_some() {
                    return Err(TokenError::InvalidTokenId);
                }
                if amount == 0 {
                    return Err(TokenError::InvalidAmount);
                }
            }
            TokenType::ERC721 => {
                if token_id.is_none() || amount != 1 {
                    return Err(TokenError::InvalidAmount);
                }
            }
            TokenType::ERC1155 => {
                if token_id.is_none() {
                    return Err(TokenError::InvalidTokenId);
                }
                if amount == 0 {
                    return Err(TokenError::InvalidAmount);
                }
            }
        }
        Ok(())
    }

    fn generate_token_address(&self, name: &str, symbol: &str, owner: &str) -> Result<String, TokenError> {
        let mut hasher = Keccak256::new();
        hasher.update(name.as_bytes());
        hasher.update(symbol.as_bytes());
        hasher.update(owner.as_bytes());
        hasher.update(Utc::now().timestamp().to_string().as_bytes());
        hasher.update(&rand::random::<[u8; 32]>());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&result[12..])))
    }

    fn generate_balance_key(
        &self,
        token_address: &str,
        owner: &str,
        token_id: Option<u128>,
    ) -> String {
        match token_id {
            Some(id) => format!("{}:{}:{}", token_address, owner, id),
            None => format!("{}:{}", token_address, owner),
        }
    }

    fn generate_approval_key(
        &self,
        token_address: &str,
        owner: &str,
        spender: &str,
        token_id: Option<u128>,
    ) -> String {
        match token_id {
            Some(id) => format!("{}:{}:{}:{}", token_address, owner, spender, id),
            None => format!("{}:{}:{}", token_address, owner, spender),
        }
    }

    fn generate_transaction_hash(&self) -> Result<String, TokenError> {
        let mut hasher = Keccak256::new();
        hasher.update(Utc::now().timestamp().to_string().as_bytes());
        hasher.update(&rand::random::<[u8; 32]>());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(result)))
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token not found")]
    TokenNotFound,
    #[error("Balance not found")]
    BalanceNotFound,
    #[error("Approval not found")]
    ApprovalNotFound,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Insufficient approval")]
    InsufficientApproval,
    #[error("Invalid token ID")]
    InvalidTokenId,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid decimals")]
    InvalidDecimals,
    #[error("Invalid token type")]
    InvalidTokenType,
    #[error("Invalid token data")]
    InvalidTokenData,
    #[error("Transfer failed")]
    TransferFailed,
    #[error("Approval failed")]
    ApprovalFailed,
    #[error("Mint failed")]
    MintFailed,
    #[error("Burn failed")]
    BurnFailed,
    #[error("Mint not allowed")]
    MintNotAllowed,
    #[error("Burn not allowed")]
    BurnNotAllowed,
    #[error("Pause not allowed")]
    PauseNotAllowed,
    #[error("Token is paused")]
    TokenPaused,
    #[error("Balance is frozen")]
    BalanceFrozen,
    #[error("Unauthorized operation")]
    Unauthorized,
    #[error("Self transfer not allowed")]
    SelfTransfer,
    #[error("Self approval not allowed")]
    SelfApproval,
    #[error("Approval expired")]
    ApprovalExpired,
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_token() {
        let manager = TokenManager::new();
        let token = manager.create_token(
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            1000000,
            TokenType::ERC20,
            "0x123".to_string(),
            TokenMetadata::default(),
            true,
            true,
            false,
        ).await.unwrap();

        assert_eq!(token.name, "Test Token");
        assert_eq!(token.symbol, "TEST");
        assert_eq!(token.decimals, 18);
        assert_eq!(token.total_supply, 1000000);
    }

    #[tokio::test]
    async fn test_transfer() {
        let manager = TokenManager::new();
        let token = manager.create_token(
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            1000000,
            TokenType::ERC20,
            "0x123".to_string(),
            TokenMetadata::default(),
            true,
            true,
            false,
        ).await.unwrap();

        let transfer = manager.transfer(
            &token.address,
            "0x123".to_string(),
            "0x456".to_string(),
            1000,
            None,
        ).await.unwrap();

        assert_eq!(transfer.amount, 1000);
        assert_eq!(transfer.from, "0x123");
        assert_eq!(transfer.to, "0x456");
    }

    #[tokio::test]
    async fn test_approve_and_transfer_from() {
        let manager = TokenManager::new();
        let token = manager.create_token(
            "Test Token".to_string(),
            "TEST".to_string(),
            18,
            1000000,
            TokenType::ERC20,
            "0x123".to_string(),
            TokenMetadata::default(),
            true,
            true,
            false,
        ).await.unwrap();

        // Approve
        manager.approve(
            &token.address,
            "0x123".to_string(),
            "0x456".to_string(),
            1000,
            None,
            None,
        ).await.unwrap();

        // Transfer from
        let transfer = manager.transfer_from(
            &token.address,
            "0x456".to_string(),
            "0x123".to_string(),
            "0x789".to_string(),
            500,
            None,
        ).await.unwrap();

        assert_eq!(transfer.amount, 500);
        assert_eq!(transfer.from, "0x123");
        assert_eq!(transfer.to, "0x789");
    }
}
