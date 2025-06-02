use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use sha3::{Keccak256, Digest};
use std::str::FromStr;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    ERC20,
    ERC721,
    ERC1155,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub description: Option<String>,
    pub image: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Vec<TokenAttribute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAttribute {
    pub trait_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub token_address: String,
    pub owner: String,
    pub balance: u128,
    pub token_id: Option<u128>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenApproval {
    pub token_address: String,
    pub owner: String,
    pub spender: String,
    pub amount: u128,
    pub token_id: Option<u128>,
    pub timestamp: u64,
}

pub struct TokenManager {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    balances: Arc<Mutex<HashMap<String, TokenBalance>>>,
    transfers: Arc<Mutex<Vec<TokenTransfer>>>,
    approvals: Arc<Mutex<HashMap<String, TokenApproval>>>,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            balances: Arc::new(Mutex::new(HashMap::new())),
            transfers: Arc::new(Mutex::new(Vec::new())),
            approvals: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_token(
        &self,
        name: String,
        symbol: String,
        decimals: u8,
        token_type: TokenType,
        owner: String,
        metadata: TokenMetadata,
    ) -> Result<Token, TokenError> {
        let address = self.generate_token_address(&name, &symbol)?;
        
        let token = Token {
            address: address.clone(),
            name,
            symbol,
            decimals,
            total_supply: 0,
            token_type,
            owner,
            created_at: chrono::Utc::now().timestamp() as u64,
            metadata,
        };

        let mut tokens = self.tokens.lock().await;
        tokens.insert(address.clone(), token.clone());

        Ok(token)
    }

    pub async fn mint(
        &self,
        token_address: &str,
        to: String,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<TokenTransfer, TokenError> {
        let mut tokens = self.tokens.lock().await;
        let token = tokens.get_mut(token_address)
            .ok_or(TokenError::TokenNotFound)?;

        // Token tipine göre doğrulama
        match token.token_type {
            TokenType::ERC20 => {
                if token_id.is_some() {
                    return Err(TokenError::InvalidTokenId);
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
            }
        }

        // Bakiyeyi güncelle
        let mut balances = self.balances.lock().await;
        let balance_key = self.generate_balance_key(token_address, &to, token_id);
        
        let balance = balances.entry(balance_key.clone())
            .or_insert(TokenBalance {
                token_address: token_address.to_string(),
                owner: to.clone(),
                balance: 0,
                token_id,
            });

        balance.balance += amount;
        token.total_supply += amount;

        // Transfer kaydı oluştur
        let transfer = TokenTransfer {
            token_address: token_address.to_string(),
            from: "0x0000000000000000000000000000000000000000".to_string(),
            to,
            amount,
            token_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
            transaction_hash: self.generate_transaction_hash()?,
        };

        let mut transfers = self.transfers.lock().await;
        transfers.push(transfer.clone());

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
        // Bakiyeleri kontrol et
        let mut balances = self.balances.lock().await;
        let from_key = self.generate_balance_key(token_address, &from, token_id);
        let to_key = self.generate_balance_key(token_address, &to, token_id);

        let from_balance = balances.get_mut(&from_key)
            .ok_or(TokenError::InsufficientBalance)?;

        if from_balance.balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Bakiyeleri güncelle
        from_balance.balance -= amount;
        
        let to_balance = balances.entry(to_key)
            .or_insert(TokenBalance {
                token_address: token_address.to_string(),
                owner: to.clone(),
                balance: 0,
                token_id,
            });

        to_balance.balance += amount;

        // Transfer kaydı oluştur
        let transfer = TokenTransfer {
            token_address: token_address.to_string(),
            from,
            to,
            amount,
            token_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
            transaction_hash: self.generate_transaction_hash()?,
        };

        let mut transfers = self.transfers.lock().await;
        transfers.push(transfer.clone());

        Ok(transfer)
    }

    pub async fn approve(
        &self,
        token_address: &str,
        owner: String,
        spender: String,
        amount: u128,
        token_id: Option<u128>,
    ) -> Result<TokenApproval, TokenError> {
        let approval = TokenApproval {
            token_address: token_address.to_string(),
            owner,
            spender,
            amount,
            token_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        let mut approvals = self.approvals.lock().await;
        let approval_key = self.generate_approval_key(token_address, &approval.owner, &approval.spender, token_id);
        approvals.insert(approval_key, approval.clone());

        Ok(approval)
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
            .ok_or(TokenError::BalanceNotFound)?;

        Ok(balance.balance)
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

        Ok(approval.amount)
    }

    fn generate_token_address(&self, name: &str, symbol: &str) -> Result<String, TokenError> {
        let mut hasher = Keccak256::new();
        hasher.update(name.as_bytes());
        hasher.update(symbol.as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
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
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        hasher.update(rand::random::<u64>().to_string().as_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(result)))
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
    #[error("Transfer failed")]
    TransferFailed,
    #[error("Approval failed")]
    ApprovalFailed,
    #[error("Mint failed")]
    MintFailed,
    #[error("Burn failed")]
    BurnFailed,
} 