use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub name: String,
    pub description: String,
    pub commission_rate: u32, // 0-10000 (0-100%)
    pub min_stake: u128,
    pub max_stake: u128,
    pub total_stake: u128,
    pub delegators: HashSet<String>,
    pub active: bool,
    pub created_at: u64,
    pub last_reward_at: u64,
    pub performance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub validator_address: String,
    pub delegator_address: String,
    pub amount: u128,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub rewards_claimed: u128,
    pub last_claim_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reward {
    pub validator_address: String,
    pub delegator_address: String,
    pub amount: u128,
    pub timestamp: u64,
    pub epoch: u64,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub validator_address: String,
    pub reason: SlashingReason,
    pub amount: u128,
    pub timestamp: u64,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    DoubleSigning,
    Downtime,
    InvalidBlock,
    InvalidVote,
    Other(String),
}

pub struct DelegationManager {
    validators: Arc<Mutex<HashMap<String, Validator>>>,
    delegations: Arc<Mutex<HashMap<String, Delegation>>>,
    rewards: Arc<Mutex<Vec<Reward>>>,
    slashing_events: Arc<Mutex<Vec<SlashingEvent>>>,
    epoch_duration: Duration,
    current_epoch: u64,
}

impl DelegationManager {
    pub fn new(epoch_duration: Duration) -> Self {
        Self {
            validators: Arc::new(Mutex::new(HashMap::new())),
            delegations: Arc::new(Mutex::new(HashMap::new())),
            rewards: Arc::new(Mutex::new(Vec::new())),
            slashing_events: Arc::new(Mutex::new(Vec::new())),
            epoch_duration,
            current_epoch: 0,
        }
    }

    pub async fn register_validator(
        &self,
        address: String,
        name: String,
        description: String,
        commission_rate: u32,
        min_stake: u128,
        max_stake: u128,
    ) -> Result<Validator, DelegationError> {
        if commission_rate > 10000 {
            return Err(DelegationError::InvalidCommissionRate);
        }

        let validator = Validator {
            address: address.clone(),
            name,
            description,
            commission_rate,
            min_stake,
            max_stake,
            total_stake: 0,
            delegators: HashSet::new(),
            active: true,
            created_at: chrono::Utc::now().timestamp() as u64,
            last_reward_at: 0,
            performance_score: 1.0,
        };

        let mut validators = self.validators.lock().await;
        validators.insert(address.clone(), validator.clone());

        Ok(validator)
    }

    pub async fn delegate(
        &self,
        validator_address: &str,
        delegator_address: String,
        amount: u128,
    ) -> Result<Delegation, DelegationError> {
        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        if !validator.active {
            return Err(DelegationError::ValidatorInactive);
        }

        if amount < validator.min_stake {
            return Err(DelegationError::InsufficientStake);
        }

        if validator.total_stake + amount > validator.max_stake {
            return Err(DelegationError::ExceedsMaxStake);
        }

        let delegation = Delegation {
            validator_address: validator_address.to_string(),
            delegator_address: delegator_address.clone(),
            amount,
            start_time: chrono::Utc::now().timestamp() as u64,
            end_time: None,
            rewards_claimed: 0,
            last_claim_time: 0,
        };

        let mut delegations = self.delegations.lock().await;
        let delegation_key = self.generate_delegation_key(validator_address, &delegator_address);
        delegations.insert(delegation_key, delegation.clone());

        validator.total_stake += amount;
        validator.delegators.insert(delegator_address);

        Ok(delegation)
    }

    pub async fn undelegate(
        &self,
        validator_address: &str,
        delegator_address: &str,
    ) -> Result<Delegation, DelegationError> {
        let mut delegations = self.delegations.lock().await;
        let delegation_key = self.generate_delegation_key(validator_address, delegator_address);
        
        let delegation = delegations.get_mut(&delegation_key)
            .ok_or(DelegationError::DelegationNotFound)?;

        if delegation.end_time.is_some() {
            return Err(DelegationError::AlreadyUndelegated);
        }

        delegation.end_time = Some(chrono::Utc::now().timestamp() as u64);

        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        validator.total_stake -= delegation.amount;
        validator.delegators.remove(delegator_address);

        Ok(delegation.clone())
    }

    pub async fn distribute_rewards(&self, epoch: u64) -> Result<Vec<Reward>, DelegationError> {
        let validators = self.validators.lock().await;
        let mut delegations = self.delegations.lock().await;
        let mut rewards = self.rewards.lock().await;

        let mut epoch_rewards = Vec::new();
        let total_rewards = self.calculate_epoch_rewards(epoch);

        for validator in validators.values() {
            if !validator.active || validator.total_stake == 0 {
                continue;
            }

            let validator_rewards = self.calculate_validator_rewards(
                validator,
                total_rewards,
                &delegations,
            )?;

            for (delegator_address, amount) in validator_rewards {
                let reward = Reward {
                    validator_address: validator.address.clone(),
                    delegator_address: delegator_address.clone(),
                    amount,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    epoch,
                    transaction_hash: self.generate_transaction_hash()?,
                };

                // Delegasyon bakiyesini güncelle
                let delegation_key = self.generate_delegation_key(&validator.address, &delegator_address);
                if let Some(delegation) = delegations.get_mut(&delegation_key) {
                    delegation.rewards_claimed += amount;
                    delegation.last_claim_time = reward.timestamp;
                }

                rewards.push(reward.clone());
                epoch_rewards.push(reward);
            }
        }

        Ok(epoch_rewards)
    }

    pub async fn slash_validator(
        &self,
        validator_address: &str,
        reason: SlashingReason,
        amount: u128,
        evidence: String,
    ) -> Result<SlashingEvent, DelegationError> {
        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        if !validator.active {
            return Err(DelegationError::ValidatorInactive);
        }

        let slashing_event = SlashingEvent {
            validator_address: validator_address.to_string(),
            reason: reason.clone(),
            amount,
            timestamp: chrono::Utc::now().timestamp() as u64,
            evidence,
        };

        // Validator'ı cezalandır
        validator.performance_score *= 0.5;
        if validator.performance_score < 0.1 {
            validator.active = false;
        }

        // Slashing olayını kaydet
        let mut slashing_events = self.slashing_events.lock().await;
        slashing_events.push(slashing_event.clone());

        Ok(slashing_event)
    }

    pub async fn get_validator_info(&self, address: &str) -> Result<Validator, DelegationError> {
        let validators = self.validators.lock().await;
        let validator = validators.get(address)
            .ok_or(DelegationError::ValidatorNotFound)?
            .clone();

        Ok(validator)
    }

    pub async fn get_delegation_info(
        &self,
        validator_address: &str,
        delegator_address: &str,
    ) -> Result<Delegation, DelegationError> {
        let delegations = self.delegations.lock().await;
        let delegation_key = self.generate_delegation_key(validator_address, delegator_address);
        
        let delegation = delegations.get(&delegation_key)
            .ok_or(DelegationError::DelegationNotFound)?
            .clone();

        Ok(delegation)
    }

    fn calculate_epoch_rewards(&self, epoch: u64) -> u128 {
        // TODO: Implement epoch reward calculation based on network parameters
        1000000 // Örnek değer
    }

    fn calculate_validator_rewards(
        &self,
        validator: &Validator,
        total_rewards: u128,
        delegations: &HashMap<String, Delegation>,
    ) -> Result<HashMap<String, u128>, DelegationError> {
        let mut rewards = HashMap::new();
        let validator_share = (validator.total_stake as f64 / self.get_total_stake() as f64) * total_rewards as f64;
        let commission = (validator_share * validator.commission_rate as f64) / 10000.0;
        let delegator_share = validator_share - commission;

        for delegator_address in &validator.delegators {
            let delegation_key = self.generate_delegation_key(&validator.address, delegator_address);
            if let Some(delegation) = delegations.get(&delegation_key) {
                if delegation.end_time.is_some() {
                    continue;
                }

                let delegator_share = (delegation.amount as f64 / validator.total_stake as f64) * delegator_share;
                rewards.insert(delegator_address.clone(), delegator_share as u128);
            }
        }

        Ok(rewards)
    }

    fn get_total_stake(&self) -> u128 {
        // TODO: Implement total stake calculation
        10000000 // Örnek değer
    }

    fn generate_delegation_key(&self, validator_address: &str, delegator_address: &str) -> String {
        format!("{}:{}", validator_address, delegator_address)
    }

    fn generate_transaction_hash(&self) -> Result<String, DelegationError> {
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(result)))
    }
}

#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("Validator not found")]
    ValidatorNotFound,
    #[error("Delegation not found")]
    DelegationNotFound,
    #[error("Validator is inactive")]
    ValidatorInactive,
    #[error("Insufficient stake")]
    InsufficientStake,
    #[error("Exceeds maximum stake")]
    ExceedsMaxStake,
    #[error("Invalid commission rate")]
    InvalidCommissionRate,
    #[error("Already undelegated")]
    AlreadyUndelegated,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Reward calculation failed")]
    RewardCalculationFailed,
    #[error("Slashing failed")]
    SlashingFailed,
    #[error("Transaction failed")]
    TransactionFailed,
} 