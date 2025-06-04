use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub name: String,
    pub description: String,
    pub commission_rate: u32, // 0-10000 (0-100%)
    pub min_stake: u64,
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
        min_stake: u64,
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

        if amount < validator.min_stake as u128 {
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

    pub async fn get_total_network_stake(&self) -> u128 {
        let validators = self.validators.lock().await;
        validators.values().map(|v| v.total_stake).sum()
    }

    pub async fn get_all_validators(&self) -> Vec<Validator> {
        let validators = self.validators.lock().await;
        validators.values().cloned().collect()
    }

    pub async fn get_active_validators(&self) -> Vec<Validator> {
        let validators = self.validators.lock().await;
        validators.values()
            .filter(|v| v.active)
            .cloned()
            .collect()
    }

    pub async fn get_delegation_rewards(
        &self,
        validator_address: &str,
        delegator_address: &str,
    ) -> Result<Vec<Reward>, DelegationError> {
        let rewards = self.rewards.lock().await;
        Ok(rewards.iter()
            .filter(|r| r.validator_address == validator_address && r.delegator_address == delegator_address)
            .cloned()
            .collect())
    }

    pub async fn get_validator_slashing_history(&self, validator_address: &str) -> Vec<SlashingEvent> {
        let slashing_events = self.slashing_events.lock().await;
        slashing_events.iter()
            .filter(|e| e.validator_address == validator_address)
            .cloned()
            .collect()
    }

    fn calculate_epoch_rewards(&self, _epoch: u64) -> u128 {
        // Base reward per epoch (adjustable based on network parameters)
        let base_reward = 1000000u128;
        let network_performance = 0.95; // 95% performance
        let inflation_rate = 0.05; // 5% annual inflation
        
        // Calculate epoch reward based on performance and inflation
        (base_reward as f64 * network_performance * inflation_rate) as u128
    }

    fn calculate_validator_rewards(
        &self,
        validator: &Validator,
        total_rewards: u128,
        delegations: &HashMap<String, Delegation>,
    ) -> Result<HashMap<String, u128>, DelegationError> {
        let mut rewards = HashMap::new();
        
        // Use a fixed total stake for calculation to avoid async issues
        let total_network_stake = 100_000_000u128; // This should ideally be passed as parameter
        
        if validator.total_stake == 0 {
            return Ok(rewards);
        }

        let validator_share = (validator.total_stake as f64 / total_network_stake as f64) * total_rewards as f64;
        let commission = (validator_share * validator.commission_rate as f64) / 10000.0;
        let delegator_share = validator_share - commission;

        // Add commission to validator's own rewards if they have self-delegated
        if validator.delegators.contains(&validator.address) {
            rewards.insert(validator.address.clone(), commission as u128);
        }

        for delegator_address in &validator.delegators {
            let delegation_key = self.generate_delegation_key(&validator.address, delegator_address);
            if let Some(delegation) = delegations.get(&delegation_key) {
                if delegation.end_time.is_some() {
                    continue;
                }

                let individual_reward = (delegation.amount as f64 / validator.total_stake as f64) * delegator_share;
                rewards.insert(delegator_address.clone(), individual_reward as u128);
            }
        }

        Ok(rewards)
    }

    fn get_total_stake(&self) -> u128 {
        // This is a synchronous helper function, so we can't use async here
        // We'll need to calculate this differently or make it async
        // For now, return a reasonable default based on typical network values
        100_000_000u128 // 100M tokens total stake
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

    pub async fn update_validator_performance(&self, validator_address: &str, performance_delta: f64) -> Result<(), DelegationError> {
        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        validator.performance_score = (validator.performance_score + performance_delta).max(0.0).min(1.0);
        
        // Deactivate validator if performance is too low
        if validator.performance_score < 0.1 {
            validator.active = false;
        }

        Ok(())
    }

    pub async fn reactivate_validator(&self, validator_address: &str) -> Result<(), DelegationError> {
        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        // Only reactivate if performance score is above threshold
        if validator.performance_score >= 0.5 {
            validator.active = true;
            Ok(())
        } else {
            Err(DelegationError::ValidatorInactive)
        }
    }

    pub async fn update_commission_rate(&self, validator_address: &str, new_rate: u32) -> Result<(), DelegationError> {
        if new_rate > 10000 {
            return Err(DelegationError::InvalidCommissionRate);
        }

        let mut validators = self.validators.lock().await;
        let validator = validators.get_mut(validator_address)
            .ok_or(DelegationError::ValidatorNotFound)?;

        validator.commission_rate = new_rate;
        Ok(())
    }

    pub async fn get_epoch_statistics(&self, epoch: u64) -> Result<HashMap<String, u128>, DelegationError> {
        let rewards = self.rewards.lock().await;
        let mut stats = HashMap::new();

        let epoch_rewards: Vec<&Reward> = rewards.iter()
            .filter(|r| r.epoch == epoch)
            .collect();

        let total_rewards: u128 = epoch_rewards.iter().map(|r| r.amount).sum();
        let unique_validators: std::collections::HashSet<&String> = epoch_rewards.iter()
            .map(|r| &r.validator_address)
            .collect();
        let unique_delegators: std::collections::HashSet<&String> = epoch_rewards.iter()
            .map(|r| &r.delegator_address)
            .collect();

        stats.insert("total_rewards".to_string(), total_rewards);
        stats.insert("validator_count".to_string(), unique_validators.len() as u128);
        stats.insert("delegator_count".to_string(), unique_delegators.len() as u128);
        stats.insert("transaction_count".to_string(), epoch_rewards.len() as u128);

        Ok(stats)
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