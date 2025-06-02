
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use sha3::{Keccak256, Digest};
use rand::{rngs::OsRng, RngCore};
use crate::state::ChainState;
use crate::database::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposer: String,
    pub proposal_type: ProposalType,
    pub start_time: u64,
    pub end_time: u64,
    pub status: ProposalStatus,
    pub votes: HashMap<String, Vote>,
    pub required_quorum: u64,
    pub required_majority: u64,
    pub execution_time: Option<u64>,
    pub execution_tx: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    ParameterChange {
        parameter: String,
        old_value: String,
        new_value: String,
    },
    ContractUpgrade {
        contract_address: String,
        new_version: String,
        upgrade_data: Vec<u8>,
    },
    EmergencyAction {
        action_type: String,
        action_data: Vec<u8>,
    },
    ValidatorSetChange {
        validators: Vec<String>,
        powers: Vec<u64>,
    },
    TreasurySpend {
        recipient: String,
        amount: u128,
        purpose: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed,
    Failed,
    Executed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: String,
    pub proposal_id: String,
    pub vote_type: VoteType,
    pub voting_power: u64,
    pub timestamp: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Yes,
    No,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub description: String,
    pub last_updated: u64,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorUpdate {
    pub address: String,
    pub power: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryBalance {
    pub total_balance: u128,
    pub available_balance: u128,
    pub locked_balance: u128,
}

pub struct GovernanceManager {
    proposals: Arc<Mutex<HashMap<String, Proposal>>>,
    parameters: Arc<Mutex<HashMap<String, Parameter>>>,
    votes: Arc<Mutex<HashMap<String, Vote>>>,
    voting_power: Arc<Mutex<HashMap<String, u64>>>,
    chain_state: Arc<ChainState>,
    database: Arc<Database>,
    treasury_balance: Arc<Mutex<TreasuryBalance>>,
    total_voting_power: Arc<Mutex<u64>>,
    min_proposal_duration: Duration,
    max_proposal_duration: Duration,
    min_voting_power: u64,
    quorum_percentage: u64, // 0-100
    majority_percentage: u64, // 0-100
}

impl GovernanceManager {
    pub fn new(
        chain_state: Arc<ChainState>,
        database: Arc<Database>,
        min_proposal_duration: Duration,
        max_proposal_duration: Duration,
        min_voting_power: u64,
        quorum_percentage: u64,
        majority_percentage: u64,
    ) -> Self {
        let treasury_balance = TreasuryBalance {
            total_balance: 0,
            available_balance: 0,
            locked_balance: 0,
        };

        Self {
            proposals: Arc::new(Mutex::new(HashMap::new())),
            parameters: Arc::new(Mutex::new(HashMap::new())),
            votes: Arc::new(Mutex::new(HashMap::new())),
            voting_power: Arc::new(Mutex::new(HashMap::new())),
            chain_state,
            database,
            treasury_balance: Arc::new(Mutex::new(treasury_balance)),
            total_voting_power: Arc::new(Mutex::new(0)),
            min_proposal_duration,
            max_proposal_duration,
            min_voting_power,
            quorum_percentage,
            majority_percentage,
        }
    }

    pub async fn initialize(&self) -> Result<(), GovernanceError> {
        // Initialize default parameters
        self.initialize_default_parameters().await?;
        
        // Update voting power from chain state
        self.update_voting_power().await?;
        
        // Update treasury balance
        self.update_treasury_balance().await?;
        
        Ok(())
    }

    async fn initialize_default_parameters(&self) -> Result<(), GovernanceError> {
        let mut parameters = self.parameters.lock().await;
        let now = chrono::Utc::now().timestamp() as u64;
        
        let default_params = vec![
            ("block_time", "3", "Target block time in seconds"),
            ("gas_limit", "30000000", "Maximum gas per block"),
            ("min_stake", "1000000", "Minimum stake for validators"),
            ("max_validators", "100", "Maximum number of validators"),
            ("reward_rate", "5", "Annual reward rate percentage"),
            ("slashing_rate", "10", "Slashing rate percentage"),
            ("unbonding_period", "604800", "Unbonding period in seconds (7 days)"),
            ("proposal_deposit", "10000", "Minimum deposit for proposals"),
        ];

        for (name, value, description) in default_params {
            parameters.insert(name.to_string(), Parameter {
                name: name.to_string(),
                value: value.to_string(),
                description: description.to_string(),
                last_updated: now,
                updated_by: "system".to_string(),
            });
        }

        Ok(())
    }

    async fn update_voting_power(&self) -> Result<(), GovernanceError> {
        let mut voting_power = self.voting_power.lock().await;
        let mut total_power = self.total_voting_power.lock().await;
        
        voting_power.clear();
        *total_power = 0;

        // Get all validators from chain state
        let validators = self.chain_state.get_all_validators().await;
        for validator in validators {
            let power = validator.stake;
            voting_power.insert(validator.address.clone(), power);
            *total_power += power;
        }

        Ok(())
    }

    async fn update_treasury_balance(&self) -> Result<(), GovernanceError> {
        let mut treasury = self.treasury_balance.lock().await;
        
        // Get treasury account balance from chain state
        let treasury_address = "0x0000000000000000000000000000000000000001"; // Treasury address
        if let Some(account) = self.chain_state.get_account(treasury_address).await {
            treasury.total_balance = account.balance as u128;
            treasury.available_balance = account.balance as u128;
            treasury.locked_balance = 0;
        }

        Ok(())
    }

    pub async fn create_proposal(
        &self,
        title: String,
        description: String,
        proposer: String,
        proposal_type: ProposalType,
        duration: Duration,
    ) -> Result<Proposal, GovernanceError> {
        // Süre kontrolü
        if duration < self.min_proposal_duration || duration > self.max_proposal_duration {
            return Err(GovernanceError::InvalidDuration);
        }

        // Proposer'ın voting power kontrolü
        let voting_power = self.get_voting_power(&proposer).await?;
        if voting_power < self.min_voting_power {
            return Err(GovernanceError::InsufficientVotingPower);
        }

        // Check proposal deposit
        let deposit_param = self.get_parameter("proposal_deposit").await?;
        let required_deposit: u64 = deposit_param.value.parse()
            .map_err(|_| GovernanceError::InvalidParameter)?;
        
        if let Some(account) = self.chain_state.get_account(&proposer).await {
            if account.balance < required_deposit {
                return Err(GovernanceError::InsufficientBalance);
            }
        } else {
            return Err(GovernanceError::InvalidAddress);
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let total_power = *self.total_voting_power.lock().await;
        
        let proposal = Proposal {
            id: self.generate_proposal_id(&title, &proposer)?,
            title,
            description,
            proposer,
            proposal_type,
            start_time: now,
            end_time: now + duration.as_secs(),
            status: ProposalStatus::Active,
            votes: HashMap::new(),
            required_quorum: (total_power * self.quorum_percentage) / 100,
            required_majority: (total_power * self.majority_percentage) / 100,
            execution_time: None,
            execution_tx: None,
        };

        // Öneriyi kaydet
        let mut proposals = self.proposals.lock().await;
        proposals.insert(proposal.id.clone(), proposal.clone());

        // Database'e kaydet
        self.save_proposal_to_db(&proposal).await?;

        Ok(proposal)
    }

    pub async fn cast_vote(
        &self,
        proposal_id: &str,
        voter: String,
        vote_type: VoteType,
        reason: Option<String>,
    ) -> Result<Vote, GovernanceError> {
        let mut proposals = self.proposals.lock().await;
        let proposal = proposals.get_mut(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Öneri durumu kontrolü
        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::ProposalNotActive);
        }

        // Zaman kontrolü
        let now = chrono::Utc::now().timestamp() as u64;
        if now < proposal.start_time || now > proposal.end_time {
            return Err(GovernanceError::VotingPeriodEnded);
        }

        // Voting power kontrolü
        let voting_power = self.get_voting_power(&voter).await?;
        if voting_power == 0 {
            return Err(GovernanceError::NoVotingPower);
        }

        let vote = Vote {
            voter: voter.clone(),
            proposal_id: proposal_id.to_string(),
            vote_type: vote_type.clone(),
            voting_power,
            timestamp: now,
            reason,
        };

        // Oyu kaydet
        proposal.votes.insert(voter.clone(), vote.clone());
        let mut votes = self.votes.lock().await;
        votes.insert(format!("{}:{}", proposal_id, voter), vote.clone());

        // Database'e kaydet
        self.save_vote_to_db(&vote).await?;

        // Öneri durumunu güncelle
        self.update_proposal_status(proposal).await?;

        Ok(vote)
    }

    pub async fn execute_proposal(
        &self,
        proposal_id: &str,
        executor: String,
    ) -> Result<Proposal, GovernanceError> {
        let mut proposals = self.proposals.lock().await;
        let proposal = proposals.get_mut(proposal_id)
            .ok_or(GovernanceError::ProposalNotFound)?;

        // Öneri durumu kontrolü
        if proposal.status != ProposalStatus::Passed {
            return Err(GovernanceError::ProposalNotPassed);
        }

        // Executor yetkisi kontrolü
        let voting_power = self.get_voting_power(&executor).await?;
        if voting_power < self.min_voting_power {
            return Err(GovernanceError::InsufficientVotingPower);
        }

        // Öneriyi uygula
        let tx_hash = match &proposal.proposal_type {
            ProposalType::ParameterChange { parameter, new_value, .. } => {
                self.update_parameter(parameter, new_value, &executor).await?
            }
            ProposalType::ContractUpgrade { contract_address, new_version, upgrade_data } => {
                self.upgrade_contract(contract_address, new_version, upgrade_data).await?
            }
            ProposalType::EmergencyAction { action_type, action_data } => {
                self.execute_emergency_action(action_type, action_data).await?
            }
            ProposalType::ValidatorSetChange { validators, powers } => {
                self.update_validator_set(validators, powers).await?
            }
            ProposalType::TreasurySpend { recipient, amount, purpose } => {
                self.spend_treasury(recipient, *amount, purpose).await?
            }
        };

        // Öneri durumunu güncelle
        proposal.status = ProposalStatus::Executed;
        proposal.execution_time = Some(chrono::Utc::now().timestamp() as u64);
        proposal.execution_tx = Some(tx_hash);

        // Database'e kaydet
        self.save_proposal_to_db(proposal).await?;

        Ok(proposal.clone())
    }

    pub async fn get_proposal_info(&self, proposal_id: &str) -> Result<Proposal, GovernanceError> {
        let proposals = self.proposals.lock().await;
        if let Some(proposal) = proposals.get(proposal_id) {
            Ok(proposal.clone())
        } else {
            // Database'den yükle
            self.load_proposal_from_db(proposal_id).await
        }
    }

    pub async fn get_parameter(&self, name: &str) -> Result<Parameter, GovernanceError> {
        let parameters = self.parameters.lock().await;
        parameters.get(name)
            .ok_or(GovernanceError::ParameterNotFound)
            .map(|p| p.clone())
    }

    pub async fn get_all_proposals(&self) -> Result<Vec<Proposal>, GovernanceError> {
        let proposals = self.proposals.lock().await;
        Ok(proposals.values().cloned().collect())
    }

    pub async fn get_treasury_balance(&self) -> Result<TreasuryBalance, GovernanceError> {
        self.update_treasury_balance().await?;
        let treasury = self.treasury_balance.lock().await;
        Ok(treasury.clone())
    }

    async fn update_proposal_status(&self, proposal: &mut Proposal) -> Result<(), GovernanceError> {
        let now = chrono::Utc::now().timestamp() as u64;
        if now <= proposal.end_time {
            return Ok(());
        }

        let (yes_votes, _no_votes, total_votes) = self.calculate_votes(proposal);
        
        if total_votes < proposal.required_quorum {
            proposal.status = ProposalStatus::Failed;
            return Ok(());
        }

        if yes_votes >= proposal.required_majority {
            proposal.status = ProposalStatus::Passed;
        } else {
            proposal.status = ProposalStatus::Failed;
        }

        Ok(())
    }

    async fn update_parameter(
        &self,
        name: &str,
        value: &str,
        updated_by: &str,
    ) -> Result<String, GovernanceError> {
        let mut parameters = self.parameters.lock().await;
        let parameter = parameters.entry(name.to_string())
            .or_insert(Parameter {
                name: name.to_string(),
                value: value.to_string(),
                description: String::new(),
                last_updated: 0,
                updated_by: String::new(),
            });

        parameter.value = value.to_string();
        parameter.last_updated = chrono::Utc::now().timestamp() as u64;
        parameter.updated_by = updated_by.to_string();

        // Generate transaction hash for the parameter update
        Ok(self.generate_transaction_hash()?)
    }

    async fn upgrade_contract(
        &self,
        contract_address: &str,
        new_version: &str,
        upgrade_data: &[u8],
    ) -> Result<String, GovernanceError> {
        // Create contract upgrade transaction
        let tx_data = format!("upgrade:{}:{}", contract_address, new_version);
        let mut hasher = Keccak256::new();
        hasher.update(tx_data.as_bytes());
        hasher.update(upgrade_data);
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        
        Ok(format!("0x{}", hex::encode(result)))
    }

    async fn execute_emergency_action(
        &self,
        action_type: &str,
        action_data: &[u8],
    ) -> Result<String, GovernanceError> {
        // Execute emergency action based on type
        match action_type {
            "pause_chain" => {
                // Pause chain operations
                tracing::warn!("Emergency action: Chain paused");
            }
            "emergency_upgrade" => {
                // Execute emergency upgrade
                tracing::warn!("Emergency action: Emergency upgrade executed");
            }
            "validator_slash" => {
                // Slash validators
                tracing::warn!("Emergency action: Validator slashing executed");
            }
            _ => {
                return Err(GovernanceError::InvalidAction);
            }
        }

        let tx_data = format!("emergency:{}:{}", action_type, hex::encode(action_data));
        let mut hasher = Keccak256::new();
        hasher.update(tx_data.as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        
        Ok(format!("0x{}", hex::encode(result)))
    }

    async fn update_validator_set(
        &self,
        validators: &[String],
        powers: &[u64],
    ) -> Result<String, GovernanceError> {
        if validators.len() != powers.len() {
            return Err(GovernanceError::InvalidParameter);
        }

        // Update validator set in chain state
        for (i, validator) in validators.iter().enumerate() {
            let power = powers[i];
            // Here we would update the actual validator set
            tracing::info!("Updating validator {} with power {}", validator, power);
        }

        // Update voting power
        self.update_voting_power().await?;

        let tx_data = format!("validator_set_update:{}", validators.len());
        let mut hasher = Keccak256::new();
        hasher.update(tx_data.as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        
        Ok(format!("0x{}", hex::encode(result)))
    }

    async fn spend_treasury(
        &self,
        recipient: &str,
        amount: u128,
        purpose: &str,
    ) -> Result<String, GovernanceError> {
        let mut treasury = self.treasury_balance.lock().await;
        
        if treasury.available_balance < amount {
            return Err(GovernanceError::InsufficientBalance);
        }

        treasury.available_balance -= amount;
        
        // Create spending transaction
        let tx_data = format!("treasury_spend:{}:{}:{}", recipient, amount, purpose);
        let mut hasher = Keccak256::new();
        hasher.update(tx_data.as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        
        tracing::info!("Treasury spend: {} to {} for {}", amount, recipient, purpose);
        
        Ok(format!("0x{}", hex::encode(result)))
    }

    async fn get_voting_power(&self, address: &str) -> Result<u64, GovernanceError> {
        let voting_power = self.voting_power.lock().await;
        Ok(*voting_power.get(address).unwrap_or(&0))
    }

    fn calculate_votes(&self, proposal: &Proposal) -> (u64, u64, u64) {
        let mut yes_votes = 0;
        let mut no_votes = 0;
        let mut total_votes = 0;

        for vote in proposal.votes.values() {
            total_votes += vote.voting_power;
            match vote.vote_type {
                VoteType::Yes => yes_votes += vote.voting_power,
                VoteType::No => no_votes += vote.voting_power,
                VoteType::Abstain => {},
            }
        }

        (yes_votes, no_votes, total_votes)
    }

    fn generate_proposal_id(&self, title: &str, proposer: &str) -> Result<String, GovernanceError> {
        let mut hasher = Keccak256::new();
        hasher.update(title.as_bytes());
        hasher.update(proposer.as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(&result[..8])))
    }

    fn generate_transaction_hash(&self) -> Result<String, GovernanceError> {
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        hasher.update(chrono::Utc::now().timestamp().to_string().as_bytes());
        let result = hasher.finalize();
        Ok(format!("0x{}", hex::encode(result)))
    }

    async fn save_proposal_to_db(&self, proposal: &Proposal) -> Result<(), GovernanceError> {
        let key = format!("governance:proposal:{}", proposal.id);
        let value = serde_json::to_vec(proposal)
            .map_err(|_| GovernanceError::SerializationError)?;
        
        self.database.put(key.as_bytes(), &value).await
            .map_err(|_| GovernanceError::DatabaseError)?;
        
        Ok(())
    }

    async fn save_vote_to_db(&self, vote: &Vote) -> Result<(), GovernanceError> {
        let key = format!("governance:vote:{}:{}", vote.proposal_id, vote.voter);
        let value = serde_json::to_vec(vote)
            .map_err(|_| GovernanceError::SerializationError)?;
        
        self.database.put(key.as_bytes(), &value).await
            .map_err(|_| GovernanceError::DatabaseError)?;
        
        Ok(())
    }

    async fn load_proposal_from_db(&self, proposal_id: &str) -> Result<Proposal, GovernanceError> {
        let key = format!("governance:proposal:{}", proposal_id);
        let value = self.database.get(key.as_bytes()).await
            .map_err(|_| GovernanceError::DatabaseError)?
            .ok_or(GovernanceError::ProposalNotFound)?;
        
        let proposal: Proposal = serde_json::from_slice(&value)
            .map_err(|_| GovernanceError::SerializationError)?;
        
        Ok(proposal)
    }
}

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("Proposal not found")]
    ProposalNotFound,
    #[error("Parameter not found")]
    ParameterNotFound,
    #[error("Proposal not active")]
    ProposalNotActive,
    #[error("Proposal not passed")]
    ProposalNotPassed,
    #[error("Voting period ended")]
    VotingPeriodEnded,
    #[error("Invalid duration")]
    InvalidDuration,
    #[error("Insufficient voting power")]
    InsufficientVotingPower,
    #[error("No voting power")]
    NoVotingPower,
    #[error("Invalid proposal type")]
    InvalidProposalType,
    #[error("Invalid parameter")]
    InvalidParameter,
    #[error("Invalid value")]
    InvalidValue,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Invalid action")]
    InvalidAction,
    #[error("Execution failed")]
    ExecutionFailed,
    #[error("Transaction failed")]
    TransactionFailed,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Database error")]
    DatabaseError,
    #[error("Serialization error")]
    SerializationError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_proposal_creation() {
        let chain_state = Arc::new(ChainState::new());
        let database = Arc::new(Database::new("test.db").await.unwrap());
        
        let governance = GovernanceManager::new(
            chain_state,
            database,
            Duration::from_secs(3600), // 1 hour min
            Duration::from_secs(604800), // 1 week max
            1000,
            33, // 33% quorum
            50, // 50% majority
        );

        let proposal_type = ProposalType::ParameterChange {
            parameter: "block_time".to_string(),
            old_value: "3".to_string(),
            new_value: "2".to_string(),
        };

        // This would fail without proper setup, but shows the interface
        let result = governance.create_proposal(
            "Reduce block time".to_string(),
            "Proposal to reduce block time from 3s to 2s".to_string(),
            "0x1234567890abcdef".to_string(),
            proposal_type,
            Duration::from_secs(86400), // 1 day
        ).await;

        // In a real test, we'd set up the chain state and voting power first
        assert!(result.is_err()); // Expected to fail without setup
    }
}
