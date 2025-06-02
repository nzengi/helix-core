use anyhow::Result;
use rand::{rngs::OsRng, RngCore};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GearParameters {
    pub beta_angle: f64,
    pub torque_ratio: f64,
    pub gear_ratio: f64,
    pub efficiency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressMetadata {
    pub address: Address,
    pub gear_params: GearParameters,
    pub creation_time: chrono::DateTime<chrono::Utc>,
    pub address_type: AddressType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AddressType {
    User,
    Validator,
    Contract,
    Multisig,
}

impl Address {
    pub fn new(address: String) -> Result<Self> {
        if !Self::is_valid(&address) {
            anyhow::bail!("Invalid address format");
        }
        Ok(Address(address))
    }

    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let public_key_bytes = public_key.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&public_key_bytes[1..]);
        let hash = hasher.finalize();

        Address(format!("0x{}", hex::encode(&hash[12..])))
    }

    pub fn from_gear_parameters(gear_params: &GearParameters) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(&gear_params.beta_angle.to_le_bytes());
        hasher.update(&gear_params.torque_ratio.to_le_bytes());
        hasher.update(&gear_params.gear_ratio.to_le_bytes());
        hasher.update(&gear_params.efficiency.to_le_bytes());

        let hash = hasher.finalize();
        Address(format!("0xg{}", hex::encode(&hash[12..])))
    }

    pub fn generate_validator_address(stake: u64, beta_angle: f64) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(b"validator:");
        hasher.update(&stake.to_le_bytes());
        hasher.update(&beta_angle.to_le_bytes());
        hasher.update(&chrono::Utc::now().timestamp().to_le_bytes());

        let hash = hasher.finalize();
        Address(format!("0xv{}", hex::encode(&hash[12..])))
    }

    pub fn generate_contract_address(deployer: &Address, nonce: u64) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(deployer.as_bytes());
        hasher.update(&nonce.to_le_bytes());

        let hash = hasher.finalize();
        Address(format!("0xc{}", hex::encode(&hash[12..])))
    }

    pub fn generate_multisig_address(owners: &[Address], threshold: u32) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(b"multisig:");
        for owner in owners {
            hasher.update(owner.as_bytes());
        }
        hasher.update(&threshold.to_le_bytes());

        let hash = hasher.finalize();
        Address(format!("0xm{}", hex::encode(&hash[12..])))
    }

    pub fn is_valid(address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }

        let hex_part = &address[2..];
        if hex_part.len() != 40 && hex_part.len() != 41 {
            return false;
        }

        hex_part.chars().all(|c| c.is_ascii_hexdigit())
    }

    pub fn get_address_type(&self) -> AddressType {
        if self.0.starts_with("0xv") {
            AddressType::Validator
        } else if self.0.starts_with("0xc") {
            AddressType::Contract
        } else if self.0.starts_with("0xm") {
            AddressType::Multisig
        } else if self.0.starts_with("0xg") {
            AddressType::User
        } else {
            AddressType::User
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn checksum(&self) -> String {
        let address = self.0.trim_start_matches("0x").to_lowercase();
        let mut hasher = Keccak256::new();
        hasher.update(address.as_bytes());
        let hash = hasher.finalize();

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in address.chars().enumerate() {
            if c.is_ascii_digit() {
                result.push(c);
            } else {
                let hash_byte = hash[i / 2];
                let nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0xf
                };
                if nibble >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c);
                }
            }
        }

        result
    }
}

impl GearParameters {
    pub fn new(
        beta_angle: f64,
        torque_ratio: f64,
        gear_ratio: f64,
        efficiency: f64,
    ) -> Result<Self> {
        if !(10.0..=80.0).contains(&beta_angle) {
            anyhow::bail!("Beta angle must be between 10 and 80 degrees");
        }

        if !(0.1..=10.0).contains(&torque_ratio) {
            anyhow::bail!("Torque ratio must be between 0.1 and 10.0");
        }

        if !(0.5..=5.0).contains(&gear_ratio) {
            anyhow::bail!("Gear ratio must be between 0.5 and 5.0");
        }

        if !(0.1..=1.0).contains(&efficiency) {
            anyhow::bail!("Efficiency must be between 0.1 and 1.0");
        }

        Ok(Self {
            beta_angle,
            torque_ratio,
            gear_ratio,
            efficiency,
        })
    }

    pub fn calculate_torque(&self, input_force: f64) -> f64 {
        input_force * self.torque_ratio * self.efficiency * self.beta_angle.to_radians().sin()
    }

    pub fn is_self_locking(&self) -> bool {
        let friction_coefficient = 0.15; // Typical steel-on-steel
        let lead_angle = (self.gear_ratio / (2.0 * std::f64::consts::PI)).atan();
        lead_angle.tan() <= friction_coefficient * self.beta_angle.to_radians().cos()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Address {
    fn from(address: String) -> Self {
        Address(address)
    }
}

impl From<&str> for Address {
    fn from(address: &str) -> Self {
        Address(address.to_string())
    }
}

pub struct AddressGenerator {
    secp: Secp256k1<secp256k1::All>,
}

impl AddressGenerator {
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    pub fn generate_keypair(&self) -> Result<(SecretKey, PublicKey, Address)> {
        let mut rng = OsRng;
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&self.secp, &secret_key);
        let address = Address::from_public_key(&public_key);

        Ok((secret_key, public_key, address))
    }

    pub fn generate_gear_address(
        &self,
        beta_angle: f64,
        stake: u64,
    ) -> Result<(GearParameters, Address)> {
        let mut rng = OsRng;
        let torque_ratio = 1.0 + (rng.next_u32() % 300) as f64 / 100.0; // 1.0-4.0
        let gear_ratio = 0.5 + (rng.next_u32() % 450) as f64 / 100.0; // 0.5-5.0
        let efficiency = 0.80 + (rng.next_u32() % 20) as f64 / 100.0; // 0.80-1.00

        let gear_params = GearParameters::new(beta_angle, torque_ratio, gear_ratio, efficiency)?;
        let address = Address::from_gear_parameters(&gear_params);

        Ok((gear_params, address))
    }
}

impl Default for AddressGenerator {
    fn default() -> Self {
        Self::new()
    }
}
