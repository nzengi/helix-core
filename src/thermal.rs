
use sysinfo::{System, SystemExt, ComponentExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn, error};

pub struct ThermalBalancer {
    pub current_temp: f64,
    pub optimal_temp: f64,
    pub efficiency_factor: f64,
    pub system: Arc<Mutex<System>>,
    pub temp_history: Vec<ThermalReading>,
    pub max_history: usize,
}

#[derive(Debug, Clone)]
pub struct ThermalReading {
    pub temperature: f64,
    pub timestamp: u64,
    pub component_name: String,
}

#[derive(Debug, Clone)]
pub struct ThermalStats {
    pub current_temp: f64,
    pub average_temp: f64,
    pub max_temp: f64,
    pub min_temp: f64,
    pub efficiency_factor: f64,
    pub thermal_state: ThermalState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThermalState {
    Optimal,
    Warning,
    Critical,
    Emergency,
}

impl ThermalBalancer {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            current_temp: 40.0,
            optimal_temp: 40.0,
            efficiency_factor: 1.0,
            system: Arc::new(Mutex::new(system)),
            temp_history: Vec::new(),
            max_history: 100,
        }
    }

    pub async fn update_temperature(&mut self) -> Result<(), String> {
        let mut system = self.system.lock().await;
        system.refresh_components();

        let mut total_temp = 0.0;
        let mut component_count = 0;

        for component in system.components() {
            let temp = component.temperature();
            if temp > 0.0 {
                total_temp += temp;
                component_count += 1;

                // Add to history
                let reading = ThermalReading {
                    temperature: temp,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    component_name: component.label().to_string(),
                };

                self.temp_history.push(reading);

                // Maintain history size
                if self.temp_history.len() > self.max_history {
                    self.temp_history.remove(0);
                }
            }
        }

        if component_count > 0 {
            self.current_temp = total_temp / component_count as f64;
            self.efficiency_factor = self.calculate_efficiency_factor();
            
            info!("Temperature updated: {:.2}°C, Efficiency: {:.2}", 
                  self.current_temp, self.efficiency_factor);
        } else {
            warn!("No temperature sensors found, using default values");
        }

        Ok(())
    }

    pub fn calculate_efficiency_factor(&self) -> f64 {
        let temp_diff = (self.current_temp - self.optimal_temp).abs();
        let factor = (1.0 - (temp_diff * 0.01)).max(0.1);
        
        // Apply additional penalties for extreme temperatures
        if self.current_temp > 80.0 {
            factor * 0.5 // Severe penalty for very high temps
        } else if self.current_temp > 70.0 {
            factor * 0.7 // Moderate penalty for high temps
        } else if self.current_temp < 10.0 {
            factor * 0.8 // Penalty for very low temps
        } else {
            factor
        }
    }

    pub fn get_thermal_state(&self) -> ThermalState {
        match self.current_temp {
            temp if temp > 85.0 => ThermalState::Emergency,
            temp if temp > 75.0 => ThermalState::Critical,
            temp if temp > 65.0 => ThermalState::Warning,
            _ => ThermalState::Optimal,
        }
    }

    pub fn adjust_beta_for_temperature(&self, base_beta: f64) -> f64 {
        match self.get_thermal_state() {
            ThermalState::Emergency => base_beta * 0.5, // Drastically reduce performance
            ThermalState::Critical => base_beta * 0.7,  // Significantly reduce performance
            ThermalState::Warning => base_beta * 0.85,  // Slightly reduce performance
            ThermalState::Optimal => base_beta,         // Normal performance
        }
    }

    pub fn get_thermal_stats(&self) -> ThermalStats {
        let temps: Vec<f64> = self.temp_history.iter().map(|r| r.temperature).collect();
        
        let average_temp = if !temps.is_empty() {
            temps.iter().sum::<f64>() / temps.len() as f64
        } else {
            self.current_temp
        };

        let max_temp = temps.iter().cloned().fold(self.current_temp, f64::max);
        let min_temp = temps.iter().cloned().fold(self.current_temp, f64::min);

        ThermalStats {
            current_temp: self.current_temp,
            average_temp,
            max_temp,
            min_temp,
            efficiency_factor: self.efficiency_factor,
            thermal_state: self.get_thermal_state(),
        }
    }

    pub async fn monitor_thermal_limits(&self) -> Result<(), String> {
        match self.get_thermal_state() {
            ThermalState::Emergency => {
                error!("EMERGENCY: Temperature critical at {:.2}°C! System protection activated.", 
                       self.current_temp);
                // In a real system, this would trigger emergency shutdown
                Err("Emergency thermal protection activated".to_string())
            },
            ThermalState::Critical => {
                error!("CRITICAL: Temperature very high at {:.2}°C! Reducing performance.", 
                       self.current_temp);
                Ok(())
            },
            ThermalState::Warning => {
                warn!("WARNING: Temperature elevated at {:.2}°C. Monitoring closely.", 
                      self.current_temp);
                Ok(())
            },
            ThermalState::Optimal => {
                Ok(())
            }
        }
    }

    pub fn clear_history(&mut self) {
        self.temp_history.clear();
    }

    pub fn get_temperature_trend(&self) -> Option<f64> {
        if self.temp_history.len() < 2 {
            return None;
        }

        let recent_count = (self.temp_history.len() / 4).max(1);
        let recent_temps: Vec<f64> = self.temp_history
            .iter()
            .rev()
            .take(recent_count)
            .map(|r| r.temperature)
            .collect();

        let older_temps: Vec<f64> = self.temp_history
            .iter()
            .take(recent_count)
            .map(|r| r.temperature)
            .collect();

        if recent_temps.is_empty() || older_temps.is_empty() {
            return None;
        }

        let recent_avg = recent_temps.iter().sum::<f64>() / recent_temps.len() as f64;
        let older_avg = older_temps.iter().sum::<f64>() / older_temps.len() as f64;

        Some(recent_avg - older_avg)
    }

    pub fn predict_thermal_throttling(&self, workload_increase: f64) -> bool {
        let predicted_temp = self.current_temp + (workload_increase * 10.0);
        predicted_temp > 75.0
    }
}

impl Default for ThermalBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_thermal_balancer_creation() {
        let balancer = ThermalBalancer::new();
        assert_eq!(balancer.optimal_temp, 40.0);
        assert!(balancer.efficiency_factor > 0.0);
    }

    #[tokio::test]
    async fn test_efficiency_calculation() {
        let mut balancer = ThermalBalancer::new();
        balancer.current_temp = 40.0; // Optimal
        assert_eq!(balancer.calculate_efficiency_factor(), 1.0);

        balancer.current_temp = 50.0; // 10 degrees above optimal
        let factor = balancer.calculate_efficiency_factor();
        assert!(factor < 1.0 && factor > 0.8);
    }

    #[test]
    fn test_thermal_states() {
        let mut balancer = ThermalBalancer::new();
        
        balancer.current_temp = 30.0;
        assert_eq!(balancer.get_thermal_state(), ThermalState::Optimal);

        balancer.current_temp = 70.0;
        assert_eq!(balancer.get_thermal_state(), ThermalState::Warning);

        balancer.current_temp = 80.0;
        assert_eq!(balancer.get_thermal_state(), ThermalState::Critical);

        balancer.current_temp = 90.0;
        assert_eq!(balancer.get_thermal_state(), ThermalState::Emergency);
    }

    #[test]
    fn test_beta_adjustment() {
        let mut balancer = ThermalBalancer::new();
        let base_beta = 40.0;

        balancer.current_temp = 30.0; // Optimal
        assert_eq!(balancer.adjust_beta_for_temperature(base_beta), base_beta);

        balancer.current_temp = 90.0; // Emergency
        assert!(balancer.adjust_beta_for_temperature(base_beta) < base_beta * 0.6);
    }
}
