#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env, String, Vec, log};

#[contracttype]
#[derive(Clone, Debug)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub anomaly_type: String,
    pub action_taken: String,
    pub timestamp: u64,
    pub confidence_score: u32, // 0-10000 (representing 0.00-100.00%)
    pub was_auto_executed: bool,
    pub diagnosis_summary: String,
}

#[contracttype]
pub enum DataKey {
    Record(String),  // incident_id -> IncidentRecord
    Count,           // total record count
    AllIds,          // Vec<String> of all incident IDs
}

#[contract]
pub struct IncidentAuditContract;

#[contractimpl]
impl IncidentAuditContract {
    /// Store a new incident record on-chain.
    pub fn store_incident(
        env: Env,
        incident_id: String,
        anomaly_type: String,
        action_taken: String,
        timestamp: u64,
        confidence_score: u32,
        was_auto_executed: bool,
        diagnosis_summary: String,
    ) {
        let record = IncidentRecord {
            incident_id: incident_id.clone(),
            anomaly_type,
            action_taken,
            timestamp,
            confidence_score,
            was_auto_executed,
            diagnosis_summary,
        };

        // Store the record
        env.storage().persistent().set(&DataKey::Record(incident_id.clone()), &record);

        // Update the count
        let count: u32 = env.storage().persistent().get(&DataKey::Count).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Count, &(count + 1));

        // Append to ID list
        let mut ids: Vec<String> = env.storage().persistent().get(&DataKey::AllIds).unwrap_or(Vec::new(&env));
        ids.push_back(incident_id.clone());
        env.storage().persistent().set(&DataKey::AllIds, &ids);

        // Extend TTL for persistence
        env.storage().persistent().extend_ttl(&DataKey::Record(incident_id), 100, 100);
        env.storage().persistent().extend_ttl(&DataKey::Count, 100, 100);
        env.storage().persistent().extend_ttl(&DataKey::AllIds, 100, 100);

        log!(&env, "Stored incident: {}", record.incident_id);
    }

    /// Retrieve a single incident record by ID.
    pub fn get_incident(env: Env, incident_id: String) -> IncidentRecord {
        env.storage()
            .persistent()
            .get(&DataKey::Record(incident_id))
            .expect("Incident not found")
    }

    /// Get the total number of stored incidents.
    pub fn get_count(env: Env) -> u32 {
        env.storage().persistent().get(&DataKey::Count).unwrap_or(0)
    }

    /// List all stored incident IDs.
    pub fn list_incident_ids(env: Env) -> Vec<String> {
        env.storage()
            .persistent()
            .get(&DataKey::AllIds)
            .unwrap_or(Vec::new(&env))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_store_and_retrieve() {
        let env = Env::default();
        let contract_id = env.register(IncidentAuditContract, ());
        let client = IncidentAuditContractClient::new(&env, &contract_id);

        client.store_incident(
            &String::from_str(&env, "inc-001"),
            &String::from_str(&env, "CrashLoopBackOff"),
            &String::from_str(&env, "delete_pod"),
            &1711700000u64,
            &9000u32,
            &true,
            &String::from_str(&env, "Pod crashloop-demo exited with code 1"),
        );

        let record = client.get_incident(&String::from_str(&env, "inc-001"));
        assert_eq!(record.anomaly_type, String::from_str(&env, "CrashLoopBackOff"));
        assert_eq!(record.confidence_score, 9000);
        assert_eq!(record.was_auto_executed, true);
        assert_eq!(client.get_count(), 1);
    }
}
