#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, BytesN, Env, Vec
};

/// Core constants for verification key points management
const POINT_SIZE: usize = 32;
const SET_SIZE: u32 = 8;

/// Contract error for verification key points validation
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Error when verification key points invariant is violated
    VKPtBytesMaxDepthInvariantViolated = 1,
}

#[contract]
pub struct SemaphoreVerifierKeyPts;

#[contractimpl]
impl SemaphoreVerifierKeyPts {
    /// Initializes the verification key points storage.
    /// Stores a set of verification points used for zero-knowledge proof verification.
    pub fn initialize(env: Env) {
        let mut points = Vec::new(&env);
        
        // Verification key points from original Semaphore implementation
        let sample_data = [
            0x289691d7_i32,    // Point 1
            0x70593405_i32,    // Point 2
            0x504ae4bd_i32,    // Point 3
            0x7be283f3_i32,    // Point 4
            0x465af66f_i32,    // Point 5
            0x62fc7f1e_i32,    // Point 6
            0x66f03876_i32,    // Point 7
            0xb445efddu32 as i32, // Point 8
        ];

        for value in sample_data.iter() {
            points.push_back(*value);
        }
        
        env.storage().instance().set(&symbol_short!("POINTS"), &points);
    }

    /// Retrieves verification points for a specific Merkle tree depth.
    /// Used during zero-knowledge proof verification to validate group membership claims.
    pub fn get_pts(env: Env, merkle_tree_depth: i32) -> Vec<BytesN<32>> {
        let stored_points: Vec<i32> = env.storage().instance()
            .get(&symbol_short!("POINTS"))
            .unwrap_or_else(|| Vec::new(&env));

        let mut result = Vec::new(&env);
        let start_idx = ((merkle_tree_depth - 1) * SET_SIZE as i32) as u32;
        let end_idx = (start_idx + SET_SIZE).min(stored_points.len());

        for i in start_idx..end_idx {
            if let Some(value) = stored_points.get(i) {
                let mut bytes = [0u8; POINT_SIZE];
                bytes[0..4].copy_from_slice(&value.to_be_bytes());
                result.push_back(BytesN::from_array(&env, &bytes));
            }
        }
        result
    }

    /// Validates the verification key points structure.
    /// Ensures stored points match the expected format for the Semaphore protocol.
    pub fn check_invariant(env: Env, max_depth: i32) -> Result<(), Error> {
        let stored_points: Vec<i32> = env.storage().instance()
            .get(&symbol_short!("POINTS"))
            .unwrap_or_else(|| Vec::new(&env));

        let expected_len = (max_depth * SET_SIZE as i32) as u32;
        if stored_points.len() != expected_len {
            return Err(Error::VKPtBytesMaxDepthInvariantViolated);
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use soroban_sdk::Env;
    use super::*;  // Importante: necesitamos importar todo del módulo padre

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register(SemaphoreVerifierKeyPts, ());
        let client = SemaphoreVerifierKeyPtsClient::new(&env, &contract_id);
        
        client.initialize();
        let points = client.get_pts(&1);
        assert!(!points.is_empty(), "Points should be initialized");
    }

    #[test]
    fn test_get_pts() {
        let env = Env::default();
        let contract_id = env.register(SemaphoreVerifierKeyPts, ());
        let client = SemaphoreVerifierKeyPtsClient::new(&env, &contract_id);
        
        client.initialize();
        let points = client.get_pts(&1);
        assert!(!points.is_empty(), "Should return non-empty points array");
        assert_eq!(points.len(), 8, "Should return exactly 8 points");
    }
}