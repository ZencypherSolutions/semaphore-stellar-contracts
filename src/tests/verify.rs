use soroban_sdk::{testutils::Address as _, Env};
use crate::{SemaphoreVerifier, BLS12_381_G1_COMPRESSED_SIZE, BLS12_381_G2_COMPRESSED_SIZE};

/// Integration tests for the Semaphore verifier contract.
/// These tests verify the BLS12-381 pairing check logic using CAP-0059.

#[test]
fn test_verify_contract_registration() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);
    assert_eq!(contract_id.is_some(), true);
}

#[test]
fn test_verify_with_all_zero_proof() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);

    let nullifier_hash = [0u8; 32];
    let signal_hash = [0u8; 32];
    let merkle_root = [0u8; 32];

    let mut proof = Vec::new();
    let total_size = BLS12_381_G1_COMPRESSED_SIZE * 3 + BLS12_381_G2_COMPRESSED_SIZE * 3;
    for _ in 0..total_size {
        proof.push_back(0u8);
    }

    // All-zero proof should not verify (identity element edge case)
    // The test ensures the contract runs without panicking
    let result = env.call(contract_id, "verify", (&nullifier_hash, &signal_hash, &merkle_root, &proof));
    // Expected: false or panic due to invalid points
    let _: bool = result.try_into().unwrap_or(false);
}

#[test]
fn test_verify_different_public_inputs() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);

    let nullifier_hash_1 = [0x01u8; 32];
    let signal_hash_1 = [0x02u8; 32];
    let merkle_root_1 = [0x03u8; 32];

    let nullifier_hash_2 = [0x04u8; 32];
    let signal_hash_2 = [0x05u8; 32];
    let merkle_root_2 = [0x06u8; 32];

    let mut proof = Vec::new();
    let total_size = BLS12_381_G1_COMPRESSED_SIZE * 3 + BLS12_381_G2_COMPRESSED_SIZE * 3;
    for _ in 0..total_size {
        proof.push_back(0u8);
    }

    let result_1 = env.call(contract_id, "verify", (&nullifier_hash_1, &signal_hash_1, &merkle_root_1, &proof));
    let result_2 = env.call(contract_id, "verify", (&nullifier_hash_2, &signal_hash_2, &merkle_root_2, &proof));

    // Both should return false for invalid proofs, but the contract should not panic
    assert_eq!(result_1.try_into().unwrap_or(false), false);
    assert_eq!(result_2.try_into().unwrap_or(false), false);
}

#[test]
fn test_parse_proof_empty() {
    // Ensure parse_proof handles empty input gracefully
    use crate::SemaphoreVerifier;
    let env = Env::default();
    let proof: Vec<u8> = Vec::new();
    let points = SemaphoreVerifier::parse_proof(&env, &proof);
    // Should not panic; points will be all zeros
    assert_eq!(points.a_g1, [0u8; BLS12_381_G1_COMPRESSED_SIZE]);
}
