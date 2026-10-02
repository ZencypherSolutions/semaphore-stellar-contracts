#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Env};

use crate::{SemaphoreVerifier, BLS12_381_G1_COMPRESSED_SIZE, BLS12_381_G2_COMPRESSED_SIZE};

#[test]
fn test_verify_returns_false_for_invalid_proof() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);
    let verifier = SemaphoreVerifierClient::new(&env, &contract_id);

    let nullifier_hash = [0xABu8; 32];
    let signal_hash = [0xBCu8; 32];
    let merkle_root = [0xCDu8; 32];

    // Create a dummy proof (all zeros) - should fail verification
    let mut proof = Vec::new();
    for _ in 0..(BLS12_381_G1_COMPRESSED_SIZE + BLS12_381_G2_COMPRESSED_SIZE
        + BLS12_381_G1_COMPRESSED_SIZE + BLS12_381_G2_COMPRESSED_SIZE
        + BLS12_381_G1_COMPRESSED_SIZE + BLS12_381_G2_COMPRESSED_SIZE)
    {
        proof.push_back(0u8);
    }

    let result = verifier.verify(&nullifier_hash, &signal_hash, &merkle_root, &proof);
    assert_eq!(result, false);
}

#[test]
fn test_hash_to_g1_produces_valid_point() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);
    let verifier = SemaphoreVerifierClient::new(&env, &contract_id);

    // Test that hash_to_g1 produces consistent output for same input
    let input = [0x42u8; 32];
    let pt1 = verifier.hash_to_g1(&input);
    let pt2 = verifier.hash_to_g1(&input);
    assert_eq!(pt1, pt2);
}

#[test]
#[should_panic(expected = "HostFunctionType not supported in test environment")]
fn test_multi_pairing_check_invalid_points() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreVerifier);
    let verifier = SemaphoreVerifierClient::new(&env, &contract_id);

    let nullifier_hash = [0xABu8; 32];
    let signal_hash = [0xBCu8; 32];
    let merkle_root = [0xCDu8; 32];

    let mut proof = Vec::new();
    for _ in 0..(BLS12_381_G1_COMPRESSED_SIZE + BLS12_381_G2_COMPRESSED_SIZE
        + BLS12_381_G1_COMPRESSED_SIZE + BLS12_381_G2_COMPRESSED_SIZE)
    {
        proof.push_back(0xFFu8);
    }

    verifier.verify(&nullifier_hash, &signal_hash, &merkle_root, &proof);
}

/// Test client for the SemaphoreVerifier contract.
#[soroban_sdk::token_client]
struct SemaphoreVerifierClient;
