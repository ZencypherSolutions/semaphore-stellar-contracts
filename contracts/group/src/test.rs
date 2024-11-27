#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Bytes, Env};

#[test]
fn assert_group_admin() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreGroupContract);
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);

    // Test admin, member1, member2
    let admin = Address::generate(&env);
    let member1 = Address::generate(&env);
    let member2 = Address::generate(&env);

    let group_id = 1;
    client.create_group(&group_id, &admin);

    // Assert group admin
    let group_admin = client.get_group_admin(&group_id);
    assert_eq!(group_admin, admin);

    // Add member 1
    // client.add_member(&group_id, &member1);

    // // Assert member 1 is in the group
    // let member_count = client.get_member_count(&group_id);
    // assert_eq!(member_count, 1);
}

#[test]
fn test_semaphore_flow() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreGroupContract);
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);

    // Setup group admin
    let admin = Address::generate(&env);
    let group_id = 1;
    client.create_group(&group_id, &admin);

    // Create identity commitments using BLS12-381
    let bls12_381 = env.crypto().bls12_381();
    let dst = Bytes::from_slice(&env, b"SEMAPHORE_IDENTITY");

    // User 1 creates identity commitment
    let secret1 = Bytes::from_slice(&env, b"user1_secret");
    let commitment1 = bls12_381.hash_to_g1(&secret1, &dst);

    // User 2 creates identity commitment
    let secret2 = Bytes::from_slice(&env, b"user2_secret");
    let commitment2 = bls12_381.hash_to_g1(&secret2, &dst);

    // Convert commitments to Bytes
    let commitment1_bytes = Bytes::from_slice(&env, &commitment1.to_array());
    let commitment2_bytes = Bytes::from_slice(&env, &commitment2.to_array());

    client.add_member(&group_id, &commitment1_bytes);
    client.add_member(&group_id, &commitment2_bytes);

    // Verify member count
    let member_count = client.get_member_count(&group_id);
    assert_eq!(member_count, 2);

    // Verify membership
    let is_member = client.is_member(&group_id, &commitment1_bytes);
    assert!(is_member);
}
