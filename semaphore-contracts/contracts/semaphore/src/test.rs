#![cfg(test)]

use super::*;
use soroban_sdk::{
    crypto::bls12_381::G1Affine, log, testutils::Address as _, vec, Bytes, Env, String,
};

#[test]
fn test_bls12_381() {
    let env = Env::default();
    let bls12_381 = env.crypto().bls12_381();

    // Create two different messages to hash
    let msg1 = Bytes::from_slice(&env, b"message1 to hash");
    let msg2 = Bytes::from_slice(&env, b"message2 to hash");
    let dst = Bytes::from_slice(&env, b"domain separation tag");

    // Hash both messages to G1 points
    let point1: G1Affine = bls12_381.hash_to_g1(&msg1, &dst);
    let point2: G1Affine = bls12_381.hash_to_g1(&msg2, &dst);

    // Convert points to bytes for storage
    let bytes1 = point1.to_bytes();
    let bytes2 = point2.to_bytes();

    // Convert back to points
    let recovered_point1 = G1Affine::from_bytes(bytes1);
    let recovered_point2 = G1Affine::from_bytes(bytes2);

    // Add points using both original and recovered points
    let sum1 = bls12_381.g1_add(&point1, &point2);
    let sum2 = bls12_381.g1_add(&recovered_point1, &recovered_point2);

    // Log the results
    log!(&env, "Original point1: {:?}", point1.to_bytes());
    log!(&env, "Original point2: {:?}", point2.to_bytes());
    log!(&env, "Recovered point1: {:?}", recovered_point1.to_bytes());
    log!(&env, "Recovered point2: {:?}", recovered_point2.to_bytes());
    log!(&env, "Sum1: {:?}", sum1.to_bytes());
    log!(&env, "Sum2: {:?}", sum2.to_bytes());

    // Verify that conversion didn't affect the points
    assert_eq!(point1.to_bytes(), recovered_point1.to_bytes());
    assert_eq!(point2.to_bytes(), recovered_point2.to_bytes());
    assert_eq!(sum1.to_bytes(), sum2.to_bytes());
}

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
