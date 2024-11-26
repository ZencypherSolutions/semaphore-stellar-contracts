#![cfg(test)]

use super::*;
use soroban_sdk::{
    crypto::bls12_381::G1Affine, log, testutils::Address as _, vec, Bytes, Env, String,
};

#[test]
fn test_bls12_381() {
    let env = Env::default();
    let bls12_381 = env.crypto().bls12_381();

    // Create message and domain separation tag bytes
    let msg = Bytes::from_slice(&env, b"message to hash");
    let dst = Bytes::from_slice(&env, b"domain separation tag");

    // Hash the message to a G1 point
    let point: G1Affine = bls12_381.hash_to_g1(&msg, &dst);

    // log the point
    log!(&env, "point", point);
}

#[test]
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
