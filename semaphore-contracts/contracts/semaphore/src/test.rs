#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, vec, Env, String};

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
