#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, vec, Env, String};

#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreGroupContract);
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);

    // Test admin, member1, member2
    let admin = Address::generate(&env);
    let member1 = Address::generate(&env);
    let member2 = Address::generate(&env);

    let group_id = 1;
    let words = client.create_group(&group_id, &admin);
}
