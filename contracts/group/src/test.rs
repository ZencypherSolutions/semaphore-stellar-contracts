#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events, AuthorizedFunction, AuthorizedInvocation},
    vec, Env, IntoVal
};

const GROUP1_ID: u32 = 1;

#[test]
fn test_create_group_group_already_exists() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP1_ID, &admin);
    assert_eq!(client.try_create_group(&GROUP1_ID, &admin), Err(Ok(Error::GroupAlreadyExists)));
}

#[test]
fn test_create_group() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP1_ID, &admin);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_created"), GROUP1_ID).into_val(&env),
                GROUP1_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP1_ID).into_val(&env),
                admin.into_val(&env)
            ),
        ]
    );
}

#[test]
fn test_update_group_admin_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let new_admin = Address::generate(&env);
    assert_eq!(client.try_update_group_admin(&GROUP1_ID, &new_admin), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_update_group_admin_not_current_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP1_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP1_ID, &new_admin);
}

#[test]
fn test_update_group_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP1_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP1_ID, &new_admin);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "update_group_admin"),
                    (GROUP1_ID, new_admin.clone()).into_val(&env)
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_created"), GROUP1_ID).into_val(&env),
                GROUP1_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP1_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_pending"), GROUP1_ID, admin.clone(), new_admin.clone()).into_val(&env),
                ().into_val(&env)
            )
        ]
    );
}

// #[test]
// fn assert_group_admin() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, SemaphoreGroupContract);
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);

//     // Test admin, member1, member2
//     let admin = Address::generate(&env);
//     let member1 = Address::generate(&env);
//     let member2 = Address::generate(&env);

//     let group_id = 1;
//     client.create_group(&group_id, &admin);

//     // Assert group admin
//     let group_admin = client.get_group_admin(&group_id);
//     assert_eq!(group_admin, admin);

//     // Add member 1
//     // client.add_member(&group_id, &member1);

//     // // Assert member 1 is in the group
//     // let member_count = client.get_member_count(&group_id);
//     // assert_eq!(member_count, 1);
// }

// #[test]
// fn test_semaphore_flow() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, SemaphoreGroupContract);
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);

//     // Setup group admin
//     let admin = Address::generate(&env);
//     let group_id = 1;
//     client.create_group(&group_id, &admin);

//     // Create identity commitments using BLS12-381
//     let bls12_381 = env.crypto().bls12_381();
//     let dst = Bytes::from_slice(&env, b"SEMAPHORE_IDENTITY");

//     // User 1 creates identity commitment
//     let secret1 = Bytes::from_slice(&env, b"user1_secret");
//     let commitment1 = bls12_381.hash_to_g1(&secret1, &dst);

//     // User 2 creates identity commitment
//     let secret2 = Bytes::from_slice(&env, b"user2_secret");
//     let commitment2 = bls12_381.hash_to_g1(&secret2, &dst);

//     // Convert commitments to Bytes
//     let commitment1_bytes = Bytes::from_slice(&env, &commitment1.to_array());
//     let commitment2_bytes = Bytes::from_slice(&env, &commitment2.to_array());

//     client.add_member(&group_id, &commitment1_bytes);
//     client.add_member(&group_id, &commitment2_bytes);

//     // Verify member count
//     let member_count = client.get_member_count(&group_id);
//     assert_eq!(member_count, 2);

//     // Verify membership
//     let is_member = client.is_member(&group_id, &commitment1_bytes);
//     assert!(is_member);
// }
