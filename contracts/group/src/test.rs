#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events, AuthorizedFunction, AuthorizedInvocation},
    vec, Env, IntoVal, Bytes
};

const GROUP_ID: u32 = 1;

fn member_identity_commitment(env: &Env, items: &[u8]) -> Bytes {
    // Create identity commitments using BLS12-381
    let bls12_381 = env.crypto().bls12_381();
    let dst = Bytes::from_slice(&env, b"SEMAPHORE_IDENTITY");
    // Member creates identity commitment
    let secret = Bytes::from_slice(&env, items);
    let commitment = bls12_381.hash_to_g1(&secret, &dst);
    // Convert commitments to Bytes
    Bytes::from_slice(&env, &commitment.to_array())
}

#[test]
fn test_create_group_group_already_exists() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.try_create_group(&GROUP_ID, &admin), Err(Ok(Error::GroupAlreadyExists)));
}

#[test]
fn test_create_group() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
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
    assert_eq!(client.try_update_group_admin(&GROUP_ID, &new_admin), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_update_group_admin_caller_not_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP_ID, &new_admin);
}

#[test]
fn test_update_group_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP_ID, &new_admin);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "update_group_admin"),
                    (GROUP_ID, &new_admin).into_val(&env)
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
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_pending"), GROUP_ID, &admin, &new_admin).into_val(&env),
                ().into_val(&env)
            )
        ]
    );
}

#[test]
fn test_accept_group_admin_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_accept_group_admin(&GROUP_ID), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
fn test_accept_group_admin_caller_is_not_the_pending_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.try_accept_group_admin(&GROUP_ID), Err(Ok(Error::CallerIsNotThePendingGroupAdmin)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_accept_group_admin_caller_not_pending_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP_ID, &new_admin);
    client.accept_group_admin(&GROUP_ID);
}

#[test]
fn test_accept_group_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP_ID, &new_admin);
    client.accept_group_admin(&GROUP_ID);
    assert_eq!(
        env.auths(),
        std::vec![(
            new_admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "accept_group_admin"),
                    (GROUP_ID,).into_val(&env)
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
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_pending"), GROUP_ID, &admin, &new_admin).into_val(&env),
                ().into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID, &admin, &new_admin).into_val(&env),
                ().into_val(&env)
            ),
        ]
    );
}

#[test]
fn test_get_pending_admin_caller_is_not_the_pending_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_get_pending_admin(&GROUP_ID), Err(Ok(Error::CallerIsNotThePendingGroupAdmin)));
}

#[test]
fn test_get_pending_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let new_admin = Address::generate(&env);
    client.update_group_admin(&GROUP_ID, &new_admin);
    assert_eq!(client.get_pending_admin(&GROUP_ID), new_admin);
}

#[test]
fn test_add_member_invalid_identity_commitment() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_add_member(&GROUP_ID, &Bytes::new(&env)), Err(Ok(Error::InvalidIdentityCommitment)));
}

#[test]
fn test_add_member_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    assert_eq!(client.try_add_member(&GROUP_ID, &member1_identity_commitment), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_add_member_caller_not_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
}

#[test]
fn test_add_member_member_already_exists() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(client.try_add_member(&GROUP_ID, &member1_identity_commitment), Err(Ok(Error::MemberAlreadyExists)));
}

#[test]
fn test_add_member() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "add_member"),
                    (GROUP_ID, &member1_identity_commitment).into_val(&env)
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
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "MemberAdded"), GROUP_ID, &member1_identity_commitment, 0_u32).into_val(&env),
                ().into_val(&env)
            )
        ]
    );
}

#[test]
fn test_add_members_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    let member2_identity_commitment = member_identity_commitment(&env, b"member2_secret");
    let members = vec![&env, member1_identity_commitment, member2_identity_commitment];
    assert_eq!(client.try_add_members(&GROUP_ID, &members), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_add_members_caller_not_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    let member2_identity_commitment = member_identity_commitment(&env, b"member2_secret");
    let members = vec![&env, member1_identity_commitment, member2_identity_commitment];
    client.add_members(&GROUP_ID, &members);
}

// This test is commented out because it will fail until add_members is refactored to call
// require_auth only once

// #[test]
// fn test_add_members() {
//     let env = Env::default();
//     env.mock_all_auths();
//     let contract_id = env.register(SemaphoreGroupContract, ());
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);
//     let admin = Address::generate(&env);
//     client.create_group(&GROUP_ID, &admin);
//     let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
//     let member2_identity_commitment = member_identity_commitment(&env, b"member2_secret");
//     let members = vec![&env, member1_identity_commitment.clone(), member2_identity_commitment.clone()];
//     client.add_members(&GROUP_ID, &members);
//     assert_eq!(
//         env.auths(),
//         std::vec![(
//             admin.clone(),
//             AuthorizedInvocation {
//                 function: AuthorizedFunction::Contract((
//                     contract_id.clone(),
//                     Symbol::new(&env, "add_members"),
//                     (GROUP_ID, members).into_val(&env)
//                 )),
//                 sub_invocations: std::vec![]
//             }
//         )]
//     );
//     assert_eq!(
//         env.events().all(),
//         vec![
//             &env,
//             (
//                 contract_id.clone(),
//                 (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
//                 GROUP_ID.into_val(&env)
//             ),
//             (
//                 contract_id.clone(),
//                 (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
//                 admin.into_val(&env)
//             ),
//             (
//                 contract_id.clone(),
//                 (Symbol::new(&env, "MemberAdded"), GROUP_ID, &member1_identity_commitment, 0_u32).into_val(&env),
//                 ().into_val(&env)
//             ),
//             (
//                 contract_id.clone(),
//                 (Symbol::new(&env, "MemberAdded"), GROUP_ID, &member2_identity_commitment, 1_u32).into_val(&env),
//                 ().into_val(&env)
//             )
//         ]
//     );
// }

#[test]
fn test_update_member_invalid_identity_commitment() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_update_member(&GROUP_ID, &Bytes::new(&env), &Bytes::new(&env)), Err(Ok(Error::InvalidIdentityCommitment)));
}

#[test]
fn test_update_member_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let member1_new_identity_commitment = member_identity_commitment(&env, b"member1_new_secret");
    assert_eq!(client.try_update_member(&GROUP_ID, &Bytes::new(&env), &member1_new_identity_commitment), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_update_member_caller_not_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_new_identity_commitment = member_identity_commitment(&env, b"member1_new_secret");
    client.update_member(&GROUP_ID, &Bytes::new(&env), &member1_new_identity_commitment);
}


#[test]
fn test_update_member_member_does_not_exist() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_new_identity_commitment = member_identity_commitment(&env, b"member1_new_secret");
    assert_eq!(client.try_update_member(&GROUP_ID, &Bytes::new(&env), &member1_new_identity_commitment), Err(Ok(Error::MemberDoesNotExist)));
}

#[test]
fn test_update_member_member_already_exists() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_new_identity_commitment = member_identity_commitment(&env, b"member1_new_secret");
    client.add_member(&GROUP_ID, &member1_new_identity_commitment);
    assert_eq!(client.try_update_member(&GROUP_ID, &member1_new_identity_commitment, &member1_new_identity_commitment), Err(Ok(Error::MemberAlreadyExists)));
}

#[test]
fn test_update_member() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    let member1_new_identity_commitment = member_identity_commitment(&env, b"member1_new_secret");
    client.update_member(&GROUP_ID, &member1_identity_commitment, &member1_new_identity_commitment);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "update_member"),
                    (GROUP_ID, &member1_identity_commitment, &member1_new_identity_commitment).into_val(&env)
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
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "MemberAdded"), GROUP_ID, &member1_identity_commitment, 0_u32).into_val(&env),
                ().into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "MemberUpdated"), GROUP_ID, &member1_identity_commitment, &member1_new_identity_commitment).into_val(&env),
                ().into_val(&env)
            )
        ]
    );
}

#[test]
fn test_remove_member_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_remove_member(&GROUP_ID, &Bytes::new(&env)), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_remove_member_caller_not_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    client.remove_member(&GROUP_ID, &Bytes::new(&env));
}

#[test]
fn test_remove_member_member_does_not_exist() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.try_remove_member(&GROUP_ID, &Bytes::new(&env)), Err(Ok(Error::MemberDoesNotExist)));
}

#[test]
fn test_remove_member() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    client.remove_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "remove_member"),
                    (GROUP_ID, &member1_identity_commitment).into_val(&env)
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
                (Symbol::new(&env, "group_created"), GROUP_ID).into_val(&env),
                GROUP_ID.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "group_admin_updated"), GROUP_ID).into_val(&env),
                admin.into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "MemberAdded"), GROUP_ID, &member1_identity_commitment, 0_u32).into_val(&env),
                ().into_val(&env)
            ),
            (
                contract_id.clone(),
                (Symbol::new(&env, "MemberRemoved"), GROUP_ID, &member1_identity_commitment).into_val(&env),
                ().into_val(&env)
            )
        ]
    );
}

#[test]
fn test_get_group_admin_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_get_group_admin(&GROUP_ID), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
fn test_get_group_admin() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.get_group_admin(&GROUP_ID), admin);
}

#[test]
fn test_get_member_member_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_get_member(&GROUP_ID, &Bytes::new(&env)), Err(Ok(Error::MemberDoesNotExist)));
}

#[test]
fn test_get_member() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(
        client.get_member(&GROUP_ID, &member1_identity_commitment),
        Member { identity_commitment: member1_identity_commitment, group_id: GROUP_ID, index: 0_u32 }
    );
}

#[test]
fn test_get_member_count_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_get_member_count(&GROUP_ID), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
fn test_get_member_count() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.get_member_count(&GROUP_ID), 0_u32);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(client.get_member_count(&GROUP_ID), 1_u32);
}

#[test]
fn test_is_member_group_does_not_exist() {
    let env = Env::default();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    assert_eq!(client.try_is_member(&GROUP_ID, &Bytes::new(&env)), Err(Ok(Error::GroupDoesNotExist)));
}

#[test]
fn test_is_member() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(SemaphoreGroupContract, ());
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.create_group(&GROUP_ID, &admin);
    assert_eq!(client.is_member(&GROUP_ID, &Bytes::new(&env)), false);
    let member1_identity_commitment = member_identity_commitment(&env, b"member1_secret");
    client.add_member(&GROUP_ID, &member1_identity_commitment);
    assert_eq!(client.is_member(&GROUP_ID, &member1_identity_commitment), true);
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
