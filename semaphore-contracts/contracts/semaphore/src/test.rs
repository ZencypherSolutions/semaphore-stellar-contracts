#![cfg(test)]
use super::*;
use soroban_sdk::{Address as _, Env};


#[test]
fn test_create_group() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SemaphoreGroupContract);
    let client = SemaphoreGroupContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let group_id = 1;

    // Test 1: Successful group creation
    let result = client.create_group(&group_id, &admin);
    assert!(result.is_ok());

    // Verify admin was set correctly
    let stored_admin = client.get_group_admin(&group_id).unwrap();
    assert_eq!(stored_admin, admin);

    // Verify member count was initialized to 0
    let member_count = client.get_member_count(&group_id).unwrap();
    assert_eq!(member_count, 0);

    // Test 2: Attempt to create duplicate group
    let duplicate_result = client.create_group(&group_id, &admin);
    assert_eq!(duplicate_result, Err(Error::GroupAlreadyExists));

    // Verify events
    let events = env.events().all();
    let created_events: Vec<_> = events
        .iter()
        .filter(|e| e.0 == ("GroupCreated", group_id))
        .collect();
    assert_eq!(created_events.len(), 1);
}
// #[test]
// fn test_update_group_admin() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, SemaphoreGroupContract);
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);
//     let admin = Address::generate(&env);
//     let new_admin = Address::generate(&env);

//     // Create group
//     client.create_group(&1, &admin).unwrap();

//     // Try updating admin without authentication (should fail)
//     assert_eq!(
//         client.update_group_admin(&1, &new_admin),
//         Err(Error::CallerIsNotTheGroupAdmin)
//     );

//     // Update admin with proper authentication
//     env.set_auths(&[(&admin, "update_group_admin", (&1, &new_admin))]);
//     assert!(client.update_group_admin(&1, &new_admin).is_ok());

//     // Verify original admin is still active until acceptance
//     assert_eq!(client.get_group_admin(&1).unwrap(), admin);
// }

// #[test]
// fn test_accept_group_admin() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, SemaphoreGroupContract);
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);
//     let admin = Address::generate(&env);
//     let new_admin = Address::generate(&env);
//     let third_party = Address::generate(&env);

//     // Create group and set up pending admin
//     client.create_group(&1, &admin).unwrap();
//     env.set_auths(&[(&admin, "update_group_admin", (&1, &new_admin))]);
//     client.update_group_admin(&1, &new_admin).unwrap();

//     // Try accepting admin role with wrong address (should fail)
//     env.set_auths(&[(&third_party, "accept_group_admin", &1)]);
//     assert_eq!(
//         client.accept_group_admin(&1),
//         Err(Error::CallerIsNotThePendingGroupAdmin)
//     );

//     // Accept admin role with correct address
//     env.set_auths(&[(&new_admin, "accept_group_admin", &1)]);
//     assert!(client.accept_group_admin(&1).is_ok());

//     // Verify admin was updated
//     assert_eq!(client.get_group_admin(&1).unwrap(), new_admin);

//     // Verify new admin can perform admin actions
//     env.set_auths(&[(&new_admin, "add_member", (&1, &123))]);
//     assert!(client.add_member(&1, &123).is_ok());
// }

// #[test]
// fn test_add_member() {
//     let env = Env::default();
//     let contract_id = env.register_contract(None, SemaphoreGroupContract);
//     let client = SemaphoreGroupContractClient::new(&env, &contract_id);

//     let admin = Address::generate(&env);

//     // Create group
//     client.create_group(&1, &admin).unwrap();

//     // Test adding member
//     env.mock_all_auths();
//     assert!(client.add_member(&1, &123).is_ok());

//     // Verify member count
//     assert_eq!(client.get_member_count(&1).unwrap(), 1);

//     // Test adding duplicate member
//     assert_eq!(client.add_member(&1, &123), Err(Error::MemberAlreadyExists));
// }
