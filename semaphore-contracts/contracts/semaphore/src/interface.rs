use soroban_sdk::{Address, Env, Vec};
use crate::datatypes::{Error, Member};



pub trait SemaphoreGroupInterface {
    // Group Management
    fn create_group(env: Env, group_id: u32, admin: Address) -> Result<(), Error>;
    fn update_group_admin(env: Env, group_id: u32, new_admin: Address) -> Result<(), Error>;
    fn accept_group_admin(env: Env, group_id: u32) -> Result<(), Error>;
    fn get_pending_admin(env: Env, group_id: u32) -> Result<Address, Error>;
    
    // Member Management
    fn add_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error>;
    fn add_members(env: Env, group_id: u32, identity_commitments: Vec<u32>) -> Result<(), Error>;
    fn update_member(env: Env, group_id: u32, old_identity_commitment: u32, new_identity_commitment: u32) -> Result<(), Error>;
    fn remove_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error>;
    
    // View Functions
    fn get_group_admin(env: Env, group_id: u32) -> Result<Address, Error>;
    fn get_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<Member, Error>;
    fn get_member_count(env: Env, group_id: u32) -> Result<u32, Error>;
    fn is_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<bool, Error>;
}