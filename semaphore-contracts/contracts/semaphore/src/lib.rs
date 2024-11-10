#![no_std]


use soroban_sdk::{contract, contractimpl, Env, Address, Vec, Symbol};
use crate::interface::SemaphoreGroupInterface;
use crate::datatypes::{Error, DataKey, Member};

#[contract]
pub struct SemaphoreGroupContract;

#[contractimpl]
impl SemaphoreGroupInterface for SemaphoreGroupContract {
    fn create_group(env: Env, group_id: u32, admin: Address) -> Result<(), Error> {
        let admin_key = DataKey::Admin(group_id);
        
        // Check if group already exists
        if env.storage().instance().has(&admin_key) {
            return Err(Error::GroupAlreadyExists);
        }
        
        // Initialize group
        env.storage().instance().set(&admin_key, &admin);
        env.storage().instance().set(&DataKey::MemberCount(group_id), &0u32);
        
        // Emit events using Symbol for event names and proper tuple syntax
        env.events().publish(
            (Symbol::new(&env, "group_created"), group_id),
            group_id
        );
        
        env.events().publish(
            (Symbol::new(&env, "group_admin_updated"), group_id),
            admin
        );
        
        Ok(())
    }

    fn update_group_admin(env: Env, group_id: u32, new_admin: Address) -> Result<(), Error> {
        let admin_key = DataKey::Admin(group_id);
        let current_admin:Address  = env.storage().instance().get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;
    
        // Verify caller is current admin
        (&current_admin).require_auth();
    
        // Set pending admin
        let pending_admin_key = DataKey::PendingAdmin(group_id);
        env.storage().instance().set(&pending_admin_key, &new_admin);
    
        // Emit event with all information in topics
        env.events().publish(
            (
                Symbol::new(&env, "group_admin_pending"),
                group_id,
                current_admin,
                new_admin
            ),
            () 
        );
    
        Ok(())
    }

   fn accept_group_admin(env: Env, group_id: u32) -> Result<(), Error> {
    let pending_admin_key = DataKey::PendingAdmin(group_id);
    let admin_key = DataKey::Admin(group_id);

    // Verify group exists
    let current_admin: Address = env.storage().instance()
        .get::<_, Address>(&admin_key)  
        .ok_or(Error::GroupDoesNotExist)?;

    // Get and verify pending admin
    let new_admin: Address = env.storage().instance()
        .get::<_, Address>(&pending_admin_key)
        .ok_or(Error::CallerIsNotThePendingGroupAdmin)?;

    // Verify caller is the pending admin
    (&new_admin).require_auth();
    
    // Update admin
    env.storage().instance().set(&admin_key, &new_admin);
    env.storage().instance().remove(&pending_admin_key);

    // Emit event
    env.events().publish(
        (
            Symbol::new(&env, "group_admin_updated"),
            group_id,
            current_admin,
            new_admin
        ),
        ()
    );

    Ok(())
}
    fn get_pending_admin(env: Env, group_id: u32) -> Result<Address, Error> {
        let pending_admin_key = DataKey::PendingAdmin(group_id);
        // Try to get the pending admin; return an error if not set
        env.storage().instance().get(&pending_admin_key)
            .ok_or(Error::CallerIsNotThePendingGroupAdmin)
    }
    

    fn add_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error> {
        if identity_commitment == 0 {
            return Err(Error::InvalidIdentityCommitment);
        }

        let admin_key = DataKey::Admin(group_id);
        let admin = env.storage().instance().get::<_, Address>(&admin_key)  
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        (&admin).require_auth();

        let member_key = DataKey::Member(group_id, identity_commitment);
        if env.storage().instance().has(&member_key) {
            return Err(Error::MemberAlreadyExists);
        }

        // Get and increment member count
        let count_key = DataKey::MemberCount(group_id);
        let current_count: u32 = env.storage().instance().get(&count_key)
            .unwrap_or(0);
        
        // Create and store new member
        let member = Member {
            identity_commitment,
            group_id,
            index: current_count,
        };
        
        env.storage().instance().set(&member_key, &member);
        env.storage().instance().set(&count_key, &(current_count + 1));

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "MemberAdded"),
                group_id,
                identity_commitment,
                current_count
            ),
            ()
        );

        Ok(())
    }

    fn add_members(env: Env, group_id: u32, identity_commitments: Vec<u32>) -> Result<(), Error> {
        // Get admin to verify authorization once for the whole operation
        let admin_key = DataKey::Admin(group_id);
        let admin = env.storage().instance().get::<_, Address>(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;
        
        // Verify caller is admin for the main add_members call
        (&admin).require_auth();
    
        // Add each member
        for commitment in identity_commitments.iter() {
            // Note: we don't need to require_auth again since we're in the same transaction
            Self::add_member(env.clone(), group_id, commitment)?;
        }
        Ok(())
    }


    fn update_member(
        env: Env,
        group_id: u32,
        old_identity_commitment: u32,
        new_identity_commitment: u32
    ) -> Result<(), Error> {
        if new_identity_commitment == 0 {
            return Err(Error::InvalidIdentityCommitment);
        }

        let admin_key = DataKey::Admin(group_id);
        let admin:Address = env.storage().instance().get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        (&admin).require_auth();

        // Check if old member exists and new member doesn't
        let old_member_key = DataKey::Member(group_id, old_identity_commitment);
        let new_member_key = DataKey::Member(group_id, new_identity_commitment);

        let old_member: Member = env.storage().instance().get(&old_member_key)
            .ok_or(Error::MemberDoesNotExist)?;

        if env.storage().instance().has(&new_member_key) {
            return Err(Error::MemberAlreadyExists);
        }

        // Create updated member
        let new_member = Member {
            identity_commitment: new_identity_commitment,
            group_id,
            index: old_member.index,
        };

        // Update storage
        env.storage().instance().set(&new_member_key, &new_member);
        env.storage().instance().remove(&old_member_key);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "MemberUpdated"),
                group_id,
                old_identity_commitment,
                new_identity_commitment
            ),
            () 
        );

        Ok(())
    }

    fn remove_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error> {
        let admin_key = DataKey::Admin(group_id);
        let admin:Address = env.storage().instance().get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        (&admin).require_auth();

        // Check if member exists
        let member_key = DataKey::Member(group_id, identity_commitment);
        if !env.storage().instance().has(&member_key) {
            return Err(Error::MemberDoesNotExist);
        }

        // Decrement member count
        let count_key = DataKey::MemberCount(group_id);
        let current_count: u32 = env.storage().instance().get(&count_key)
            .unwrap_or(1);
        
        env.storage().instance().set(&count_key, &(current_count - 1));
        env.storage().instance().remove(&member_key);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "MemberRemoved"),
                group_id,
                identity_commitment
            ),
            () 
        );

        Ok(())
    }

    fn get_group_admin(env: Env, group_id: u32) -> Result<Address, Error> {
        let admin_key = DataKey::Admin(group_id);
        env.storage().instance().get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)
    }

    fn get_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<Member, Error> {
        let member_key = DataKey::Member(group_id, identity_commitment);
        env.storage().instance().get(&member_key)
            .ok_or(Error::MemberDoesNotExist)
    }

    fn get_member_count(env: Env, group_id: u32) -> Result<u32, Error> {
        let count_key = DataKey::MemberCount(group_id);
        env.storage().instance().get(&count_key)
            .ok_or(Error::GroupDoesNotExist)
    }

    fn is_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<bool, Error> {
        // Check if group exists first
        let admin_key = DataKey::Admin(group_id);
        if !env.storage().instance().has(&admin_key) {
            return Err(Error::GroupDoesNotExist);
        }
        
        let member_key = DataKey::Member(group_id, identity_commitment);
        Ok(env.storage().instance().has(&member_key))
    }
}
mod test;
mod datatypes;
mod interface;
