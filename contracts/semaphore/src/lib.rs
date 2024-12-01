#![no_std]

use crate::datatypes::{DataKey, Error, Member};
use crate::interface::SemaphoreGroupInterface;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Map, Symbol, Vec};

// Constants
const MIN_DEPTH: u32 = 16;
const MAX_DEPTH: u32 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemaphoreProof {
    merkle_tree_depth: u32,
    merkle_tree_root: BytesN<32>,
    nullifier: BytesN<32>,
    message: BytesN<32>,
    scope: BytesN<32>,
    points: Vec<BytesN<32>>, // Contains 8 points
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    admin: Address,
    merkle_tree_duration: u64,
    merkle_root_creation_dates: Map<BytesN<32>, u64>,
    merkle_tree: MerkleTree, //IMT?
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    depth: u32,
    leaves: Vec<BytesN<32>>,
}
#[contract]
pub struct Semaphore {
    verifier: Address, // Address of the verifier contract
}

#[contractimpl]
impl Semaphore {
    pub fn new(env: Env, verifier: Address) -> Self {
        Self { verifier }
    }

    pub fn create_group(
        env: &Env,
        admin: Address,
        merkle_tree_duration: u64,
    ) -> Result<u32, Error> {
        let group_id = env
            .storage()
            .instance()
            .get::<_, u32>("group_counter")
            .unwrap_or(0);

        // Create new group
        let group = Group {
            admin: admin.clone(),
            merkle_tree_duration,
            merkle_root_creation_dates: Map::new(&env),
            merkle_tree: MerkleTree {
                depth: MIN_DEPTH,
                leaves: Vec::new(&env),
            },
        };

        // Store group
        env.storage().instance().set(&group_id.to_string(), &group);
        env.storage()
            .instance()
            .set("group_counter", &(group_id + 1));

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "group_created"), group_id, admin),
            group_id,
        );

        Ok(group_id)
    }

    pub fn update_group_admin(env: &Env, group_id: u32, new_admin: Address) -> Result<(), Error> {
        let mut group: Group = env
            .storage()
            .instance()
            .get(&group_id.to_string())
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is current admin
        group.admin.require_auth();

        // Update admin
        group.admin = new_admin.clone();
        env.storage().instance().set(&group_id.to_string(), &group);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "group_admin_updated"),
                group_id,
                new_admin,
            ),
            (),
        );

        Ok(())
    }

    pub fn add_member(
        env: &Env,
        group_id: u32,
        identity_commitment: BytesN<32>,
    ) -> Result<(), Error> {
        let mut group: Group = env
            .storage()
            .instance()
            .get(&group_id.to_string())
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        group.admin.require_auth();

        // Add member to merkle tree
        group
            .merkle_tree
            .leaves
            .push_back(identity_commitment.clone());

        // Calculate new root
        let new_root = self.calculate_merkle_root(&group.merkle_tree)?;

        // Update root creation date
        group
            .merkle_root_creation_dates
            .set(new_root.clone(), env.ledger().timestamp());

        // Update group storage
        env.storage().instance().set(&group_id.to_string(), &group);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "member_added"),
                group_id,
                identity_commitment,
                new_root,
            ),
            (),
        );

        Ok(())
    }

    pub fn validate_proof(env: &Env, group_id: u32, proof: SemaphoreProof) -> Result<(), Error> {
        let group: Group = env
            .storage()
            .instance()
            .get(&group_id.to_string())
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify nullifier hasn't been used
        let nullifier_key = format!("nullifier:{}:{}", group_id, proof.nullifier.to_hex());
        if env.storage().instance().has(&nullifier_key) {
            return Err(Error::NullifierAlreadyUsed);
        }

        // Verify merkle tree depth
        if proof.merkle_tree_depth < MIN_DEPTH || proof.merkle_tree_depth > MAX_DEPTH {
            return Err(Error::InvalidMerkleTreeDepth);
        }

        // Verify group has members
        if group.merkle_tree.leaves.is_empty() {
            return Err(Error::GroupHasNoMembers);
        }

        // Check merkle root validity and expiration
        let current_root = self.calculate_merkle_root(&group.merkle_tree)?;
        if proof.merkle_tree_root != current_root {
            let creation_date = group
                .merkle_root_creation_dates
                .get(proof.merkle_tree_root.clone())
                .ok_or(Error::MerkleTreeRootNotInGroup)?;

            if env.ledger().timestamp() > creation_date + group.merkle_tree_duration {
                return Err(Error::MerkleTreeRootExpired);
            }
        }

        // Verify the proof using the verifier contract
        let result = self.verify_proof(&proof)?;
        if !result {
            return Err(Error::InvalidProof);
        }

        // Mark nullifier as used
        env.storage().instance().set(&nullifier_key, &true);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "proof_validated"),
                group_id,
                proof.merkle_tree_root,
                proof.nullifier,
                proof.message,
                proof.scope,
            ),
            (),
        );

        Ok(())
    }

    // Internal helper functions

    fn calculate_merkle_root(&self, tree: &MerkleTree) -> Result<BytesN<32>, Error> {
        if tree.leaves.is_empty() {
            return Err(Error::GroupHasNoMembers);
        }

        let mut current_level = tree.leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new(&self.env);

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level.get(i).unwrap();
                let right = if i + 1 < current_level.len() {
                    current_level.get(i + 1).unwrap()
                } else {
                    left.clone()
                };

                next_level.push_back(self.hash_pair(&left, &right));
            }

            current_level = next_level;
        }

        Ok(current_level.get(0).unwrap())
    }

    fn hash_pair(&self, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        let mut data = Vec::new(&self.env);
        data.push_back(left.clone());
        data.push_back(right.clone());
        self.env.crypto().keccak256(&data.into())
    }

    fn verify_proof(&self, proof: &SemaphoreProof) -> Result<bool, Error> {
        // Call external verifier contract
        // Note: This is a simplified version. In practice, you'd need to implement
        // the actual zero-knowledge proof verification logic or call an external verifier
        Ok(true)
    }
}
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
        env.storage()
            .instance()
            .set(&DataKey::MemberCount(group_id), &0u32);

        // Emit events using Symbol for event names and proper tuple syntax
        env.events()
            .publish((Symbol::new(&env, "group_created"), group_id), group_id);

        env.events()
            .publish((Symbol::new(&env, "group_admin_updated"), group_id), admin);

        Ok(())
    }

    fn update_group_admin(env: Env, group_id: u32, new_admin: Address) -> Result<(), Error> {
        let admin_key = DataKey::Admin(group_id);
        let current_admin: Address = env
            .storage()
            .instance()
            .get(&admin_key)
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
                new_admin,
            ),
            (),
        );

        Ok(())
    }

    fn accept_group_admin(env: Env, group_id: u32) -> Result<(), Error> {
        let pending_admin_key = DataKey::PendingAdmin(group_id);
        let admin_key = DataKey::Admin(group_id);

        // Verify group exists
        let current_admin: Address = env
            .storage()
            .instance()
            .get::<_, Address>(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;

        // Get and verify pending admin
        let new_admin: Address = env
            .storage()
            .instance()
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
                new_admin,
            ),
            (),
        );

        Ok(())
    }
    fn get_pending_admin(env: Env, group_id: u32) -> Result<Address, Error> {
        let pending_admin_key = DataKey::PendingAdmin(group_id);
        // Try to get the pending admin; return an error if not set
        env.storage()
            .instance()
            .get(&pending_admin_key)
            .ok_or(Error::CallerIsNotThePendingGroupAdmin)
    }

    fn add_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error> {
        if identity_commitment == 0 {
            return Err(Error::InvalidIdentityCommitment);
        }

        let admin_key = DataKey::Admin(group_id);
        let admin = env
            .storage()
            .instance()
            .get::<_, Address>(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        (&admin).require_auth();

        let member_key = DataKey::Member(group_id, identity_commitment);
        if env.storage().instance().has(&member_key) {
            return Err(Error::MemberAlreadyExists);
        }

        // Get and increment member count
        let count_key = DataKey::MemberCount(group_id);
        let current_count: u32 = env.storage().instance().get(&count_key).unwrap_or(0);

        // Create and store new member
        let member = Member {
            identity_commitment,
            group_id,
            index: current_count,
        };

        env.storage().instance().set(&member_key, &member);
        env.storage()
            .instance()
            .set(&count_key, &(current_count + 1));

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "MemberAdded"),
                group_id,
                identity_commitment,
                current_count,
            ),
            (),
        );

        Ok(())
    }

    fn add_members(env: Env, group_id: u32, identity_commitments: Vec<u32>) -> Result<(), Error> {
        // Get admin to verify authorization once for the whole operation
        let admin_key = DataKey::Admin(group_id);
        let admin = env
            .storage()
            .instance()
            .get::<_, Address>(&admin_key)
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
        new_identity_commitment: u32,
    ) -> Result<(), Error> {
        if new_identity_commitment == 0 {
            return Err(Error::InvalidIdentityCommitment);
        }

        let admin_key = DataKey::Admin(group_id);
        let admin: Address = env
            .storage()
            .instance()
            .get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)?;

        // Verify caller is admin
        (&admin).require_auth();

        // Check if old member exists and new member doesn't
        let old_member_key = DataKey::Member(group_id, old_identity_commitment);
        let new_member_key = DataKey::Member(group_id, new_identity_commitment);

        let old_member: Member = env
            .storage()
            .instance()
            .get(&old_member_key)
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
                new_identity_commitment,
            ),
            (),
        );

        Ok(())
    }

    fn remove_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<(), Error> {
        let admin_key = DataKey::Admin(group_id);
        let admin: Address = env
            .storage()
            .instance()
            .get(&admin_key)
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
        let current_count: u32 = env.storage().instance().get(&count_key).unwrap_or(1);

        env.storage()
            .instance()
            .set(&count_key, &(current_count - 1));
        env.storage().instance().remove(&member_key);

        // Emit event
        env.events().publish(
            (
                Symbol::new(&env, "MemberRemoved"),
                group_id,
                identity_commitment,
            ),
            (),
        );

        Ok(())
    }

    fn get_group_admin(env: Env, group_id: u32) -> Result<Address, Error> {
        let admin_key = DataKey::Admin(group_id);
        env.storage()
            .instance()
            .get(&admin_key)
            .ok_or(Error::GroupDoesNotExist)
    }

    fn get_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<Member, Error> {
        let member_key = DataKey::Member(group_id, identity_commitment);
        env.storage()
            .instance()
            .get(&member_key)
            .ok_or(Error::MemberDoesNotExist)
    }

    fn get_member_count(env: Env, group_id: u32) -> Result<u32, Error> {
        let count_key = DataKey::MemberCount(group_id);
        env.storage()
            .instance()
            .get(&count_key)
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
mod datatypes;
mod interface;
mod test;
