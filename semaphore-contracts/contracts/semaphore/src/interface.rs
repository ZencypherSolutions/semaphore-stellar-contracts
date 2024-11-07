#![no_std]

use soroban_sdk::{auth::Context, contractclient, Address, BytesN, Env, Vec};
use datatypes::{Error};



#[contractclient(name = "SemaphoreClient")]
pub trait SemaphoreInterface {
    /// @dev Returns the address of the group admin. The group admin can be an Ethereum account or a smart contract.
    /// @param groupId: Id of the group.
    /// @return Address of the group admin.
    fn get_group_admin(env: Env, group_id: u32) -> Result<Address, Error>;
    /// @dev Returns true if a member exists in a group.
    /// @param groupId: Id of the group.
    /// @param identityCommitment: Identity commitment.
    /// @return True if the member exists, false otherwise.
    fn has_member(env: Env, group_id: u32, identity_commitment: u32) -> Result<bool, Error>;
    /// @dev Returns the index of a member.
    /// @param groupId: Id of the group.
    /// @param identityCommitment: Identity commitment.
    /// @return Index of member.
    fn index_of(env: Env, group_id: u32, identity_commitment: u32) -> Result<u32, Error>;
    /// @dev Returns the last root hash of a group.
    /// @param groupId: Id of the group.
    /// @return Root hash of the group.
    fn get_merkle_tree_root(env: Env, group_id: u32) -> Result<u32, Error>;
    /// @dev Returns the depth of the tree of a group.
    /// @param groupId: Id of the group.
    /// @return Depth of the group tree.
    fn get_merkle_tree_depth(env: Env, group_id: u32) -> Result<u32, Error>;
    /// @dev Returns the number of tree leaves of a group.
    /// @param groupId: Id of the group.
    /// @return Number of tree leaves.
    fn get_merkle_tree_size(env: Env, group_id: u32) -> Result<u32, Error>;




}

mod datatypes;