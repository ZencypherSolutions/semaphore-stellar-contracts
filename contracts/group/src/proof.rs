use core::fmt::Debug;
use soroban_sdk::{contracttype, Bytes, Env, Vec};

use crate::imt::hash_node;

/// Merkle proof path, bottom to top
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Proof(pub Vec<Branch>);

impl Proof {
    /// Compute the leaf index for this proof
    pub fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            Branch::Left(_) => index << 1,
            Branch::Right(_) => (index << 1) + 1,
        })
    }

    /// Compute the Merkle root given a leaf hash
    pub fn root(&self, env: &Env, hash: &Bytes) -> Bytes {
        self.0
            .iter()
            .fold(hash.clone(), |hash, branch| match branch {
                Branch::Left(sibling) => hash_node(env, &sibling, &hash),
                Branch::Right(sibling) => hash_node(env, &hash, &sibling),
            })
    }
}

/// Element of a Merkle proof
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Branch {
    /// Left branch taken, value is the right sibling hash
    Left(Bytes),
    /// Right branch taken, value is the left sibling hash
    Right(Bytes),
}

impl Branch {
    /// Get the inner value
    pub fn into_inner(self) -> Bytes {
        match self {
            Self::Left(sibling) => sibling,
            Self::Right(sibling) => sibling,
        }
    }
}
