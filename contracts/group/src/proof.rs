use core::fmt::Debug;
use soroban_sdk::{contracttype, Bytes, Vec};

/// Merkle proof path, bottom to top
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Proof(pub Vec<Branch>);

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
