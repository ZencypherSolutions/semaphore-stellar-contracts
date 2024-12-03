use soroban_sdk::{contracttype, contracterror, U256, BytesN};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    InvalidProofFormat = 1,
    InvalidPublicSignals = 2,
    InvalidMerkleTreeDepth = 3,
    VerificationFailed = 4,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub p_a: Vec<U256>,         // Point A coordinates [x, y]
    pub p_b: Vec<Vec<U256>>,    // Point B coordinates [[x1, x2], [y1, y2]]
    pub p_c: Vec<U256>,         // Point C coordinates [x, y]
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSignals {
    pub root: BytesN<32>,                    // Merkle tree root
    pub nullifier_hash: BytesN<32>,          // Nullifier hash
    pub signal_hash: BytesN<32>,             // Signal hash
    pub external_nullifier_hash: BytesN<32>, // External nullifier hash
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    AllowedTreeDepths,           // Store allowed Merkle tree depths
    VerifierConfig(u32),         // Any additional config needed per tree depth
}