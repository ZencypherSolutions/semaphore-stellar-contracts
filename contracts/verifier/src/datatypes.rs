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
    pub p_a: BytesN<96>,     // G1 point (2 * 48 bytes)
    pub p_b: BytesN<192>,    // G2 point (4 * 48 bytes)
    pub p_c: BytesN<96>,     // G1 point (2 * 48 bytes)
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
    VerificationKey(u32),        // maps tree_depth -> verification key
    AllowedTreeDepths,           // Store allowed Merkle tree depths
    VerifierConfig(u32),         // Any additional config needed per tree depth
}