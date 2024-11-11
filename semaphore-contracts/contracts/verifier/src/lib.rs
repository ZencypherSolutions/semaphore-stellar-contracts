#![no_std]
extern crate alloc;
use soroban_sdk::{contract, contractimpl, Env, Vec, U256, BytesN};
use semaphore::{
    protocol::{verify_proof, Proof},
    hash_to_field
};
use ethers_core::types::U256 as EthersU256;

#[contractimpl]
impl SemaphoreVerifier {
    pub fn verify_proof(
        env: Env,
        p_a: Vec<U256>,
        p_b: Vec<Vec<U256>>,
        p_c: Vec<U256>,
        root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        signal_hash: BytesN<32>,
        external_nullifier_hash: BytesN<32>,
        merkle_tree_depth: u32,
    ) -> bool {
        // Convert Soroban U256 to EthersU256
        fn convert_to_ethers_u256(soroban_u256: &U256) -> EthersU256 {
            let bytes = soroban_u256.to_be_bytes();
            // Convert to standard Vec first
            let std_vec: alloc::vec::Vec<u8> = bytes.slice(0..).into_iter().collect();
            EthersU256::from_big_endian(&std_vec)
        }

        // Convert p_a to (EthersU256, EthersU256)
        let a_tuple = (
            convert_to_ethers_u256(&p_a.get(0).unwrap()),
            convert_to_ethers_u256(&p_a.get(1).unwrap())
        );

        // Convert p_b to ([EthersU256; 2], [EthersU256; 2])
        let b_tuple = (
            [
                convert_to_ethers_u256(&p_b.get(0).unwrap().get(0).unwrap()),
                convert_to_ethers_u256(&p_b.get(0).unwrap().get(1).unwrap())
            ],
            [
                convert_to_ethers_u256(&p_b.get(1).unwrap().get(0).unwrap()),
                convert_to_ethers_u256(&p_b.get(1).unwrap().get(1).unwrap())
            ]
        );

        // Convert p_c to (EthersU256, EthersU256)
        let c_tuple = (
            convert_to_ethers_u256(&p_c.get(0).unwrap()),
            convert_to_ethers_u256(&p_c.get(1).unwrap())
        );

        let proof = Proof(
            a_tuple,
            b_tuple,
            c_tuple,
        );

        // Convert public signals to Field types
        let root_bytes: [u8; 32] = root.to_array();
        let root_field = hash_to_field(&root_bytes);

        let nullifier_bytes: [u8; 32] = nullifier_hash.to_array();
        let nullifier_field = hash_to_field(&nullifier_bytes);

        let signal_bytes: [u8; 32] = signal_hash.to_array();
        let signal_field = hash_to_field(&signal_bytes);

        let external_bytes: [u8; 32] = external_nullifier_hash.to_array();
        let external_field = hash_to_field(&external_bytes);

        match verify_proof(
            root_field,
            nullifier_field,
            signal_field,
            external_field,
            &proof,
            merkle_tree_depth as usize,
        ) {
            Ok(result) => result,
            Err(_) => false,
        }
    }
}

