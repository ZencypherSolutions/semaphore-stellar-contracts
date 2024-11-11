#![no_std]
extern crate alloc;
use soroban_sdk::{contract, contractimpl, Env, Vec, U256, BytesN};
use semaphore::{
    protocol::{verify_proof, Proof},
    hash_to_field
};
use ethers_core::types::U256 as EthersU256;