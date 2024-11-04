#![no_std]
use soroban_sdk::{contract, contractimpl, storage::Storage, Env, Vec};

#[derive(Clone)]
pub struct VerifyingKey(Vec<u8>);

#[derive(Clone)]
pub struct SemaphoreProof {
    proof_data: Vec<u8>,
    public_inputs: Vec<u8>,
}

#[derive(Clone, Debug)]
#[repr(u32)]
pub enum Error {
    InvalidProof = 1,
    InvalidVerificationKey = 2,
    VerificationFailed = 3,
}