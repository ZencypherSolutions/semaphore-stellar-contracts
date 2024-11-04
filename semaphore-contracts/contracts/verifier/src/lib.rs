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

#[contract]
pub struct SemaphoreVerifier;

#[contractimpl]
impl SemaphoreVerifier {
    pub fn init(env: Env, verifying_key: Vec<u8>) -> Self {
        let storage = env.storage();
        storage.set("verifying_key", &verifying_key);
        Self
    }

    pub fn verify_proof(
        env: Env,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Result<bool, Error> {
        let verifying_key: Vec<u8> = env
            .storage()
            .get("verifying_key")
            .ok_or(Error::InvalidVerificationKey)?;

        let proof = SemaphoreProof {
            proof_data: proof_bytes,
            public_inputs: public_inputs.clone(),
        };
        //Logic from semaphore
        Ok(true)
    }

    pub fn update_verifying_key(
        env: Env,
        new_verifying_key: Vec<u8>,
    ) -> Result<(), Error> {
        env.storage().set("verifying_key", &new_verifying_key);
        Ok(())
    }

    pub fn get_verifying_key(env: Env) -> Vec<u8> {
        env.storage()
            .get("verifying_key")
            .unwrap_or(Vec::new())
    }
}