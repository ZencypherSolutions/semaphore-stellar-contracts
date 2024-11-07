#![no_std]
use soroban_sdk::{contract, contractimpl, vec, Env, String, Vec};
use crate::interface::SemaphoreInterface;
use crate::datatypes::{Error, Signer, SignerKey};

#[contract]
pub struct SemaphoreContract;

#[contractimpl]
impl SemaphoreContract {
    pub fn hello(env: Env, to: String) -> Vec<String> {
        vec![&env, String::from_str(&env, "Hello"), to]
    }
}

mod test;
mod datatypes;
mod interface;
