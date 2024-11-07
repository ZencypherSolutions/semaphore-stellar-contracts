#![no_std]

use soroban_sdk::{auth::Context, contractclient, Address, BytesN, Env, Vec};
use types::{Error, Signer, SignerKey};

pub mod types;

#[contractclient(name = "SemaphoreClient")]
pub trait SemaphoreInterface {
}