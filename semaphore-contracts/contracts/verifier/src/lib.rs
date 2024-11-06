use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Fp256};
use ark_std::{One, Zero};
use std::str::FromStr;
use ark_ff::QuadExtField;
use ark_bn254::Fq2Parameters;
use ark_ff::Fp2ParamsWrapper;

/// Constants for the Semaphore verifier
pub struct VerificationKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: Vec<G1Affine>,
}

#[derive(Debug)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

pub struct SemaphoreVerifier {
    vk: VerificationKey,
}

impl SemaphoreVerifier {

    // Initialize the verification key based on the tree depth
    pub fn new(merkle_tree_depth: usize) -> Self {
        let vk = Self::init_verification_key(merkle_tree_depth);
        Self { vk }
    }

}