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

    //Initialize the verification key
    fn init_verification_key(depth: usize) -> VerificationKey {
        // Convert large integers to Fp256
        let alpha_x = Fp256::from_str("16428432848801857252194528405604668803277877773566238944394625302971855135431").unwrap();
        let alpha_y = Fp256::from_str("16846502678714586896801519656441059708016666274385668027902869494772365009666").unwrap();
        let alpha_g1 = G1Affine::new(alpha_x, alpha_y, false);

        let beta_x1 = Fp256::from_str("3182164110458002340215786955198810119980427837186618912744689678939861918171").unwrap();
        let beta_x2 = Fp256::from_str("16348171800823588416173124589066524623406261996681292662100840445103873053252").unwrap();
        let beta_y1 = Fp256::from_str("4920802715848186258981584729175884379674325733638798907835771393452862684714").unwrap();
        let beta_y2 = Fp256::from_str("19687132236965066906216944365591810874384658708175106803089633851114028275753").unwrap();

        let beta_x = QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(beta_x1, beta_x2);
        let beta_y = QuadExtField::<Fp2ParamsWrapper<Fq2Parameters>>::new(beta_y1, beta_y2);

        let beta_g2 = G2Affine::new(beta_x, beta_y, false);

        // Initialize the rest of the parameters...
        VerificationKey {
            alpha_g1,
            beta_g2,
            gamma_g2: G2Affine::prime_subgroup_generator(),
            delta_g2: G2Affine::prime_subgroup_generator(),
            ic: vec![G1Affine::prime_subgroup_generator(); depth + 1],
        }
    }

}