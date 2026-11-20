use soroban_sdk::{Env, Bytes, BytesN, Vec};

pub fn example() -> &'static str {
    "Hello, Verifier!"
}

/// Performs a multi‑pairing check between G1 and G2 points using the native
/// Soroban host function `bls12_381_pairing_check`.
///
/// # Arguments
///
/// * `g1_points` - A vector of G1 points, each encoded as `BytesN<48>`.
/// * `g2_points` - A vector of G2 points, each encoded as `BytesN<96>`.
///
/// # Returns
///
/// `true` if the pairing check succeeds, otherwise `false`.
pub fn bls12_381_multi_pairing_check(g1_points: Vec<BytesN<48>>, g2_points: Vec<BytesN<96>>) -> bool {
    let env = Env::default();
    env.bls12_381_pairing_check(&g1_points, &g2_points)
}

/// Adds two G1 points using the native Soroban host function `bls12_381_add`.
///
/// # Arguments
///
/// * `p1` - First G1 point (`BytesN<48>`).
/// * `p2` - Second G1 point (`BytesN<48>`).
///
/// # Returns
///
/// The resulting G1 point (`BytesN<48>`).
pub fn bls12_381_g1_add(p1: BytesN<48>, p2: BytesN<48>) -> BytesN<48> {
    let env = Env::default();
    env.bls12_381_add(&p1, &p2)
}

/// Multiplies a G1 point by a scalar using the native Soroban host function
/// `bls12_381_mul`.
///
/// # Arguments
///
/// * `point` - The G1 point to be multiplied (`BytesN<48>`).
/// * `scalar` - The scalar multiplier (`BytesN<32>`).
///
/// # Returns
///
/// The resulting G1 point (`BytesN<48>`).
pub fn bls12_381_g1_mul(point: BytesN<48>, scalar: BytesN<32>) -> BytesN<48> {
    let env = Env::default();
    env.bls12_381_mul(&point, &scalar)
}

/// Hashes arbitrary data to a G1 point using the native Soroban host function
/// `bls12_381_hash_to_g1`.
///
/// # Arguments
///
/// * `msg` - The data to hash (`Bytes`).
///
/// # Returns
///
/// A G1 point (`BytesN<48>`) derived from the hash.
pub fn bls12_381_hash_to_g1(msg: Bytes) -> BytesN<48> {
    let env = Env::default();
    env.bls12_381_hash_to_g1(&msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::bytes;

    #[test]
    fn test_example_verifier() {
        let result = example();
        assert_eq!(result, "Hello, Verifier!");
    }

    #[test]
    fn test_bls12_381_operations() {
        // Simple sanity checks that the host functions are callable.
        // The actual cryptographic correctness is not verified here.

        let env = Env::default();

        // Create dummy points and scalars (all zeros). The host functions should
        // handle them without panicking and return deterministic results.
        let zero_g1 = BytesN::<48>::from_array(&env, &[0u8; 48]);
        let zero_g2 = BytesN::<96>::from_array(&env, &[0u8; 96]);
        let zero_scalar = BytesN::<32>::from_array(&env, &[0u8; 32]);
        let msg = bytes!(&env, b"test");

        // Pairing check with empty vectors should succeed (by definition).
        assert!(bls12_381_multi_pairing_check(Vec::new(&env), Vec::new(&env)));

        // Adding zero to zero should give zero.
        assert_eq!(bls12_381_g1_add(zero_g1.clone(), zero_g1.clone()), zero_g1);

        // Multiplying zero point by zero scalar should give zero.
        assert_eq!(bls12_381_g1_mul(zero_g1.clone(), zero_scalar.clone()), zero_g1);

        // Hashing to G1 should return a valid point (non‑empty).
        let hashed = bls12_381_hash_to_g1(msg);
        assert_ne!(hashed, BytesN::<48>::from_array(&env, &[0u8; 48]));
    }
}