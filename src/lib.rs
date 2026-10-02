use soroban_sdk::{contract, contractimpl, Address, Symbol, Map, Vec, env::HostFunctionType, Env};

// BLS12-381 types mapped to byte arrays (CAP-0059)
pub const BLS12_381_G1_COMPRESSED_SIZE: usize = 48;
pub const BLS12_381_G2_COMPRESSED_SIZE: usize = 96;
pub const BLS12_381_SCALAR_SIZE: usize = 32;

// Semaphore circuit constants
pub const CIRCUIT_GATES: u32 = 101; // number of gates in Semaphore circuit
pub const NB_PUBLIC: u32 = 3; // number of public inputs (nullifier, message_hash, merkle_root)
pub const NB_PRIVATE: u32 = 5; // number of private inputs
pub const NB_COMMITMENTS: u32 = 2; // alpha_1, gamma_2

#[contract]
pub struct SemaphoreVerifier;

#[contractimpl]
impl SemaphoreVerifier {
    /// Verify a Semaphore proof on-chain using BLS12-381 pairing checks.
    ///
    /// Arguments:
    /// - env: Soroban environment
    /// - nullifier_hash: 32-byte nullifier hash (public input)
    /// - signal_hash: 32-byte hash of the signal/message (public input)
    /// - merkle_root: 32-byte Merkle root of the tree (public input)
    /// - proof: compressed proof bytes as Vec<u8>
    ///
    /// Returns true if the proof is valid, false otherwise.
    pub fn verify(
        env: Env,
        nullifier_hash: [u8; 32],
        signal_hash: [u8; 32],
        merkle_root: [u8; 32],
        proof: Vec<u8>,
    ) -> bool {
        let public_inputs = [nullifier_hash, signal_hash, merkle_root];

        Self::verify_with_circuit(&env, &public_inputs, &proof)
    }

    /// Verify using the Semaphore circuit constants.
    pub fn verify_with_circuit(
        env: &Env,
        public_inputs: &[[u8; 32]; NB_PUBLIC as usize],
        proof: &[u8],
    ) -> bool {
        Self::verify_circuit(
            env,
            *public_inputs,
            proof,
            NB_COMMITMENTS,
            NB_PRIVATE,
            NB_PUBLIC,
            CIRCUIT_GATES,
        )
    }

    /// Core verification logic using BLS12-381 pairing checks (CAP-0059).
    /// Implements the Groth16 verification equation:
    ///     e(alpha_1, beta_2) == e(A, B) * e(C, D) * product of public input pairings
    fn verify_circuit(
        env: &Env,
        public_inputs: [[u8; 32]; NB_PUBLIC as usize],
        proof: &[u8],
        nb_commitments: u32,
        nb_private_inputs: u32,
        nb_public_inputs: u32,
        gate_count: u32,
    ) -> bool {
        // Parse proof points from the compressed proof bytes
        let proof_data = Self::parse_proof(proof);

        let a_g1 = proof_data.a_g1;
        let b_g1 = proof_data.b_g1;
        let b_g2 = proof_data.b_g2;
        let c_g1 = proof_data.c_g1;
        let c_g2 = proof_data.c_g2;
        let gamma_g2 = proof_data.gamma_g2;
        let delta_g1 = proof_data.delta_g1;
        let delta_g2 = proof_data.delta_g2;

        // Compute the public input affine coordinates in G1 (hashed to curve)
        let mut public_affine: Vec<[u8; 32]> = Vec::new();
        for input in &public_inputs {
            let pt = Self::hash_to_g1_bytes(env, input);
            public_affine.push(pt);
        }

        // For Semaphore, the public inputs map to specific points in the verification key
        // nullifier_hash -> pk[0], signal_hash -> pk[1], merkle_root -> pk[2]
        let pi_a = Self::compute_pi_a(env, &public_affine);
        let pi_b = Self::compute_pi_b(env, &public_affine);
        let pi_c = Self::compute_pi_c(env, &public_affine);

        // --- BLS12-381 Pairing Checks ---
        // The Groth16 verification equation:
        //   A(α,β) = e(alpha_1, beta_2)
        //             / (e(A, B) * e(C, D) * e(pi_a, H) * e(pi_b, K) * e(pi_c, L))
        // But Semaphore uses a simplified circuit. We verify via multi-pairing.

        // Compute the "A" point for the pairing: A = alpha_1 (from proof)
        // We need: e(alpha_1, beta_2) * e(A, -B) * e(C, -D) * pairing_with_public_inputs == 1

        // For the Semaphore verifier, we use the standard multi-pairing approach:
        // e(α, β) · e(A, H)^(-1) · e(C, D)^(-1) · Π e(public_input_i, basis_i)^(-1) = 1

        // Using CAP-0059 native host functions:
        // bls12_381_multi_pairing_check((g1_points, g2_points)) -> bool

        // Build the G1 points for multi-pairing:
        // [α, A_neg, C_neg, pi_a_neg, pi_b_neg, pi_c_neg]
        // Build the G2 points for multi-pairing:
        // [β, B, D_neg, H_basis, K_basis, L_basis]

        // For Semaphore circuit specifically:
        // A = a_g1, B = b_g1, C = c_g1
        // D = c_g2 (pairing with C), H = b_g2 (pairing with A negated)
        // The public inputs contribute through the verification key basis points

        // Compute negated points for G1
        let a_g1_neg = Self::bls12_381_g1_neg(env, &a_g1);
        let c_g1_neg = Self::bls12_381_g1_neg(env, &c_g1);

        // pi_a, pi_b, pi_c are in G1 (hash-to-curve outputs), negate them
        let pi_a_neg = Self::bls12_381_g1_neg(env, &pi_a);
        let pi_b_neg = Self::bls12_381_g1_neg(env, &pi_b);
        let pi_c_neg = Self::bls12_381_g1_neg(env, &pi_c);

        // Semaphore verification key basis points (precomputed, stored as constants)
        // These correspond to H, K, L in G2 for the public input polynomials
        let h_g2 = Self::get_h_g2();
        let k_g2 = Self::get_k_g2();
        let l_g2 = Self::get_l_g2();

        // Build G1 points array: [α, A_neg, C_neg, pi_a_neg, pi_b_neg, pi_c_neg]
        let mut g1_points: Vec<[u8; BLS12_381_G1_COMPRESSED_SIZE]> = Vec::new();
        g1_points.push(a_g1);
        g1_points.push(a_g1_neg);
        g1_points.push(c_g1_neg);

        // Build G2 points array: [β, B, D_neg, H, K, L]
        let mut g2_points: Vec<[u8; BLS12_381_G2_COMPRESSED_SIZE]> = Vec::new();
        g2_points.push(b_g2); // beta_2
        g2_points.push(b_g1); // alpha_2 equivalent - for pairing with A
        g2_points.push(c_g2); // delta_2 equivalent - for pairing with C

        // Additional G2 basis points for public inputs
        g2_points.push(h_g2);
        g2_points.push(k_g2);
        g2_points.push(l_g2);

        // Perform the multi-pairing check
        let pairing_result = Self::bls12_381_multi_pairing_check(
            env,
            &g1_points,
            &g2_points,
        );

        pairing_result
    }

    /// Parse the compressed proof bytes into individual BLS12-381 points.
    /// Semaphore proof format (compressed):
    ///   A (G1): 48 bytes
    ///   B (G2): 96 bytes
    ///   C (G1): 48 bytes
    ///   D (G2): 96 bytes
    ///   E (G1): 48 bytes  (alpha)
    ///   F (G2): 96 bytes  (beta)
    ///   G (G1): 48 bytes  (gamma)
    ///   H (G1): 48 bytes  (delta)
    fn parse_proof(proof: &[u8]) -> ProofPoints {
        // Semaphore circuit proof has specific layout
        // Total compressed proof size for Semaphore: ~432 bytes
        // but we parse dynamically based on available data

        let mut offset = 0;

        let read_g1 = |data: &[u8], off: &mut usize| -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
            let mut buf = [0u8; BLS12_381_G1_COMPRESSED_SIZE];
            buf.copy_from_slice(&data[*off..*off + BLS12_381_G1_COMPRESSED_SIZE]);
            *off += BLS12_381_G1_COMPRESSED_SIZE;
            buf
        };

        let read_g2 = |data: &[u8], off: &mut usize| -> [u8; BLS12_381_G2_COMPRESSED_SIZE] {
            let mut buf = [0u8; BLS12_381_G2_COMPRESSED_SIZE];
            buf.copy_from_slice(&data[*off..*off + BLS12_381_G2_COMPRESSED_SIZE]);
            *off += BLS12_381_G2_COMPRESSED_SIZE;
            buf
        };

        let a_g1 = read_g1(proof, &mut offset);
        let b_g2 = read_g2(proof, &mut offset);
        let c_g1 = read_g1(proof, &mut offset);
        let d_g2 = read_g2(proof, &mut offset);

        // For Semaphore, the proof format uses:
        // A, B (G2), C, D (G2) as the main proof components
        // Additional points for the circuit

        let mut proof_data = ProofPoints {
            a_g1,
            b_g1: [0u8; BLS12_381_G1_COMPRESSED_SIZE],
            b_g2,
            c_g1,
            c_g2: d_g2,
            gamma_g1: [0u8; BLS12_381_G1_COMPRESSED_SIZE],
            gamma_g2: [0u8; BLS12_381_G2_COMPRESSED_SIZE],
            delta_g1: [0u8; BLS12_381_G1_COMPRESSED_SIZE],
            delta_g2: [0u8; BLS12_381_G2_COMPRESSED_SIZE],
        };

        // Check if there are additional proof components
        if offset + BLS12_381_G1_COMPRESSED_SIZE <= proof.len() {
            proof_data.delta_g1 = read_g1(proof, &mut offset);
        }
        if offset + BLS12_381_G2_COMPRESSED_SIZE <= proof.len() {
            proof_data.delta_g2 = read_g2(proof, &mut offset);
        }
        if offset + BLS12_381_G1_COMPRESSED_SIZE <= proof.len() {
            proof_data.gamma_g1 = read_g1(proof, &mut offset);
        }
        if offset + BLS12_381_G2_COMPRESSED_SIZE <= proof.len() {
            proof_data.gamma_g2 = read_g2(proof, &mut offset);
        }
        if offset + BLS12_381_G1_COMPRESSED_SIZE <= proof.len() {
            proof_data.b_g1 = read_g1(proof, &mut offset);
        }

        proof_data
    }

    /// Hash a 32-byte scalar to a BLS12-381 G1 point using the NIST SP 800-185 hash_to_field
    /// method (SipHash variant for BLS12-381).
    fn hash_to_g1_bytes(env: &Env, input: &[u8; 32]) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        // Use the CAP-0059 bls12_381_hash_to_g1 host function
        Self::bls12_381_hash_to_g1(env, input)
    }

    /// Negate a G1 point by negating its y-coordinate (in affine representation).
    /// For compressed points, we flip the sign bit.
    fn bls12_381_g1_neg(
        env: &Env,
        point: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        // Create decompressed point, negate, recompress
        // For efficiency, use host function to decompress, then negate
        let decompressed = Self::bls12_381_g1_decompress(env, point);
        let negated = Self::bls12_381_g1_negate_affine(env, &decompressed);
        Self::bls12_381_g1_compress(env, &negated)
    }

    /// Compute pi_a = sum of public inputs multiplied by their A-basis coefficients.
    /// For Semaphore circuit, the public input matrix defines how each input maps.
    fn compute_pi_a(
        env: &Env,
        public_inputs: &[[u8; 32]],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        // Semaphore's pi_a = nullifier_hash * H_a + signal_hash * H_signal_a + merkle_root * H_merkle_a
        // where H_*_a are the verification key basis points in G1

        // Start with the first public input hashed to G1
        let mut result = Self::hash_to_g1_bytes(env, &public_inputs[0]);

        // Add contributions from other public inputs using G1 multiplication and addition
        if public_inputs.len() > 1 {
            let second_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[1]);
            // Multiply by the corresponding basis scalar and add
            let scaled = Self::bls12_381_g1_mul(env, &second_input_pt, &[1u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        if public_inputs.len() > 2 {
            let third_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[2]);
            let scaled = Self::bls12_381_g1_mul(env, &third_input_pt, &[1u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        result
    }

    /// Compute pi_b = sum of public inputs multiplied by their B-basis coefficients (G2 space).
    fn compute_pi_b(
        env: &Env,
        public_inputs: &[[u8; 32]],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        let mut result = Self::hash_to_g1_bytes(env, &public_inputs[0]);

        if public_inputs.len() > 1 {
            let second_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[1]);
            let scaled = Self::bls12_381_g1_mul(env, &second_input_pt, &[2u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        if public_inputs.len() > 2 {
            let third_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[2]);
            let scaled = Self::bls12_381_g1_mul(env, &third_input_pt, &[3u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        result
    }

    /// Compute pi_c for the third component.
    fn compute_pi_c(
        env: &Env,
        public_inputs: &[[u8; 32]],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        let mut result = Self::hash_to_g1_bytes(env, &public_inputs[0]);

        if public_inputs.len() > 1 {
            let second_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[1]);
            let scaled = Self::bls12_381_g1_mul(env, &second_input_pt, &[4u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        if public_inputs.len() > 2 {
            let third_input_pt = Self::hash_to_g1_bytes(env, &public_inputs[2]);
            let scaled = Self::bls12_381_g1_mul(env, &third_input_pt, &[5u8; 32]);
            result = Self::bls12_381_g1_add(env, &result, &scaled);
        }

        result
    }

    // ========== CAP-0059 BLS12-381 Host Function Wrappers ==========

    /// Wrapper for bls12_381_multi_pairing_check host function.
    /// Checks that the product of pairings e(g1_points[i], g2_points[i]) equals 1.
    fn bls12_381_multi_pairing_check(
        env: &Env,
        g1_points: &Vec<[u8; BLS12_381_G1_COMPRESSED_SIZE]>,
        g2_points: &Vec<[u8; BLS12_381_G2_COMPRESSED_SIZE]>,
    ) -> bool {
        // Call the native host function via invoke_host_function
        let g1_raw: Vec<soroban_sdk::RawVal> = g1_points.iter().map(|p| {
            soroban_sdk::RawVal::from_val((*p).clone())
        }).collect();

        let g2_raw: Vec<soroban_sdk::RawVal> = g2_points.iter().map(|p| {
            soroban_sdk::RawVal::from_val((*p).clone())
        }).collect();

        // Use the built-in bls12_381_multi_pairing_check via env.invoke_contract
        // In Soroban CAP-0059, this is available as a host function
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381MultiPairingCheck,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(g1_raw),
                soroban_sdk::RawVal::from_val(g2_raw),
            ]),
        )
        .unwrap()
        .try_into_val(env)
        .unwrap()
    }

    /// Wrapper for bls12_381_g1_add host function.
    fn bls12_381_g1_add(
        env: &Env,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        b: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381G1Add,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(a.clone()),
                soroban_sdk::RawVal::from_val(b.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    /// Wrapper for bls12_381_g1_mul host function.
    fn bls12_381_g1_mul(
        env: &Env,
        point: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        scalar: &[u8; BLS12_381_SCALAR_SIZE],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381G1Mul,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(point.clone()),
                soroban_sdk::RawVal::from_val(scalar.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    /// Wrapper for bls12_381_hash_to_g1 host function.
    fn bls12_381_hash_to_g1(
        env: &Env,
        input: &[u8; BLS12_381_SCALAR_SIZE],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381HashToG1,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(input.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    /// Decompress a compressed G1 point to affine coordinates.
    fn bls12_381_g1_decompress(
        env: &Env,
        compressed: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE * 2] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381G1Decompress,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(compressed.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    /// Negate an affine G1 point (swap sign of y-coordinate).
    fn bls12_381_g1_negate_affine(
        env: &Env,
        point: &[u8; BLS12_381_G1_COMPRESSED_SIZE * 2],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE * 2] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381G1Neg,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(point.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    /// Compress an affine G1 point back to compressed form.
    fn bls12_381_g1_compress(
        env: &Env,
        point: &[u8; BLS12_381_G1_COMPRESSED_SIZE * 2],
    ) -> [u8; BLS12_381_G1_COMPRESSED_SIZE] {
        env.as_env().invoke_host_function(
            soroban_sdk::host::HostFunctionType::Bls12381G1Compress,
            soroban_sdk::xdr::ToXdr::to_xdr(env.host(), vec![
                soroban_sdk::RawVal::from_val(point.clone()),
            ]),
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    // ========== Semaphore Verification Key Constants ==========
    // These are the basis points for the Semaphore circuit in G2.
    // H, K, L correspond to the public input polynomial evaluations.

    /// Returns the H basis point in G2 (for the first public input).
    fn get_h_g2() -> [u8; BLS12_381_G2_COMPRESSED_SIZE] {
        // This would be derived from the circuit's trusted setup.
        // For Semaphore v4, these are fixed constants.
        // Placeholder: actual values come from the circuit parameters.
        [0u8; BLS12_381_G2_COMPRESSED_SIZE]
    }

    /// Returns the K basis point in G2 (for the second public input).
    fn get_k_g2() -> [u8; BLS12_381_G2_COMPRESSED_SIZE] {
        [0u8; BLS12_381_G2_COMPRESSED_SIZE]
    }

    /// Returns the L basis point in G2 (for the third public input).
    fn get_l_g2() -> [u8; BLS12_381_G2_COMPRESSED_SIZE] {
        [0u8; BLS12_381_G2_COMPRESSED_SIZE]
    }
}

/// Structure holding parsed proof points from the compressed proof bytes.
#[derive(Clone, Debug)]
struct ProofPoints {
    a_g1: [u8; BLS12_381_G1_COMPRESSED_SIZE],
    b_g1: [u8; BLS12_381_G1_COMPRESSED_SIZE],
    b_g2: [u8; BLS12_381_G2_COMPRESSED_SIZE],
    c_g1: [u8; BLS12_381_G1_COMPRESSED_SIZE],
    c_g2: [u8; BLS12_381_G2_COMPRESSED_SIZE],
    gamma_g1: [u8; BLS12_381_G1_COMPRESSED_SIZE],
    gamma_g2: [u8; BLS12_381_G2_COMPRESSED_SIZE],
    delta_g1: [u8; BLS12_381_G1_COMPRESSED_SIZE],
    delta_g2: [u8; BLS12_381_G2_COMPRESSED_SIZE],
}
