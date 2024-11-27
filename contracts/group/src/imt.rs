use core::fmt::Debug;
use core::iter::successors;
use soroban_sdk::{contracttype, Bytes, Env, Vec};

use crate::proof::{Branch, Proof};

const DST: &[u8] = b"BLS_SIG_BLS12381G1";

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MerkleTree {
    /// Depth of the tree
    depth: u32,

    empty: Vec<Bytes>,

    /// Hash values of tree nodes and leaves
    nodes: Vec<Bytes>,
}

/// For a given node index, return the parent node index
/// Returns None if there is no parent (root node)
const fn parent(index: usize) -> Option<usize> {
    if index <= 1 {
        None
    } else {
        Some(index >> 1)
    }
}

/// For a given node index, return index of the first (left) child.
const fn left_child(index: usize) -> usize {
    index << 1
}

const fn depth(index: usize) -> usize {
    // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
    // The extra offset corrects this.
    if index <= 1 {
        return 0;
    }

    index.ilog2() as usize
}

/// Compute the hash of a parent node given its two child nodes
/// NOTE: currently using keccak256 for hashing
pub fn hash_node(env: &Env, left: &Bytes, right: &Bytes) -> Bytes {
    let mut combined = Bytes::new(env);
    combined.append(left);
    combined.append(right);

    env.crypto().keccak256(&combined).into()
}

impl MerkleTree {
    /// Create a new Merkle tree with a specified depth and default leaf value
    pub fn new(env: &Env, depth: u32, default_leaf: Bytes) -> Self {
        // Precompute empty hashes using `successors`
        // Precompute empty hashes using `successors`
        let mut empty = Vec::new(env);
        successors(Some(default_leaf.clone()), |prev| {
            Some(hash_node(env, prev, prev))
        })
        .take((depth + 1) as usize)
        .for_each(|hash| empty.push_back(hash));

        let mut nodes = Vec::new(env);
        nodes.push_back(default_leaf); // First node

        // Add empty nodes for each level
        for d in 0..depth {
            let num_nodes = 1 << d; // 2^d nodes at this depth
            let empty_val = empty.get((depth - d) as u32).unwrap();
            for _ in 0..num_nodes {
                nodes.push_back(empty_val.clone());
            }
        }

        Self {
            depth,
            nodes,
            empty,
        }
    }

    pub fn add_leaf(&mut self, env: &Env, leaf_index: usize, leaf_value: Bytes) {
        let leaf_pos = self.get_leaf_position(leaf_index as u32); // Position of the leaf in the tree

        // Insert the leaf value
        self.nodes.set(leaf_pos as u32, leaf_value);

        // Update parent nodes up to the root
        let mut current = leaf_pos;
        while let Some(parent_idx) = parent(current) {
            let left = self.nodes.get(left_child(parent_idx) as u32).unwrap();
            let right = self.nodes.get((left_child(parent_idx) + 1) as u32).unwrap();
            let parent_hash = hash_node(env, &left, &right);

            // Update the parent hash
            self.nodes.set(parent_idx as u32, parent_hash);
            current = parent_idx;
        }
    }

    /// Generate a Merkle proof for a leaf at given index
    pub fn proof(&self, leaf_index: usize) -> Option<Proof> {
        if leaf_index >= self.num_leaves() {
            return None;
        }

        let mut index = self.get_leaf_position(leaf_index as u32);
        let mut path = Vec::new(&self.nodes.env());

        while let Some(parent_idx) = parent(index) {
            // Add proof for node at index to parent
            path.push_back(match index & 1 {
                // If index is odd, we're the right child, need left sibling
                1 => Branch::Left(self.nodes.get((index - 1) as u32).unwrap()),
                // If index is even, we're the left child, need right sibling
                0 => Branch::Right(self.nodes.get((index + 1) as u32).unwrap()),
                _ => unreachable!(),
            });

            index = parent_idx;
        }

        Some(Proof(path))
    }

    pub fn verify_proof(&self, env: &Env, leaf_hash: &Bytes, proof: &Proof) -> bool {
        let root = proof.root(env, leaf_hash);
        let get_root = self.get_root();
        root == get_root
    }

    pub fn get_root(&self) -> Bytes {
        self.nodes.get(1).unwrap()
    }

    pub fn num_leaves(&self) -> usize {
        1 << self.depth
    }

    pub fn get_leaf_position(&self, leaf_index: u32) -> usize {
        (1 << (self.depth - 1)) + leaf_index as usize
    }

    /// hash the bls12_381 value to a g1 point
    pub fn hash_to_g1(&self, env: &Env, value: Bytes) -> Bytes {
        env.crypto()
            .bls12_381()
            .hash_to_g1(&value, &Bytes::from_slice(env, DST))
            .to_bytes()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{crypto::bls12_381::G1Affine, log, vec};

    use super::*;

    #[test]
    fn bls12_381_can_convert_to_bytes_and_back() {
        let env = Env::default();
        let bls12_381 = env.crypto().bls12_381();

        // Create two different messages to hash
        let msg1 = Bytes::from_slice(&env, b"message1 to hash");
        let msg2 = Bytes::from_slice(&env, b"message2 to hash");
        let dst = Bytes::from_slice(&env, b"domain separation tag");

        // Hash both messages to G1 points
        let point1 = bls12_381.hash_to_g1(&msg1, &dst);
        let point2 = bls12_381.hash_to_g1(&msg2, &dst);

        // Convert points to bytes for storage
        let bytes1 = point1.to_bytes();
        let bytes2 = point2.to_bytes();

        // Convert back to points
        let recovered_point1 = G1Affine::from_bytes(bytes1);
        let recovered_point2 = G1Affine::from_bytes(bytes2);

        // Add points using both original and recovered points
        let sum1 = bls12_381.g1_add(&point1, &point2);
        let sum2 = bls12_381.g1_add(&recovered_point1, &recovered_point2);

        // Verify that conversion didn't affect the points
        assert_eq!(point1.to_bytes(), recovered_point1.to_bytes());
        assert_eq!(point2.to_bytes(), recovered_point2.to_bytes());
        assert_eq!(sum1.to_bytes(), sum2.to_bytes());
    }

    #[test]
    fn test_new() {
        let env = Env::default();
        let default_leaf = Bytes::from_slice(&env, b"default_leaf");
        let imt = MerkleTree::new(&env, 3, default_leaf.clone());

        // calculate hash at level t - 1 (hash(leaf + leaf))
        let hash_at_level2 = hash_node(&env, &default_leaf, &default_leaf);

        // 0: default leaf
        // 1: root
        // 2: hash(leaf + leaf)
        // 3: leaf
        let level2_idx = 0 + (1 << 0) + (1 << 1) + 1; // Using bit shifts: 0 + 1 + 2 + 1 = 4
        assert_eq!(imt.nodes.get(level2_idx).unwrap(), hash_at_level2);
    }

    #[test]
    fn test_add_leaf() {
        let env = Env::default();
        let default_leaf = Bytes::from_slice(&env, b"default_leaf");

        // get expected values for testing
        // Tree structure
        //          0 // empty slot
        //          1
        //      2       3
        //    4   5   6   7

        let expected_nodes = vec![
            &env,
            Bytes::from_slice(&env, b"default_leaf"),
            Bytes::from_slice(
                &env,
                &hex::decode("ec44baf66ce9f0165df6f7489e7b768fefaaf97a90e6377011f9725779d849e2")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("b36425c35b074ac99a412458fc0bceaed7e9e401e65e32c9045c38645a0b99a4")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("b36425c35b074ac99a412458fc0bceaed7e9e401e65e32c9045c38645a0b99a4")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("e7d33409e0386a947ba46ff63ad2a5126450a326877d8b1094b70db57c03d50f")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("e7d33409e0386a947ba46ff63ad2a5126450a326877d8b1094b70db57c03d50f")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("e7d33409e0386a947ba46ff63ad2a5126450a326877d8b1094b70db57c03d50f")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("e7d33409e0386a947ba46ff63ad2a5126450a326877d8b1094b70db57c03d50f")
                    .unwrap(),
            ),
        ];

        let test_cases = vec![
            &env,
            // (index to add leaf, leaf value, expected updated node indices)
            (
                0u32,                               // leaf index
                Bytes::from_slice(&env, b"leaf_0"), // some randome value
                vec![&env, 1u32, 2u32, 4u32],       // expected updated node indices
            ),
            (
                1u32,
                Bytes::from_slice(&env, b"leaf_1"),
                vec![&env, 1u32, 2u32, 5u32],
            ),
            (
                2u32,
                Bytes::from_slice(&env, b"leaf_2"),
                vec![&env, 1u32, 3u32, 6u32],
            ),
            (
                3u32,
                Bytes::from_slice(&env, b"leaf_3"),
                vec![&env, 1u32, 3u32, 7u32],
            ),
        ];

        for (index, leaf_value, expected_updated_nodes) in test_cases {
            let mut imt = MerkleTree::new(&env, 3, default_leaf.clone());

            // Add the leaf and log state
            imt.add_leaf(&env, index as usize, leaf_value);

            // Verify nodes are updated correctly
            for i in 0..expected_nodes.len() {
                if expected_updated_nodes.contains(&i) {
                    // Updated nodes should be different from initial state
                    assert_ne!(
                        imt.nodes.get(i).unwrap(),
                        expected_nodes.get(i).unwrap(),
                        "Node {} should have been updated for leaf at index {}",
                        i,
                        index
                    );
                } else {
                    // Other nodes should remain unchanged
                    assert_eq!(
                        imt.nodes.get(i).unwrap(),
                        expected_nodes.get(i).unwrap(),
                        "Node {} should not have changed for leaf at index {}",
                        i,
                        index
                    );
                }
            }
        }
    }

    #[test]
    fn test_proof_and_verify() {
        let env = Env::default();
        let mut imt = MerkleTree::new(&env, 3, Bytes::from_slice(&env, b"default_leaf"));

        // Setup test leaves
        let test_leaves = vec![
            &env,
            (0u32, Bytes::from_slice(&env, b"leaf_0")),
            (1u32, Bytes::from_slice(&env, b"leaf_1")),
            (2u32, Bytes::from_slice(&env, b"leaf_2")),
            (3u32, Bytes::from_slice(&env, b"leaf_3")),
        ];

        // Add all leaves
        for (index, leaf_value) in test_leaves.iter() {
            imt.add_leaf(&env, index as usize, leaf_value.clone());
        }

        let expected_nodes = vec![
            &env,
            Bytes::from_slice(&env, b"64656661756c745f6c656166"),
            Bytes::from_slice(
                &env,
                &hex::decode("3411afb1a213a227a3e6914c3cdef1421ccdce632feae7fc29f4a0fa05690ec1")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("3b7e0da5747e3704403e122296d2796f7c98b11285add1298aabc373a277b1cb")
                    .unwrap(),
            ),
            Bytes::from_slice(
                &env,
                &hex::decode("060727d65d4f88eac77322dfb53320954f8fb0495dda1f26f14d1fcb2cdd60d7")
                    .unwrap(),
            ),
            Bytes::from_slice(&env, &hex::decode("6c6561665f30").unwrap()),
            Bytes::from_slice(&env, &hex::decode("6c6561665f31").unwrap()),
            Bytes::from_slice(&env, &hex::decode("6c6561665f32").unwrap()),
            Bytes::from_slice(&env, &hex::decode("6c6561665f33").unwrap()),
        ];

        // Test cases for proof verification
        let proof_test_cases = vec![
            &env,
            (
                0u32,
                vec![
                    &env,
                    Branch::Right(expected_nodes.get(5).unwrap()),
                    Branch::Right(expected_nodes.get(3).unwrap()),
                ], // proof path
            ),
            (
                1u32,
                vec![
                    &env,
                    Branch::Left(expected_nodes.get(4).unwrap()),
                    Branch::Right(expected_nodes.get(3).unwrap()),
                ], // proof path
            ),
            (
                2u32,
                vec![
                    &env,
                    Branch::Right(expected_nodes.get(7).unwrap()),
                    Branch::Left(expected_nodes.get(2).unwrap()),
                ], // proof path
            ),
            (
                3u32,
                vec![
                    &env,
                    Branch::Left(expected_nodes.get(6).unwrap()),
                    Branch::Left(expected_nodes.get(2).unwrap()),
                ], // proof path
            ),
        ];

        for (leaf_index, proof_path) in proof_test_cases {
            let proof = imt.proof(leaf_index as usize).unwrap();
            // Verify proof length
            for i in 0..proof_path.len() {
                assert_eq!(proof.0.get(i).unwrap(), proof_path.get(i).unwrap());
            }

            let leaf_hash = test_leaves.get(leaf_index).unwrap().1;

            let root = proof.root(&env, &leaf_hash);
            assert_eq!(root, imt.get_root());
        }
    }
}
