use core::fmt::Debug;
use core::iter::successors;
use soroban_sdk::{contracttype, Bytes, Env, Vec};

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
fn hash_node(env: &Env, left: Bytes, right: Bytes) -> Bytes {
    let mut combined = Bytes::new(env);
    combined.append(&left);
    combined.append(&right);

    env.crypto().keccak256(&combined).into()
}

impl MerkleTree {
    /// Create a new Merkle tree with a specified depth and default leaf value
    pub fn new(env: &Env, depth: u32, default_leaf: Bytes) -> Self {
        // Precompute empty hashes using `successors`
        // Precompute empty hashes using `successors`
        let mut empty = Vec::new(env);
        successors(Some(default_leaf.clone()), |prev| {
            Some(hash_node(env, prev.clone(), prev.clone()))
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
        let total_leaves = 1 << self.depth; // Total number of leaves
        let leaf_pos: usize = total_leaves - 1 + leaf_index; // Position of the leaf in the tree

        // Insert the leaf value
        self.nodes.set(leaf_pos as u32, leaf_value);

        // Update parent nodes up to the root
        let mut current = leaf_pos;
        while let Some(parent_idx) = parent(current) {
            let left = self.nodes.get(left_child(parent_idx) as u32).unwrap();
            let right = self.nodes.get((left_child(parent_idx) + 1) as u32).unwrap();
            let parent_hash = hash_node(env, left, right);

            // Update the parent hash
            self.nodes.set(parent_idx as u32, parent_hash);
            current = parent_idx;
        }
    }

    /// Generate a Merkle proof for a leaf at given index
    pub fn proof(&self, leaf_index: usize) {
        // if leaf_index >= self.num_leaves() {
        //     return None;
        // }

        // let mut index = self.num_leaves() + leaf_index;
        // let mut path = Vec::new(&self.nodes.env());

        // while let Some(parent_idx) = parent(index as usize) {
        //     // Add proof for node at index to parent
        //     path.push_back(match index & 1 {
        //         // If index is odd, we're the right child, need left sibling
        //         1 => Branch::Right(self.nodes.get(index - 1).unwrap()),
        //         // If index is even, we're the left child, need right sibling
        //         0 => Branch::Left(self.nodes.get(index + 1).unwrap()),
        //         _ => unreachable!(),
        //     });
        //     index = parent_idx as u32;
        // }

        // Some(Proof(path))
    }

    pub fn get_root(&self) -> Bytes {
        self.nodes.get(1).unwrap()
    }

    pub fn num_leaves(&self) -> usize {
        1 << self.depth
    }
}

#[cfg(test)]
mod tests {
    use core::iter::Empty;

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
        let hash_at_level2 = hash_node(&env, default_leaf.clone(), default_leaf.clone());

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
        let mut imt = MerkleTree::new(&env, 3, default_leaf.clone());

        let leaf_value = Bytes::from_slice(&env, b"new_leaf");

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

        imt.add_leaf(&env, 0, leaf_value);

        // add new leaf -> what happens?
        // right most leaf is updated
        // corresponding internal nodes are updated
        let expected_updated_nodes = vec![&env, 1, 3, 7];

        for i in 0..expected_nodes.len() {
            // if the node is in the expected_updated_nodes, it should be updated
            if expected_updated_nodes.contains(&i) {
                assert_ne!(imt.nodes.get(i).unwrap(), expected_nodes.get(i).unwrap());
            } else {
                // else, should not
                assert_eq!(imt.nodes.get(i).unwrap(), expected_nodes.get(i).unwrap());
            }
        }
    }
}
