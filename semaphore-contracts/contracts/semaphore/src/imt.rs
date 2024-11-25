use core::fmt::Debug;
use core::iter::{once, repeat, successors};
use soroban_sdk::{contracttype, Env, Vec};

pub type NodeType = u32; // TODO: data types base on bls12_381_hash_to_g1 return's type

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MerkleTree {
    /// Depth of the tree
    depth: u32,

    empty: Vec<NodeType>,

    /// Hash values of tree nodes and leaves
    nodes: Vec<NodeType>,
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
fn hash_node(left: NodeType, right: NodeType) -> NodeType {
    // TODO: add the `BLS12-381` hash function
    // example
    if left == 0 || right == 0 {
        1
    } else {
        left + right
    }
}

impl MerkleTree {
    /// Create a new Merkle tree with a specified depth and default leaf value
    pub fn new(env: &Env, depth: u32, default_leaf: NodeType) -> Self {
        // Precompute empty hashes using `successors`
        // Precompute empty hashes using `successors`
        let mut empty = Vec::new(env);
        successors(Some(default_leaf), |prev| Some(hash_node(*prev, *prev)))
            .take((depth + 1) as usize)
            .for_each(|hash| empty.push_back(hash));

        let mut nodes = Vec::new(env);
        nodes.push_back(default_leaf); // First node

        // Add empty nodes for each level
        for d in 0..depth {
            let num_nodes = 1 << d; // 2^d nodes at this depth
            let empty_val = empty.get((depth - d) as u32).unwrap();
            for _ in 0..num_nodes {
                nodes.push_back(empty_val);
            }
        }

        Self {
            depth,
            nodes,
            empty,
        }
    }

    pub fn add_leaf(&mut self, leaf_index: usize, leaf_value: NodeType) {
        let total_leaves = 1 << self.depth; // Total number of leaves
        let leaf_pos: usize = total_leaves - 1 + leaf_index; // Position of the leaf in the tree

        // Insert the leaf value
        self.nodes.set(leaf_pos as u32, leaf_value);

        // Update parent nodes up to the root
        let mut current = leaf_pos;
        while let Some(parent_idx) = parent(current) {
            let left = self.nodes.get(left_child(parent_idx) as u32).unwrap_or(0);
            let right = self
                .nodes
                .get((left_child(parent_idx) + 1) as u32)
                .unwrap_or(0);
            let parent_hash = hash_node(left, right);

            // Update the parent hash
            self.nodes.set(parent_idx as u32, parent_hash);
            current = parent_idx;
        }
    }

    pub fn verify_proof(&self, identity_commitment: u32, proof: Vec<u32>) -> bool {
        // TODO: implement proof verification
        true
    }

    pub fn get_root(&self) -> u32 {
        self.nodes.get(1).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let env = Env::default();
        let tree = MerkleTree::new(&env, 3, 0);
        assert_eq!(tree.empty, Vec::from_array(&env, [0, 1, 2, 4]));
        assert_eq!(tree.nodes, Vec::from_array(&env, [0, 4, 2, 2, 1, 1, 1, 1]));
    }
}
