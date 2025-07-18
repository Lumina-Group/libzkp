// Merkle Tree implementation for set membership proofs

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// A node in the Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

/// Merkle tree for efficient set membership proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub root: Option<MerkleNode>,
    pub leaves: Vec<[u8; 32]>,
    pub depth: usize,
}

/// Merkle proof for set membership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub leaf_index: usize,
    pub siblings: Vec<([u8; 32], bool)>, // (sibling_hash, is_right_sibling)
    pub root_hash: [u8; 32],
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of elements
    pub fn new(elements: Vec<&[u8]>) -> Self {
        if elements.is_empty() {
            return Self {
                root: None,
                leaves: Vec::new(),
                depth: 0,
            };
        }
        
        // Hash all elements to create leaves
        let leaves: Vec<[u8; 32]> = elements
            .iter()
            .map(|element| Self::hash_leaf(element))
            .collect();
        
        let depth = (leaves.len() as f64).log2().ceil() as usize;
        let root = Self::build_tree(&leaves);
        
        Self {
            root: Some(root),
            leaves,
            depth,
        }
    }
    
    /// Hash a leaf element
    fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"LEAF:");
        hasher.update(data);
        hasher.finalize().into()
    }
    
    /// Hash two internal nodes
    fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"NODE:");
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
    
    /// Build the tree recursively
    fn build_tree(hashes: &[[u8; 32]]) -> MerkleNode {
        if hashes.len() == 1 {
            return MerkleNode {
                hash: hashes[0],
                left: None,
                right: None,
            };
        }
        
        // Pad with zeros if odd number of nodes
        let mut padded_hashes = hashes.to_vec();
        if padded_hashes.len() % 2 == 1 {
            padded_hashes.push([0u8; 32]);
        }
        
        let mut next_level = Vec::new();
        let mut nodes = Vec::new();
        
        for chunk in padded_hashes.chunks(2) {
            let left_hash = chunk[0];
            let right_hash = chunk[1];
            let parent_hash = Self::hash_internal(&left_hash, &right_hash);
            
            let left_node = if hashes.len() == 2 {
                // Base case: create leaf nodes
                MerkleNode {
                    hash: left_hash,
                    left: None,
                    right: None,
                }
            } else {
                // Will be filled in recursive call
                MerkleNode {
                    hash: left_hash,
                    left: None,
                    right: None,
                }
            };
            
            let right_node = if hashes.len() == 2 {
                // Base case: create leaf nodes
                MerkleNode {
                    hash: right_hash,
                    left: None,
                    right: None,
                }
            } else {
                // Will be filled in recursive call
                MerkleNode {
                    hash: right_hash,
                    left: None,
                    right: None,
                }
            };
            
            nodes.push(MerkleNode {
                hash: parent_hash,
                left: Some(Box::new(left_node)),
                right: Some(Box::new(right_node)),
            });
            
            next_level.push(parent_hash);
        }
        
        if next_level.len() == 1 {
            nodes.into_iter().next().unwrap()
        } else {
            Self::build_tree(&next_level)
        }
    }
    
    /// Get the root hash of the tree
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root.as_ref().map(|node| node.hash)
    }
    
    /// Generate a membership proof for an element
    pub fn generate_proof(&self, element: &[u8]) -> Option<MerkleProof> {
        let leaf_hash = Self::hash_leaf(element);
        
        // Find the leaf index
        let leaf_index = self.leaves.iter().position(|&hash| hash == leaf_hash)?;
        
        let root_hash = self.root_hash()?;
        let siblings = self.collect_siblings(leaf_index);
        
        Some(MerkleProof {
            leaf_hash,
            leaf_index,
            siblings,
            root_hash,
        })
    }
    
    /// Collect sibling hashes for the proof path
    fn collect_siblings(&self, mut leaf_index: usize) -> Vec<([u8; 32], bool)> {
        let mut siblings = Vec::new();
        let mut current_level_size = self.leaves.len();
        
        while current_level_size > 1 {
            let is_right = leaf_index % 2 == 1;
            let sibling_index = if is_right {
                leaf_index - 1
            } else {
                leaf_index + 1
            };
            
            // Get sibling hash (this is simplified - in a real implementation,
            // we'd traverse the actual tree structure)
            let sibling_hash = if sibling_index < current_level_size {
                self.leaves[sibling_index.min(self.leaves.len() - 1)]
            } else {
                [0u8; 32] // Padding
            };
            
            siblings.push((sibling_hash, !is_right));
            
            leaf_index /= 2;
            current_level_size = (current_level_size + 1) / 2;
        }
        
        siblings
    }
    
    /// Verify a membership proof
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_hash;
        
        for &(sibling_hash, is_right_sibling) in &proof.siblings {
            current_hash = if is_right_sibling {
                Self::hash_internal(&current_hash, &sibling_hash)
            } else {
                Self::hash_internal(&sibling_hash, &current_hash)
            };
        }
        
        current_hash == proof.root_hash
    }
    
    /// Add a new element to the tree (requires rebuilding)
    pub fn add_element(&mut self, element: &[u8]) {
        let leaf_hash = Self::hash_leaf(element);
        
        if !self.leaves.contains(&leaf_hash) {
            self.leaves.push(leaf_hash);
            
            // Rebuild the tree
            let elements: Vec<Vec<u8>> = self.leaves.iter().map(|h| h.to_vec()).collect();
            let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
            *self = Self::new(element_refs);
        }
    }
    
    /// Check if an element is in the set
    pub fn contains(&self, element: &[u8]) -> bool {
        let leaf_hash = Self::hash_leaf(element);
        self.leaves.contains(&leaf_hash)
    }
    
    /// Get the number of elements in the set
    pub fn size(&self) -> usize {
        self.leaves.len()
    }
}

/// Merkle tree based set for efficient membership operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleSet {
    tree: MerkleTree,
    element_map: HashMap<Vec<u8>, usize>, // element -> leaf_index
}

impl MerkleSet {
    /// Create a new Merkle set
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(vec![]),
            element_map: HashMap::new(),
        }
    }
    
    /// Create a Merkle set from elements
    pub fn from_elements(elements: Vec<Vec<u8>>) -> Self {
        let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
        let tree = MerkleTree::new(element_refs);
        
        let mut element_map = HashMap::new();
        for (index, element) in elements.iter().enumerate() {
            element_map.insert(element.clone(), index);
        }
        
        Self {
            tree,
            element_map,
        }
    }
    
    /// Add an element to the set
    pub fn insert(&mut self, element: Vec<u8>) -> bool {
        if self.element_map.contains_key(&element) {
            return false; // Already exists
        }
        
        let index = self.tree.leaves.len();
        self.element_map.insert(element.clone(), index);
        self.tree.add_element(&element);
        true
    }
    
    /// Check if the set contains an element
    pub fn contains(&self, element: &[u8]) -> bool {
        self.tree.contains(element)
    }
    
    /// Generate a membership proof
    pub fn prove_membership(&self, element: &[u8]) -> Option<MerkleProof> {
        self.tree.generate_proof(element)
    }
    
    /// Verify a membership proof against this set
    pub fn verify_membership(&self, proof: &MerkleProof) -> bool {
        if let Some(root_hash) = self.tree.root_hash() {
            proof.root_hash == root_hash && MerkleTree::verify_proof(proof)
        } else {
            false
        }
    }
    
    /// Get the root hash
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.tree.root_hash()
    }
    
    /// Get the size of the set
    pub fn len(&self) -> usize {
        self.tree.size()
    }
    
    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MerkleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_merkle_tree_basic() {
        let elements = vec![b"alice", b"bob", b"charlie"];
        let tree = MerkleTree::new(elements);
        
        assert!(tree.root_hash().is_some());
        assert_eq!(tree.size(), 3);
        assert!(tree.contains(b"alice"));
        assert!(tree.contains(b"bob"));
        assert!(tree.contains(b"charlie"));
        assert!(!tree.contains(b"dave"));
    }
    
    #[test]
    fn test_merkle_proof() {
        let elements = vec![b"alice", b"bob", b"charlie"];
        let tree = MerkleTree::new(elements);
        
        let proof = tree.generate_proof(b"alice").unwrap();
        assert!(MerkleTree::verify_proof(&proof));
        
        let proof = tree.generate_proof(b"bob").unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }
    
    #[test]
    fn test_merkle_set() {
        let mut set = MerkleSet::new();
        
        assert!(set.insert(b"alice".to_vec()));
        assert!(set.insert(b"bob".to_vec()));
        assert!(!set.insert(b"alice".to_vec())); // Duplicate
        
        assert!(set.contains(b"alice"));
        assert!(set.contains(b"bob"));
        assert!(!set.contains(b"charlie"));
        
        let proof = set.prove_membership(b"alice").unwrap();
        assert!(set.verify_membership(&proof));
    }
}