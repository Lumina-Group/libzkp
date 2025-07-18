// Set membership proof implementation using Merkle trees

use super::merkle_tree::{MerkleSet, MerkleProof, MerkleTree};
use super::{ConstraintSystem, CircuitBuilder, Variable, VariableType, LinearConstraint};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Set membership circuit for ZKP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMembershipCircuit {
    pub set_root: [u8; 32],
    pub max_depth: usize,
}

/// Witness for set membership proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMembershipWitness {
    pub element: Vec<u8>,
    pub merkle_proof: MerkleProof,
}

impl SetMembershipCircuit {
    /// Create a new set membership circuit
    pub fn new(set_root: [u8; 32], max_depth: usize) -> Self {
        Self {
            set_root,
            max_depth,
        }
    }
    
    /// Build the constraint system for set membership
    pub fn build_constraints(&self) -> ConstraintSystem {
        let mut builder = CircuitBuilder::new();
        let mut cs = builder.finalize();
        
        // Add variables for the element hash
        let element_hash_var = cs.add_variable(
            "element_hash".to_string(),
            VariableType::UInt(256)
        );
        cs.add_private_input(element_hash_var);
        
        // Add variables for the Merkle proof path
        let mut path_vars = Vec::new();
        let mut sibling_vars = Vec::new();
        
        for i in 0..self.max_depth {
            let path_var = cs.add_variable(
                format!("path_{}", i),
                VariableType::Boolean
            );
            let sibling_var = cs.add_variable(
                format!("sibling_{}", i),
                VariableType::UInt(256)
            );
            
            cs.add_private_input(path_var);
            cs.add_private_input(sibling_var);
            
            path_vars.push(path_var);
            sibling_vars.push(sibling_var);
        }
        
        // Add variable for the computed root
        let computed_root_var = cs.add_variable(
            "computed_root".to_string(),
            VariableType::UInt(256)
        );
        
        // Add variable for the expected root (public input)
        let expected_root_var = cs.add_variable(
            "expected_root".to_string(),
            VariableType::UInt(256)
        );
        cs.add_public_input(expected_root_var);
        
        // Add constraint: computed_root == expected_root
        cs.add_equality_constraint(computed_root_var, expected_root_var);
        
        // Note: In a real implementation, we would add constraints for the
        // hash computations along the Merkle path. This would require
        // implementing SHA256 or another hash function as a circuit.
        // For now, we'll represent this as a placeholder constraint.
        
        cs
    }
    
    /// Generate witness for the circuit
    pub fn generate_witness(&self, element: &[u8], proof: &MerkleProof) -> SetMembershipWitness {
        SetMembershipWitness {
            element: element.to_vec(),
            merkle_proof: proof.clone(),
        }
    }
    
    /// Verify the witness satisfies the circuit
    pub fn verify_witness(&self, witness: &SetMembershipWitness) -> bool {
        // Verify the Merkle proof
        if !MerkleTree::verify_proof(&witness.merkle_proof) {
            return false;
        }
        
        // Check that the proof is for the claimed element
        let element_hash = MerkleTree::hash_leaf(&witness.element);
        if element_hash != witness.merkle_proof.leaf_hash {
            return false;
        }
        
        // Check that the root matches
        witness.merkle_proof.root_hash == self.set_root
    }
}

/// High-level set membership prover
#[derive(Debug)]
pub struct SetMembershipProver {
    pub merkle_set: MerkleSet,
}

impl SetMembershipProver {
    /// Create a new set membership prover
    pub fn new() -> Self {
        Self {
            merkle_set: MerkleSet::new(),
        }
    }
    
    /// Create from existing elements
    pub fn from_elements(elements: Vec<Vec<u8>>) -> Self {
        Self {
            merkle_set: MerkleSet::from_elements(elements),
        }
    }
    
    /// Add an element to the set
    pub fn add_element(&mut self, element: Vec<u8>) -> bool {
        self.merkle_set.insert(element)
    }
    
    /// Generate a membership proof for an element
    pub fn prove_membership(&self, element: &[u8]) -> Option<(SetMembershipCircuit, SetMembershipWitness)> {
        let proof = self.merkle_set.prove_membership(element)?;
        let root_hash = self.merkle_set.root_hash()?;
        
        let circuit = SetMembershipCircuit::new(root_hash, proof.siblings.len());
        let witness = circuit.generate_witness(element, &proof);
        
        Some((circuit, witness))
    }
    
    /// Verify a membership proof
    pub fn verify_membership(&self, circuit: &SetMembershipCircuit, witness: &SetMembershipWitness) -> bool {
        // Check that the circuit root matches our set root
        if let Some(our_root) = self.merkle_set.root_hash() {
            if circuit.set_root != our_root {
                return false;
            }
        } else {
            return false;
        }
        
        circuit.verify_witness(witness)
    }
    
    /// Get the current set root
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.merkle_set.root_hash()
    }
    
    /// Get the number of elements in the set
    pub fn size(&self) -> usize {
        self.merkle_set.len()
    }
}

impl Default for SetMembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch set membership operations
pub struct BatchSetMembershipProver {
    provers: HashMap<String, SetMembershipProver>,
}

impl BatchSetMembershipProver {
    pub fn new() -> Self {
        Self {
            provers: HashMap::new(),
        }
    }
    
    /// Add a named set
    pub fn add_set(&mut self, name: String, elements: Vec<Vec<u8>>) {
        let prover = SetMembershipProver::from_elements(elements);
        self.provers.insert(name, prover);
    }
    
    /// Prove membership in a named set
    pub fn prove_membership(&self, set_name: &str, element: &[u8]) -> Option<(SetMembershipCircuit, SetMembershipWitness)> {
        self.provers.get(set_name)?.prove_membership(element)
    }
    
    /// Verify membership in a named set
    pub fn verify_membership(&self, set_name: &str, circuit: &SetMembershipCircuit, witness: &SetMembershipWitness) -> bool {
        self.provers.get(set_name)
            .map(|prover| prover.verify_membership(circuit, witness))
            .unwrap_or(false)
    }
    
    /// Prove membership in multiple sets (intersection proof)
    pub fn prove_multi_membership(&self, set_names: &[String], element: &[u8]) -> Vec<(SetMembershipCircuit, SetMembershipWitness)> {
        let mut proofs = Vec::new();
        
        for set_name in set_names {
            if let Some(proof) = self.prove_membership(set_name, element) {
                proofs.push(proof);
            }
        }
        
        proofs
    }
    
    /// Get information about all sets
    pub fn get_set_info(&self) -> HashMap<String, (Option<[u8; 32]>, usize)> {
        self.provers.iter()
            .map(|(name, prover)| {
                (name.clone(), (prover.root_hash(), prover.size()))
            })
            .collect()
    }
}

impl Default for BatchSetMembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_set_membership_prover() {
        let elements = vec![
            b"alice".to_vec(),
            b"bob".to_vec(),
            b"charlie".to_vec(),
        ];
        
        let prover = SetMembershipProver::from_elements(elements);
        
        // Test membership proof
        let (circuit, witness) = prover.prove_membership(b"alice").unwrap();
        assert!(prover.verify_membership(&circuit, &witness));
        
        // Test non-membership
        assert!(prover.prove_membership(b"dave").is_none());
    }
    
    #[test]
    fn test_batch_set_membership() {
        let mut batch_prover = BatchSetMembershipProver::new();
        
        batch_prover.add_set("users".to_string(), vec![
            b"alice".to_vec(),
            b"bob".to_vec(),
        ]);
        
        batch_prover.add_set("admins".to_string(), vec![
            b"alice".to_vec(),
            b"charlie".to_vec(),
        ]);
        
        // Test membership in single set
        let (circuit, witness) = batch_prover.prove_membership("users", b"alice").unwrap();
        assert!(batch_prover.verify_membership("users", &circuit, &witness));
        
        // Test multi-set membership
        let proofs = batch_prover.prove_multi_membership(
            &["users".to_string(), "admins".to_string()],
            b"alice"
        );
        assert_eq!(proofs.len(), 2); // Alice is in both sets
        
        let proofs = batch_prover.prove_multi_membership(
            &["users".to_string(), "admins".to_string()],
            b"bob"
        );
        assert_eq!(proofs.len(), 1); // Bob is only in users
    }
}