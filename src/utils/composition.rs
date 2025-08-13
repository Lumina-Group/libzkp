use crate::proof::Proof;
use crate::utils::error_handling::{ZkpError, ZkpResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Composite proof that combines multiple individual proofs
#[derive(Debug, Clone)]
pub struct CompositeProof {
    pub proofs: Vec<Proof>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub composition_hash: Vec<u8>,
}

impl CompositeProof {
    /// Create a new composite proof from individual proofs
    pub fn new(proofs: Vec<Proof>) -> ZkpResult<Self> {
        if proofs.is_empty() {
            return Err(ZkpError::InvalidInput("cannot create composite proof from empty list".to_string()));
        }
        
        let composition_hash = Self::compute_composition_hash(&proofs);
        
        Ok(CompositeProof {
            proofs,
            metadata: HashMap::new(),
            composition_hash,
        })
    }
    
    /// Add metadata to the composite proof
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
        // Recompute hash when metadata changes
        self.composition_hash = Self::compute_composition_hash(&self.proofs);
    }
    
    /// Compute the composition hash for integrity verification
    fn compute_composition_hash(proofs: &[Proof]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"COMPOSITE_PROOF:");
        hasher.update(&(proofs.len() as u32).to_le_bytes());
        
        for proof in proofs {
            hasher.update(&proof.to_bytes());
        }
        
        hasher.finalize().to_vec()
    }
    
    /// Serialize the composite proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Header
        result.extend_from_slice(b"COMP");
        result.extend_from_slice(&(self.proofs.len() as u32).to_le_bytes());
        result.extend_from_slice(&(self.metadata.len() as u32).to_le_bytes());
        
        // Proofs
        for proof in &self.proofs {
            let proof_bytes = proof.to_bytes();
            result.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(&proof_bytes);
        }
        
        // Metadata
        for (key, value) in &self.metadata {
            let key_bytes = key.as_bytes();
            result.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(key_bytes);
            result.extend_from_slice(&(value.len() as u32).to_le_bytes());
            result.extend_from_slice(value);
        }
        
        // Composition hash
        result.extend_from_slice(&self.composition_hash);
        
        result
    }
    
    /// Deserialize composite proof from bytes
    pub fn from_bytes(data: &[u8]) -> ZkpResult<Self> {
        if data.len() < 12 {
            return Err(ZkpError::InvalidProofFormat(format!(
                "composite proof too short: expected at least 12 bytes, got {}",
                data.len()
            )));
        }
        
        if &data[0..4] != b"COMP" {
            return Err(ZkpError::InvalidProofFormat(format!(
                "invalid composite proof header: expected 'COMP', got '{:?}'",
                &data[0..4]
            )));
        }
        
        let num_proofs = match data[4..8].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return Err(ZkpError::InvalidProofFormat("invalid proofs count".to_string())),
        };
        let num_metadata = match data[8..12].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return Err(ZkpError::InvalidProofFormat("invalid metadata count".to_string())),
        };
        
        // Validate reasonable limits
        if num_proofs > 1000 || num_metadata > 1000 {
            return Err(ZkpError::InvalidProofFormat(format!(
                "composite proof has too many items: proofs={}, metadata={}",
                num_proofs, num_metadata
            )));
        }
        
        let mut offset = 12;
        let mut proofs = Vec::new();
        
        // Read proofs
        for _ in 0..num_proofs {
            if offset + 4 > data.len() {
                return Err(ZkpError::InvalidProofFormat("truncated proof length".to_string()));
            }
            
            let proof_len = match data[offset..offset+4].try_into() {
                Ok(arr) => u32::from_le_bytes(arr) as usize,
                Err(_) => return Err(ZkpError::InvalidProofFormat("invalid proof length".to_string())),
            };
            offset += 4;
            
            if offset + proof_len > data.len() {
                return Err(ZkpError::InvalidProofFormat("truncated proof data".to_string()));
            }
            
            let proof = Proof::from_bytes(&data[offset..offset+proof_len])
                .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof in composite".to_string()))?;
            
            proofs.push(proof);
            offset += proof_len;
        }
        
        // Read metadata
        let mut metadata = HashMap::new();
        for i in 0..num_metadata {
            if offset + 8 > data.len() {
                return Err(ZkpError::InvalidProofFormat(format!(
                    "truncated metadata header at index {}: offset={}, data_len={}",
                    i, offset, data.len()
                )));
            }
            
            let key_len = match data[offset..offset+4].try_into() {
                Ok(arr) => u32::from_le_bytes(arr) as usize,
                Err(_) => return Err(ZkpError::InvalidProofFormat("invalid metadata key length".to_string())),
            };
            let value_len = match data[offset+4..offset+8].try_into() {
                Ok(arr) => u32::from_le_bytes(arr) as usize,
                Err(_) => return Err(ZkpError::InvalidProofFormat("invalid metadata value length".to_string())),
            };
            offset += 8;
            
            // Validate key and value lengths
            if key_len > 1024 || value_len > 65536 {
                return Err(ZkpError::InvalidProofFormat(format!(
                    "metadata size too large at index {}: key_len={}, value_len={}",
                    i, key_len, value_len
                )));
            }
            
            if offset + key_len + value_len > data.len() {
                return Err(ZkpError::InvalidProofFormat(format!(
                    "truncated metadata content at index {}: offset={}, key_len={}, value_len={}, data_len={}",
                    i, offset, key_len, value_len, data.len()
                )));
            }
            
            let key = String::from_utf8(data[offset..offset+key_len].to_vec())
                .map_err(|_| ZkpError::InvalidProofFormat(format!(
                    "invalid metadata key at index {}: non-utf8 bytes",
                    i
                )))?;
            offset += key_len;
            
            let value = data[offset..offset+value_len].to_vec();
            offset += value_len;
            
            metadata.insert(key, value);
        }
        
        // Read composition hash
        if offset + 32 > data.len() {
            return Err(ZkpError::InvalidProofFormat("missing composition hash".to_string()));
        }
        
        let composition_hash = data[offset..offset+32].to_vec();
        
        // Verify composition hash
        let expected_hash = Self::compute_composition_hash(&proofs);
        if composition_hash != expected_hash {
            return Err(ZkpError::InvalidProofFormat("composition hash mismatch".to_string()));
        }
        
        Ok(CompositeProof {
            proofs,
            metadata,
            composition_hash,
        })
    }
    
    /// Verify the integrity of the composite proof
    pub fn verify_integrity(&self) -> bool {
        let expected_hash = Self::compute_composition_hash(&self.proofs);
        self.composition_hash == expected_hash
    }
}

/// Batch proof operations for improved performance
pub struct ProofBatch {
    operations: Vec<BatchOperation>,
}

#[derive(Debug, Clone)]
pub enum BatchOperation {
    RangeProof { value: u64, min: u64, max: u64 },
    EqualityProof { val1: u64, val2: u64 },
    ThresholdProof { values: Vec<u64>, threshold: u64 },
    MembershipProof { value: u64, set: Vec<u64> },
    ImprovementProof { old: u64, new: u64 },
    ConsistencyProof { data: Vec<u64> },
}

impl ProofBatch {
    pub fn new() -> Self {
        ProofBatch {
            operations: Vec::new(),
        }
    }
    
    pub fn add_range_proof(&mut self, value: u64, min: u64, max: u64) {
        self.operations.push(BatchOperation::RangeProof { value, min, max });
    }
    
    pub fn add_equality_proof(&mut self, val1: u64, val2: u64) {
        self.operations.push(BatchOperation::EqualityProof { val1, val2 });
    }
    
    pub fn add_threshold_proof(&mut self, values: Vec<u64>, threshold: u64) {
        self.operations.push(BatchOperation::ThresholdProof { values, threshold });
    }
    
    pub fn add_membership_proof(&mut self, value: u64, set: Vec<u64>) {
        self.operations.push(BatchOperation::MembershipProof { value, set });
    }
    
    pub fn add_improvement_proof(&mut self, old: u64, new: u64) {
        self.operations.push(BatchOperation::ImprovementProof { old, new });
    }
    
    pub fn add_consistency_proof(&mut self, data: Vec<u64>) {
        self.operations.push(BatchOperation::ConsistencyProof { data });
    }
    
    pub fn len(&self) -> usize {
        self.operations.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
    
    pub fn operations(&self) -> &[BatchOperation] {
        &self.operations
    }
}

impl Default for ProofBatch {
    fn default() -> Self {
        Self::new()
    }
}