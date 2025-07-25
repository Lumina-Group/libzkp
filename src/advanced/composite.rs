use pyo3::prelude::*;
use std::collections::HashMap;

use crate::proof::Proof;
use crate::utils::{
    composition::CompositeProof,
    error_handling::ZkpError,
};

/// Create a composite proof from multiple individual proofs
#[pyfunction]
pub fn create_composite_proof(proof_list: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    if proof_list.is_empty() {
        return Err(ZkpError::InvalidInput("proof list cannot be empty".to_string()).into());
    }

    let mut proofs = Vec::new();
    for proof_bytes in proof_list {
        let proof = Proof::from_bytes(&proof_bytes)
            .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof in list".to_string()))?;
        proofs.push(proof);
    }

    let composite = CompositeProof::new(proofs).map_err(PyErr::from)?;
    Ok(composite.to_bytes())
}

/// Verify a composite proof
#[pyfunction]
pub fn verify_composite_proof(composite_bytes: Vec<u8>) -> PyResult<bool> {
    let composite = CompositeProof::from_bytes(&composite_bytes).map_err(PyErr::from)?;
    Ok(composite.verify_integrity())
}

/// Create a proof with metadata
#[pyfunction]
pub fn create_proof_with_metadata(
    proof_data: Vec<u8>,
    metadata: HashMap<String, Vec<u8>>,
) -> PyResult<Vec<u8>> {
    let proof = Proof::from_bytes(&proof_data)
        .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof data".to_string()))?;

    let mut composite = CompositeProof::new(vec![proof]).map_err(PyErr::from)?;

    for (key, value) in metadata {
        composite.add_metadata(key, value);
    }

    Ok(composite.to_bytes())
}

/// Extract metadata from a composite proof
#[pyfunction]
pub fn extract_proof_metadata(
    composite_bytes: Vec<u8>,
) -> PyResult<HashMap<String, Vec<u8>>> {
    let composite = CompositeProof::from_bytes(&composite_bytes).map_err(PyErr::from)?;
    Ok(composite.metadata)
}