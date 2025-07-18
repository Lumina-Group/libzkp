
use crate::backend::bulletproofs::BulletproofsBackend;
use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;

const SCHEME_ID: u8 = 4;

#[pyfunction]
pub fn prove_membership(value: u64, set: Vec<u64>) -> PyResult<Vec<u8>> {
    let backend_proof = BulletproofsBackend::prove_set_membership(value, set)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
    
    let commit_marker = b"COMMIT:";
    let commit_pos = backend_proof.windows(commit_marker.len())
        .position(|window| window == commit_marker)
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "invalid backend proof format"
        ))?;
    
    let proof_bytes = &backend_proof[0..commit_pos];
    let commit_start = commit_pos + commit_marker.len();
    
    if backend_proof.len() < commit_start + 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "invalid commitment in backend proof"
        ));
    }
    
    let commitment = backend_proof[commit_start..commit_start + 32].to_vec();
    
    let proof = Proof::new(SCHEME_ID, proof_bytes.to_vec(), commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_membership(proof: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };
    
    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }
    
    if proof.commitment.len() != 32 {
        return Ok(false);
    }
    
    let mut backend_proof = Vec::new();
    backend_proof.extend_from_slice(&proof.proof);
    backend_proof.extend_from_slice(b"COMMIT:");
    backend_proof.extend_from_slice(&proof.commitment);
    
    Ok(BulletproofsBackend::verify_set_membership(&backend_proof, set))
}
