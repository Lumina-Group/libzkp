use crate::backend::{snark::SnarkBackend, ZkpBackend};
use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;

const SCHEME_ID: u8 = 2;

#[pyfunction]
pub fn prove_equality(val1: u64, val2: u64) -> PyResult<Vec<u8>> {
    if val1 != val2 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "values are not equal",
        ));
    }
    
    let mut data = Vec::new();
    data.extend_from_slice(&val1.to_le_bytes());
    data.extend_from_slice(&val2.to_le_bytes());
    let snark_proof = SnarkBackend::prove(&data);
    
    if snark_proof.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "SNARK proof generation failed"
        ));
    }
    
    let commitment = vec![0u8; 32]; 
    let proof = Proof::new(SCHEME_ID, snark_proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_equality(proof: Vec<u8>, val1: u64, val2: u64) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };
    
    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }
    
    if val1 != val2 {
        return Ok(false);
    }
    
    let mut data = Vec::new();
    data.extend_from_slice(&val1.to_le_bytes());
    data.extend_from_slice(&val2.to_le_bytes());
    
    Ok(SnarkBackend::verify(&proof.proof, &data))
}
