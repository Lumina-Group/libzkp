use crate::backend::{bulletproofs::BulletproofsBackend, ZkpBackend};
use pyo3::prelude::*;

#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if value < min || value > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "value out of range",
        ));
    }
    let data = value.to_le_bytes();
    let out = BulletproofsBackend::prove(&data);
    if out.len() < 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "proof generation failed",
        ));
    }
    let proof_len = out.len() - 32;
    let proof = out[..proof_len].to_vec();
    let commitment = out[proof_len..].to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_range(proof: Vec<u8>, commitment: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    if commitment.len() != 32 {
        return Ok(false);
    }
    let mut proof_full = proof.clone();
    proof_full.extend_from_slice(&commitment);
    Ok(BulletproofsBackend::verify(&proof_full, &[]))
}
