use crate::backend::bulletproofs::BulletproofsBackend;
use crate::utils::proof_helpers::{
    create_proof, extract_bulletproofs_components, parse_and_validate_proof,
    reconstruct_bulletproofs_proof, validate_standard_commitment,
};
use pyo3::prelude::*;

const SCHEME_ID: u8 = 3;

#[pyfunction]
pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    let backend_proof = BulletproofsBackend::prove_threshold(values, threshold)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;

    let (proof_bytes, commitment) =
        extract_bulletproofs_components(&backend_proof).map_err(PyErr::from)?;

    create_proof(SCHEME_ID, proof_bytes, commitment).map_err(PyErr::from)
}

#[pyfunction]
pub fn verify_threshold(proof: Vec<u8>, threshold: u64) -> PyResult<bool> {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    if validate_standard_commitment(&proof.commitment).is_err() {
        return Ok(false);
    }

    let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
    Ok(BulletproofsBackend::verify_threshold(
        &backend_proof,
        threshold,
    ))
}
