use crate::backend::bulletproofs::BulletproofsBackend;
use crate::utils::{
    error_handling::ZkpError,
    proof_helpers::{create_proof, extract_bulletproofs_components},
    validation::validate_range_params,
};
use pyo3::prelude::*;

const SCHEME_ID: u8 = 1;

#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<Vec<u8>> {
    // Use utility for validation
    validate_range_params(value, min, max).map_err(|e| PyErr::from(e))?;

    let backend_proof = BulletproofsBackend::prove_range_with_bounds(value, min, max)
        .map_err(|e| PyErr::from(ZkpError::BackendError(e)))?;

    // Use utility for extracting components
    let (proof_bytes, commitment) =
        extract_bulletproofs_components(&backend_proof).map_err(|e| PyErr::from(e))?;

    // Use utility for creating proof
    create_proof(SCHEME_ID, proof_bytes, commitment).map_err(|e| PyErr::from(e))
}

#[pyfunction]
pub fn verify_range(proof: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    use crate::utils::proof_helpers::{
        parse_and_validate_proof, reconstruct_bulletproofs_proof, validate_standard_commitment,
    };

    // Validate range parameters
    if min > max {
        return Ok(false);
    }

    // Parse and validate proof structure
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    // Validate commitment size
    if let Err(_) = validate_standard_commitment(&proof.commitment) {
        return Ok(false);
    }

    // Reconstruct backend proof format
    let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);

    Ok(BulletproofsBackend::verify_range_with_bounds(
        &backend_proof,
        min,
        max,
    ))
}
