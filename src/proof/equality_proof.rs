use crate::backend::snark::SnarkBackend;
use crate::proof::Proof;
use crate::utils::commitment::commit_value;
use crate::utils::error_handling::ZkpError;
use crate::utils::proof_helpers::{parse_and_validate_proof, validate_standard_commitment};
use crate::utils::validation::validate_equality_params;
use pyo3::prelude::*;

const SCHEME_ID: u8 = 2;

#[pyfunction]
pub fn prove_equality(val1: u64, val2: u64) -> PyResult<Vec<u8>> {
    validate_equality_params(val1, val2).map_err(PyErr::from)?;

    let commitment = commit_value(val1);
    let commitment_arr: [u8; 32] = match commitment.clone().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return Err(PyErr::from(ZkpError::InvalidProofFormat(
                "invalid commitment size".to_string(),
            )))
        }
    };

    let snark_proof = SnarkBackend::prove_equality_zk(val1, val2, commitment_arr);

    if snark_proof.is_empty() {
        return Err(PyErr::from(ZkpError::ProofGenerationFailed(
            "SNARK proof generation failed".to_string(),
        )));
    }

    let proof = Proof::new(SCHEME_ID, snark_proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_equality(proof: Vec<u8>, val1: u64, val2: u64) -> PyResult<bool> {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    if val1 != val2 {
        return Ok(false);
    }

    let expected_commitment = commit_value(val1);
    if validate_standard_commitment(&expected_commitment).is_err() {
        return Ok(false);
    }

    if proof.commitment != expected_commitment {
        return Ok(false);
    }

    Ok(SnarkBackend::verify_equality_zk(
        &proof.proof,
        &expected_commitment,
    ))
}

#[pyfunction]
pub fn verify_equality_with_commitment(
    proof: Vec<u8>,
    expected_commitment: Vec<u8>,
) -> PyResult<bool> {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    if validate_standard_commitment(&expected_commitment).is_err() {
        return Ok(false);
    }
    if proof.commitment != expected_commitment {
        return Ok(false);
    }

    Ok(SnarkBackend::verify_equality_zk(
        &proof.proof,
        &expected_commitment,
    ))
}
