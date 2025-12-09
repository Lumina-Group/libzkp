use crate::backend::{stark::StarkBackend, ZkpBackend};
use crate::proof::Proof;
use crate::utils::commitment::{commit_improvement, validate_improvement_commitment};
use crate::utils::proof_helpers::parse_and_validate_proof;
use crate::utils::validation::validate_improvement_params;
use pyo3::prelude::*;

const SCHEME_ID: u8 = 5;

#[pyfunction]
pub fn prove_improvement(old: u64, new: u64) -> PyResult<Vec<u8>> {
    validate_improvement_params(old, new).map_err(PyErr::from)?;

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    let stark_proof = StarkBackend::prove(&data);

    if stark_proof.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "STARK proof generation failed",
        ));
    }

    let commitment = commit_improvement(old, new).map_err(PyErr::from)?;

    let proof = Proof::new(SCHEME_ID, stark_proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_improvement(proof: Vec<u8>, old: u64) -> PyResult<bool> {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    let new = match validate_improvement_commitment(&proof.commitment, old) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    Ok(StarkBackend::verify(&proof.proof, &data))
}
