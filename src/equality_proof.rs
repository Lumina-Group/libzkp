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
    let proof = SnarkBackend::prove(&data);
    let commitment = val1.to_le_bytes().to_vec();
    let proof = Proof::new(SCHEME_ID, proof, commitment);
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
    if proof.commitment.len() != 8 {
        return Ok(false);
    }
    let val = u64::from_le_bytes(proof.commitment.clone().try_into().unwrap());
    if val != val1 || val != val2 {
        return Ok(false);
    }
    let mut data = Vec::new();
    data.extend_from_slice(&val1.to_le_bytes());
    data.extend_from_slice(&val2.to_le_bytes());
    Ok(SnarkBackend::verify(&proof.proof, &data))
}
