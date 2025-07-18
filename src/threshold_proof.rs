use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

const SCHEME_ID: u8 = 3;

#[pyfunction]
pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    let sum: u64 = values.iter().sum();
    if sum < threshold {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "threshold not met",
        ));
    }
    let commitment = sum.to_le_bytes().to_vec();
    let mut hasher = Sha256::new();
    hasher.update(b"threshold");
    hasher.update(&commitment);
    let proof = hasher.finalize().to_vec();
    let proof = Proof::new(SCHEME_ID, proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_threshold(proof: Vec<u8>, threshold: u64) -> PyResult<bool> {
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
    let sum = u64::from_le_bytes(proof.commitment.clone().try_into().unwrap());
    if sum < threshold {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"threshold");
    hasher.update(&proof.commitment);
    Ok(proof.proof == hasher.finalize().to_vec())
}
