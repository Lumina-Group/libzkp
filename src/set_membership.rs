use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const SCHEME_ID: u8 = 4;

#[pyfunction]
pub fn prove_membership(value: u64, set: Vec<u64>) -> PyResult<Vec<u8>> {
    let s: HashSet<u64> = set.into_iter().collect();
    if !s.contains(&value) {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "value not in set",
        ));
    }
    let commitment = value.to_le_bytes().to_vec();
    let mut hasher = Sha256::new();
    hasher.update(b"set_membership");
    hasher.update(&commitment);
    let proof = hasher.finalize().to_vec();
    let proof = Proof::new(SCHEME_ID, proof, commitment);
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
    if proof.commitment.len() != 8 {
        return Ok(false);
    }
    let value = u64::from_le_bytes(proof.commitment.clone().try_into().unwrap());
    let s: HashSet<u64> = set.into_iter().collect();
    if !s.contains(&value) {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"set_membership");
    hasher.update(&proof.commitment);
    Ok(proof.proof == hasher.finalize().to_vec())
}
