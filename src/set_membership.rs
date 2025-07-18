use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[pyfunction]
pub fn prove_membership(value: u64, set: Vec<u64>) -> PyResult<(Vec<u8>, Vec<u8>)> {
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
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_membership(proof: Vec<u8>, commitment: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
    if commitment.len() != 8 {
        return Ok(false);
    }
    let value = u64::from_le_bytes(commitment.clone().try_into().unwrap());
    let s: HashSet<u64> = set.into_iter().collect();
    if !s.contains(&value) {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"set_membership");
    hasher.update(&commitment);
    Ok(proof == hasher.finalize().to_vec())
}
