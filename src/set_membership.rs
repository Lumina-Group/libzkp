use pyo3::prelude::*;
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
    let proof = b"dummy_set_proof".to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_membership(proof: Vec<u8>, commitment: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
    if proof != b"dummy_set_proof" {
        return Ok(false);
    }
    if commitment.len() != 8 {
        return Ok(false);
    }
    let value = u64::from_le_bytes(commitment.clone().try_into().unwrap());
    let s: HashSet<u64> = set.into_iter().collect();
    Ok(s.contains(&value))
}
