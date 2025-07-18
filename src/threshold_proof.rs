use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyfunction]
pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
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
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_threshold(proof: Vec<u8>, commitment: Vec<u8>, threshold: u64) -> PyResult<bool> {
    if commitment.len() != 8 {
        return Ok(false);
    }
    let sum = u64::from_le_bytes(commitment.clone().try_into().unwrap());
    if sum < threshold {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"threshold");
    hasher.update(&commitment);
    Ok(proof == hasher.finalize().to_vec())
}
