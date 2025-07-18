use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyfunction]
pub fn prove_consistency(data: Vec<u64>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if data.windows(2).any(|w| w[0] > w[1]) {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "data inconsistent",
        ));
    }
    let mut commitment = Vec::with_capacity(data.len() * 8);
    for v in &data {
        commitment.extend_from_slice(&v.to_le_bytes());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"consistency");
    hasher.update(&commitment);
    let proof = hasher.finalize().to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_consistency(proof: Vec<u8>, commitment: Vec<u8>) -> PyResult<bool> {
    if commitment.len() % 8 != 0 {
        return Ok(false);
    }
    let values: Vec<u64> = commitment
        .chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if values.windows(2).any(|w| w[0] > w[1]) {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"consistency");
    hasher.update(&commitment);
    Ok(proof == hasher.finalize().to_vec())
}
