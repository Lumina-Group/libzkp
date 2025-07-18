use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if value < min || value > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "value out of range",
        ));
    }
    let commitment = value.to_le_bytes().to_vec();
    let mut hasher = Sha256::new();
    hasher.update(b"range");
    hasher.update(&commitment);
    let proof = hasher.finalize().to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_range(proof: Vec<u8>, commitment: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    if commitment.len() != 8 {
        return Ok(false);
    }
    let val = u64::from_le_bytes(commitment.clone().try_into().unwrap());
    if val < min || val > max {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"range");
    hasher.update(&commitment);
    Ok(proof == hasher.finalize().to_vec())
}
