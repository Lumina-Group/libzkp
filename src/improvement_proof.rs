use pyo3::prelude::*;
use sha2::{Digest, Sha256};

#[pyfunction]
pub fn prove_improvement(old: u64, new: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if new <= old {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "no improvement",
        ));
    }
    let commitment = new.to_le_bytes().to_vec();
    let mut hasher = Sha256::new();
    hasher.update(b"improvement");
    hasher.update(&commitment);
    let proof = hasher.finalize().to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_improvement(proof: Vec<u8>, commitment: Vec<u8>, old: u64) -> PyResult<bool> {
    if commitment.len() != 8 {
        return Ok(false);
    }
    let new_val = u64::from_le_bytes(commitment.clone().try_into().unwrap());
    if new_val <= old {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"improvement");
    hasher.update(&commitment);
    Ok(proof == hasher.finalize().to_vec())
}
