use crate::backend::{stark::StarkBackend, ZkpBackend};
use pyo3::prelude::*;

#[pyfunction]
pub fn prove_improvement(old: u64, new: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if new <= old {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "no improvement",
        ));
    }
    let diff = new - old;
    let steps = diff + 1;
    if steps < 8 || !steps.is_power_of_two() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "unsupported improvement size",
        ));
    }
    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&steps.to_le_bytes());
    let proof = StarkBackend::prove(&data);
    let commitment = new.to_le_bytes().to_vec();
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
    let diff = new_val - old;
    let steps = diff + 1;
    if steps < 8 || !steps.is_power_of_two() {
        return Ok(false);
    }
    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&steps.to_le_bytes());
    Ok(StarkBackend::verify(&proof, &data))
}
