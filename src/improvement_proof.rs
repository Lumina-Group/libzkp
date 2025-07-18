use pyo3::prelude::*;

#[pyfunction]
pub fn prove_improvement(old: u64, new: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if new <= old {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "no improvement",
        ));
    }
    let commitment = new.to_le_bytes().to_vec();
    let proof = b"dummy_improvement_proof".to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_improvement(proof: Vec<u8>, commitment: Vec<u8>, old: u64) -> PyResult<bool> {
    if proof != b"dummy_improvement_proof" {
        return Ok(false);
    }
    if commitment.len() != 8 {
        return Ok(false);
    }
    let new_val = u64::from_le_bytes(commitment.try_into().unwrap());
    Ok(new_val > old)
}
