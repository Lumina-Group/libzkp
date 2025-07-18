use pyo3::prelude::*;

#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if value < min || value > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "value out of range",
        ));
    }
    let commitment = value.to_le_bytes().to_vec();
    let proof = b"dummy_range_proof".to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_range(proof: Vec<u8>, commitment: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    if proof != b"dummy_range_proof" {
        return Ok(false);
    }
    if commitment.len() != 8 {
        return Ok(false);
    }
    let val = u64::from_le_bytes(commitment.try_into().unwrap());
    Ok(val >= min && val <= max)
}
