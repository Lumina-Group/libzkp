use pyo3::prelude::*;

#[pyfunction]
pub fn prove_consistency(data: Vec<u64>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if data.windows(2).any(|w| w[0] > w[1]) {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "data inconsistent",
        ));
    }
    let commitment = b"dummy_consistency_commitment".to_vec();
    let proof = b"dummy_consistency_proof".to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_consistency(_proof: Vec<u8>, _commitment: Vec<u8>) -> PyResult<bool> {
    // Always true for dummy example
    Ok(true)
}
