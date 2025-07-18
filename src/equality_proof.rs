use pyo3::prelude::*;

#[pyfunction]
pub fn prove_equality(val1: u64, val2: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if val1 != val2 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "values are not equal",
        ));
    }
    let commitment = val1.to_le_bytes().to_vec();
    let proof = b"dummy_equality_proof".to_vec();
    Ok((proof, commitment))
}

#[pyfunction]
pub fn verify_equality(
    proof: Vec<u8>,
    commitment: Vec<u8>,
    val1: u64,
    val2: u64,
) -> PyResult<bool> {
    if proof != b"dummy_equality_proof" {
        return Ok(false);
    }
    if commitment.len() != 8 {
        return Ok(false);
    }
    let val = u64::from_le_bytes(commitment.try_into().unwrap());
    Ok(val == val1 && val == val2)
}
