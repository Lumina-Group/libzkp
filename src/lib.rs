use pyo3::prelude::*;

pub mod consistency_proof;
pub mod equality_proof;
pub mod improvement_proof;
pub mod range_proof;
pub mod set_membership;
pub mod threshold_proof;

pub mod backend;
pub mod proof;
pub mod utils;

#[pymodule]
fn libzkp(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(range_proof::prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(range_proof::verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(equality_proof::prove_equality, m)?)?;
    m.add_function(wrap_pyfunction!(equality_proof::verify_equality, m)?)?;
    m.add_function(wrap_pyfunction!(threshold_proof::prove_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(threshold_proof::verify_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(set_membership::prove_membership, m)?)?;
    m.add_function(wrap_pyfunction!(set_membership::verify_membership, m)?)?;
    m.add_function(wrap_pyfunction!(improvement_proof::prove_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(improvement_proof::verify_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(consistency_proof::prove_consistency, m)?)?;
    m.add_function(wrap_pyfunction!(consistency_proof::verify_consistency, m)?)?;
    Ok(())
}
