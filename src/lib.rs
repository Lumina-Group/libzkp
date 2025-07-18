use pyo3::prelude::*;

// Legacy proof modules (for backward compatibility)
pub mod range_proof;
pub mod equality_proof;
pub mod threshold_proof;
pub mod improvement_proof;
pub mod consistency_proof;
pub mod utils;

// New advanced ZKP modules
pub mod zkp_backends;
pub mod circuits;
pub mod generic_zkp;

#[pymodule]
fn libzkp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Legacy API functions (for backward compatibility)
    m.add_function(wrap_pyfunction!(range_proof::prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(range_proof::verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(equality_proof::prove_equality, m)?)?;
    m.add_function(wrap_pyfunction!(equality_proof::verify_equality, m)?)?;
    m.add_function(wrap_pyfunction!(threshold_proof::prove_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(threshold_proof::verify_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(improvement_proof::prove_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(improvement_proof::verify_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(consistency_proof::prove_consistency, m)?)?;
    m.add_function(wrap_pyfunction!(consistency_proof::verify_consistency, m)?)?;
    
    // New generic ZKP API
    m.add_function(wrap_pyfunction!(generic_zkp::create_zkp_engine, m)?)?;
    m.add_class::<generic_zkp::ZKPEngine>()?;
    
    Ok(())
}