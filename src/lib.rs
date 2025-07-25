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
pub mod advanced;

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
    
    // Advanced features
    m.add_function(wrap_pyfunction!(advanced::create_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::verify_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::create_proof_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_equality_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_threshold_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::process_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_batch_status, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::clear_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::clear_cache, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_cache_stats, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::enable_performance_monitoring, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_performance_metrics, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::prove_range_cached, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::prove_equality_advanced, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::verify_proofs_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::benchmark_proof_generation, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::prove_threshold_optimized, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::create_proof_with_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::extract_proof_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::validate_proof_chain, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_proof_info, m)?)?;
    
    Ok(())
}
