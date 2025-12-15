use pyo3::prelude::*;
pub mod advanced;
pub mod backend;
pub mod proof;
pub mod tvc;
pub mod utils;

#[pymodule]
fn libzkp(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(proof::range_proof::prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(proof::range_proof::verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(proof::equality_proof::prove_equality, m)?)?;
    m.add_function(wrap_pyfunction!(proof::equality_proof::verify_equality, m)?)?;
    m.add_function(wrap_pyfunction!(
        proof::equality_proof::verify_equality_with_commitment,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::threshold_proof::prove_threshold,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::threshold_proof::verify_threshold,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::set_membership::prove_membership,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::set_membership::verify_membership,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::improvement_proof::prove_improvement,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::improvement_proof::verify_improvement,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::consistency_proof::prove_consistency,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        proof::consistency_proof::verify_consistency,
        m
    )?)?;

    // Advanced features
    m.add_function(wrap_pyfunction!(advanced::create_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::verify_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::create_proof_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_equality_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_threshold_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_membership_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_improvement_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::batch_add_consistency_proof, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::process_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_batch_status, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::clear_batch, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::clear_cache, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::get_cache_stats, m)?)?;
    m.add_function(wrap_pyfunction!(
        advanced::enable_performance_monitoring,
        m
    )?)?;
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
    m.add_function(wrap_pyfunction!(advanced::set_snark_key_dir, m)?)?;
    m.add_function(wrap_pyfunction!(advanced::is_snark_setup_initialized, m)?)?;

    // TVC bindings
    m.add_function(wrap_pyfunction!(tvc::python_bindings::tvc_simulate_transmission, m)?)?;
    m.add_function(wrap_pyfunction!(tvc::python_bindings::tvc_prove_reception, m)?)?;
    m.add_function(wrap_pyfunction!(tvc::python_bindings::tvc_verify_reception, m)?)?;

    Ok(())
}
