//! Python bindings (PyO3). Built when the `python` feature is enabled.

use pyo3::prelude::*;
use std::collections::HashMap;

#[pyfunction]
fn prove_range(value: u64, min: u64, max: u64) -> PyResult<Vec<u8>> {
    crate::proof::range_proof::prove_range(value, min, max).map_err(Into::into)
}

#[pyfunction]
fn verify_range(proof: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    Ok(crate::proof::range_proof::verify_range(proof, min, max))
}

#[pyfunction]
fn prove_equality(val1: u64, val2: u64) -> PyResult<Vec<u8>> {
    crate::proof::equality_proof::prove_equality(val1, val2).map_err(Into::into)
}

#[pyfunction]
fn verify_equality(proof: Vec<u8>, val1: u64, val2: u64) -> PyResult<bool> {
    Ok(crate::proof::equality_proof::verify_equality(proof, val1, val2))
}

#[pyfunction]
fn verify_equality_with_commitment(proof: Vec<u8>, expected_commitment: Vec<u8>) -> PyResult<bool> {
    Ok(crate::proof::equality_proof::verify_equality_with_commitment(
        proof,
        expected_commitment,
    ))
}

#[pyfunction]
fn prove_threshold(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    crate::proof::threshold_proof::prove_threshold(values, threshold).map_err(Into::into)
}

#[pyfunction]
fn verify_threshold(proof: Vec<u8>, threshold: u64) -> PyResult<bool> {
    Ok(crate::proof::threshold_proof::verify_threshold(proof, threshold))
}

#[pyfunction]
fn prove_membership(value: u64, set: Vec<u64>) -> PyResult<Vec<u8>> {
    crate::proof::set_membership::prove_membership(value, set).map_err(Into::into)
}

#[pyfunction]
fn verify_membership(proof: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
    Ok(crate::proof::set_membership::verify_membership(proof, set))
}

#[pyfunction]
fn prove_improvement(old: u64, new: u64) -> PyResult<Vec<u8>> {
    crate::proof::improvement_proof::prove_improvement(old, new).map_err(Into::into)
}

#[pyfunction]
fn verify_improvement(proof: Vec<u8>, old: u64) -> PyResult<bool> {
    Ok(crate::proof::improvement_proof::verify_improvement(proof, old))
}

#[pyfunction]
fn prove_consistency(data: Vec<u64>) -> PyResult<Vec<u8>> {
    crate::proof::consistency_proof::prove_consistency(data).map_err(Into::into)
}

#[pyfunction]
fn verify_consistency(proof: Vec<u8>) -> PyResult<bool> {
    Ok(crate::proof::consistency_proof::verify_consistency(proof))
}

#[pyfunction]
fn create_composite_proof(proof_list: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    crate::advanced::create_composite_proof(proof_list).map_err(Into::into)
}

#[pyfunction]
fn verify_composite_proof(composite_bytes: Vec<u8>) -> PyResult<bool> {
    crate::advanced::verify_composite_proof(composite_bytes).map_err(Into::into)
}

#[pyfunction]
fn verify_composite_proof_integrity_only(composite_bytes: Vec<u8>) -> PyResult<bool> {
    crate::advanced::verify_composite_proof_integrity_only(composite_bytes).map_err(Into::into)
}

#[pyfunction]
fn create_proof_with_metadata(
    proof_data: Vec<u8>,
    metadata: HashMap<String, Vec<u8>>,
) -> PyResult<Vec<u8>> {
    crate::advanced::create_proof_with_metadata(proof_data, metadata).map_err(Into::into)
}

#[pyfunction]
fn extract_proof_metadata(composite_bytes: Vec<u8>) -> PyResult<HashMap<String, Vec<u8>>> {
    crate::advanced::extract_proof_metadata(composite_bytes).map_err(Into::into)
}

#[pyfunction]
fn clear_cache() -> PyResult<()> {
    crate::advanced::clear_cache().map_err(Into::into)
}

#[pyfunction]
fn get_cache_stats() -> PyResult<HashMap<String, u64>> {
    crate::advanced::get_cache_stats().map_err(Into::into)
}

#[pyfunction]
fn enable_performance_monitoring() -> PyResult<bool> {
    crate::advanced::enable_performance_monitoring().map_err(Into::into)
}

#[pyfunction]
fn get_performance_metrics() -> PyResult<HashMap<String, f64>> {
    crate::advanced::get_performance_metrics().map_err(Into::into)
}

#[pyfunction]
fn benchmark_proof_generation_numeric(
    proof_type: String,
    iterations: u32,
) -> PyResult<HashMap<String, f64>> {
    crate::advanced::benchmark_proof_generation_numeric(proof_type, iterations).map_err(Into::into)
}

#[pyfunction]
fn prove_range_cached(value: u64, min: u64, max: u64) -> PyResult<Vec<u8>> {
    crate::advanced::prove_range_cached(value, min, max).map_err(Into::into)
}

#[pyfunction]
fn prove_equality_advanced(
    val1: u64,
    val2: u64,
    context: Option<Vec<u8>>,
) -> PyResult<Vec<u8>> {
    crate::advanced::prove_equality_advanced(val1, val2, context).map_err(Into::into)
}

#[pyfunction]
fn verify_proofs_parallel(proofs: Vec<(Vec<u8>, String)>) -> PyResult<Vec<bool>> {
    crate::advanced::verify_proofs_parallel(proofs).map_err(Into::into)
}

#[pyfunction]
fn benchmark_proof_generation(
    py: Python<'_>,
    proof_type: String,
    iterations: u32,
) -> PyResult<PyObject> {
    let m = crate::advanced::benchmark_proof_generation(proof_type, iterations)?;
    Ok(m.into_py(py))
}

#[pyfunction]
fn prove_threshold_optimized(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    crate::advanced::prove_threshold_optimized(values, threshold).map_err(Into::into)
}

#[pyfunction]
fn validate_proof_chain(proof_chain: Vec<Vec<u8>>) -> PyResult<bool> {
    crate::advanced::validate_proof_chain(proof_chain).map_err(Into::into)
}

#[pyfunction]
fn get_proof_info(proof_bytes: Vec<u8>) -> PyResult<HashMap<String, u64>> {
    crate::advanced::get_proof_info(proof_bytes).map_err(Into::into)
}

#[pyfunction]
fn set_snark_key_dir(path: String) -> PyResult<bool> {
    crate::advanced::set_snark_key_dir(path).map_err(Into::into)
}

#[pyfunction]
fn is_snark_setup_initialized() -> PyResult<bool> {
    crate::advanced::is_snark_setup_initialized().map_err(Into::into)
}

#[pyfunction]
fn create_proof_batch() -> PyResult<usize> {
    crate::advanced::create_proof_batch().map_err(Into::into)
}

#[pyfunction]
fn batch_add_range_proof(batch_id: usize, value: u64, min: u64, max: u64) -> PyResult<()> {
    crate::advanced::batch_add_range_proof(batch_id, value, min, max).map_err(Into::into)
}

#[pyfunction]
fn batch_add_equality_proof(batch_id: usize, val1: u64, val2: u64) -> PyResult<()> {
    crate::advanced::batch_add_equality_proof(batch_id, val1, val2).map_err(Into::into)
}

#[pyfunction]
fn batch_add_threshold_proof(
    batch_id: usize,
    values: Vec<u64>,
    threshold: u64,
) -> PyResult<()> {
    crate::advanced::batch_add_threshold_proof(batch_id, values, threshold).map_err(Into::into)
}

#[pyfunction]
fn batch_add_membership_proof(batch_id: usize, value: u64, set: Vec<u64>) -> PyResult<()> {
    crate::advanced::batch_add_membership_proof(batch_id, value, set).map_err(Into::into)
}

#[pyfunction]
fn batch_add_improvement_proof(batch_id: usize, old: u64, new: u64) -> PyResult<()> {
    crate::advanced::batch_add_improvement_proof(batch_id, old, new).map_err(Into::into)
}

#[pyfunction]
fn batch_add_consistency_proof(batch_id: usize, data: Vec<u64>) -> PyResult<()> {
    crate::advanced::batch_add_consistency_proof(batch_id, data).map_err(Into::into)
}

#[pyfunction]
fn process_batch(batch_id: usize) -> PyResult<Vec<Vec<u8>>> {
    crate::advanced::process_batch(batch_id).map_err(Into::into)
}

#[pyfunction]
fn get_batch_status(batch_id: usize) -> PyResult<HashMap<String, usize>> {
    crate::advanced::get_batch_status(batch_id).map_err(Into::into)
}

#[pyfunction]
fn clear_batch(batch_id: usize) -> PyResult<()> {
    crate::advanced::clear_batch(batch_id).map_err(Into::into)
}

/// Registers all Python-callable functions on the module `m`.
pub fn register_module(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(prove_equality, m)?)?;
    m.add_function(wrap_pyfunction!(verify_equality, m)?)?;
    m.add_function(wrap_pyfunction!(verify_equality_with_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(prove_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(verify_threshold, m)?)?;
    m.add_function(wrap_pyfunction!(prove_membership, m)?)?;
    m.add_function(wrap_pyfunction!(verify_membership, m)?)?;
    m.add_function(wrap_pyfunction!(prove_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(verify_improvement, m)?)?;
    m.add_function(wrap_pyfunction!(prove_consistency, m)?)?;
    m.add_function(wrap_pyfunction!(verify_consistency, m)?)?;
    m.add_function(wrap_pyfunction!(create_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_composite_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_composite_proof_integrity_only, m)?)?;
    m.add_function(wrap_pyfunction!(create_proof_with_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(extract_proof_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(clear_cache, m)?)?;
    m.add_function(wrap_pyfunction!(get_cache_stats, m)?)?;
    m.add_function(wrap_pyfunction!(enable_performance_monitoring, m)?)?;
    m.add_function(wrap_pyfunction!(get_performance_metrics, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark_proof_generation_numeric, m)?)?;
    m.add_function(wrap_pyfunction!(prove_range_cached, m)?)?;
    m.add_function(wrap_pyfunction!(prove_equality_advanced, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proofs_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark_proof_generation, m)?)?;
    m.add_function(wrap_pyfunction!(prove_threshold_optimized, m)?)?;
    m.add_function(wrap_pyfunction!(validate_proof_chain, m)?)?;
    m.add_function(wrap_pyfunction!(get_proof_info, m)?)?;
    m.add_function(wrap_pyfunction!(set_snark_key_dir, m)?)?;
    m.add_function(wrap_pyfunction!(is_snark_setup_initialized, m)?)?;
    m.add_function(wrap_pyfunction!(create_proof_batch, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_range_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_equality_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_threshold_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_membership_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_improvement_proof, m)?)?;
    m.add_function(wrap_pyfunction!(batch_add_consistency_proof, m)?)?;
    m.add_function(wrap_pyfunction!(process_batch, m)?)?;
    m.add_function(wrap_pyfunction!(get_batch_status, m)?)?;
    m.add_function(wrap_pyfunction!(clear_batch, m)?)?;
    Ok(())
}
