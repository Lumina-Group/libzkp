//! Python bindings (PyO3). Built when the `python` feature is enabled.

use pyo3::prelude::*;
use pyo3::IntoPyObject;
use std::collections::HashMap;

macro_rules! py_zkp {
    ($name:ident, $ret:ty, $($arg:ident : $t:ty),* => $e:expr) => {
        #[pyfunction]
        fn $name($($arg: $t),*) -> PyResult<$ret> {
            $e.map_err(Into::into)
        }
    };
}

macro_rules! py_ok {
    ($name:ident, $ret:ty, $($arg:ident : $t:ty),* => $e:expr) => {
        #[pyfunction]
        fn $name($($arg: $t),*) -> PyResult<$ret> {
            Ok($e)
        }
    };
}

py_zkp!(prove_range, Vec<u8>, value: u64, min: u64, max: u64 => crate::proof::range_proof::prove_range(value, min, max));
py_ok!(verify_range, bool, proof: Vec<u8>, min: u64, max: u64 => crate::proof::range_proof::verify_range(proof, min, max));

py_zkp!(prove_equality, Vec<u8>, val1: u64, val2: u64 => crate::proof::equality_proof::prove_equality(val1, val2));
py_ok!(verify_equality, bool, proof: Vec<u8>, val1: u64, val2: u64 => crate::proof::equality_proof::verify_equality(proof, val1, val2));
py_ok!(verify_equality_with_commitment, bool, proof: Vec<u8>, expected_commitment: Vec<u8> => crate::proof::equality_proof::verify_equality_with_commitment(proof, expected_commitment));
// MiMC-5 (BN254 Fr) commitment for Groth16 proofs; exposed for `verify_equality_with_commitment` callers.
py_ok!(snark_commit_value, Vec<u8>, value: u64 => crate::utils::commitment::commit_value_snark(value));

py_zkp!(prove_threshold, Vec<u8>, values: Vec<u64>, threshold: u64 => crate::proof::threshold_proof::prove_threshold(values, threshold));
py_ok!(verify_threshold, bool, proof: Vec<u8>, threshold: u64 => crate::proof::threshold_proof::verify_threshold(proof, threshold));

py_zkp!(prove_membership, Vec<u8>, value: u64, set: Vec<u64> => crate::proof::set_membership::prove_membership(value, set));
py_ok!(verify_membership, bool, proof: Vec<u8>, set: Vec<u64> => crate::proof::set_membership::verify_membership(proof, set));

py_zkp!(prove_improvement, Vec<u8>, old: u64, new: u64 => crate::proof::improvement_proof::prove_improvement(old, new));
py_ok!(verify_improvement, bool, proof: Vec<u8>, old: u64 => crate::proof::improvement_proof::verify_improvement(proof, old));

py_zkp!(prove_consistency, Vec<u8>, data: Vec<u64> => crate::proof::consistency_proof::prove_consistency(data));
py_ok!(verify_consistency, bool, proof: Vec<u8> => crate::proof::consistency_proof::verify_consistency(proof));

py_zkp!(create_composite_proof, Vec<u8>, proof_list: Vec<Vec<u8>> => crate::advanced::create_composite_proof(proof_list));
py_zkp!(verify_composite_proof, bool, composite_bytes: Vec<u8> => crate::advanced::verify_composite_proof(composite_bytes));
py_zkp!(verify_composite_proof_integrity_only, bool, composite_bytes: Vec<u8> => crate::advanced::verify_composite_proof_integrity_only(composite_bytes));
py_zkp!(create_proof_with_metadata, Vec<u8>, proof_data: Vec<u8>, metadata: HashMap<String, Vec<u8>> => crate::advanced::create_proof_with_metadata(proof_data, metadata));
py_zkp!(extract_proof_metadata, HashMap<String, Vec<u8>>, composite_bytes: Vec<u8> => crate::advanced::extract_proof_metadata(composite_bytes));

py_zkp!(clear_cache, (),  => crate::advanced::clear_cache());
py_zkp!(get_cache_stats, HashMap<String, u64>,  => crate::advanced::get_cache_stats());
py_zkp!(get_performance_metrics, HashMap<String, f64>,  => crate::advanced::get_performance_metrics());
py_zkp!(benchmark_proof_generation_numeric, HashMap<String, f64>, proof_type: String, iterations: u32 => crate::advanced::benchmark_proof_generation_numeric(proof_type, iterations));
py_zkp!(prove_range_cached, Vec<u8>, value: u64, min: u64, max: u64 => crate::advanced::prove_range_cached(value, min, max));
py_zkp!(prove_equality_advanced, Vec<u8>, val1: u64, val2: u64 => crate::advanced::prove_equality_advanced(val1, val2));
py_zkp!(verify_proofs_parallel, Vec<bool>, proofs: Vec<(Vec<u8>, String)> => crate::advanced::verify_proofs_parallel(proofs));
py_zkp!(prove_threshold_optimized, Vec<u8>, values: Vec<u64>, threshold: u64 => crate::advanced::prove_threshold_optimized(values, threshold));
py_zkp!(validate_proof_chain, bool, proof_chain: Vec<Vec<u8>> => crate::advanced::validate_proof_chain(proof_chain));
py_zkp!(get_proof_info, HashMap<String, u64>, proof_bytes: Vec<u8> => crate::advanced::get_proof_info(proof_bytes));
py_zkp!(set_snark_key_dir, bool, path: String => crate::advanced::set_snark_key_dir(path));
py_zkp!(is_snark_setup_initialized, bool,  => crate::advanced::is_snark_setup_initialized());
py_zkp!(create_proof_batch, u64,  => crate::advanced::create_proof_batch());
py_zkp!(batch_add_range_proof, (), batch_id: u64, value: u64, min: u64, max: u64 => crate::advanced::batch_add_range_proof(batch_id, value, min, max));
py_zkp!(batch_add_equality_proof, (), batch_id: u64, val1: u64, val2: u64 => crate::advanced::batch_add_equality_proof(batch_id, val1, val2));
py_zkp!(batch_add_threshold_proof, (), batch_id: u64, values: Vec<u64>, threshold: u64 => crate::advanced::batch_add_threshold_proof(batch_id, values, threshold));
py_zkp!(batch_add_membership_proof, (), batch_id: u64, value: u64, set: Vec<u64> => crate::advanced::batch_add_membership_proof(batch_id, value, set));
py_zkp!(batch_add_improvement_proof, (), batch_id: u64, old: u64, new: u64 => crate::advanced::batch_add_improvement_proof(batch_id, old, new));
py_zkp!(batch_add_consistency_proof, (), batch_id: u64, data: Vec<u64> => crate::advanced::batch_add_consistency_proof(batch_id, data));
py_zkp!(process_batch, Vec<Vec<u8>>, batch_id: u64 => crate::advanced::process_batch(batch_id));
py_zkp!(get_batch_status, HashMap<String, usize>, batch_id: u64 => crate::advanced::get_batch_status(batch_id));
py_zkp!(clear_batch, (), batch_id: u64 => crate::advanced::clear_batch(batch_id));

#[cfg(feature = "batch-store")]
#[pyfunction]
fn set_batch_store_dir(path: String) -> PyResult<()> {
    crate::advanced::batch_store::set_batch_store_dir(path).map_err(Into::into)
}

#[cfg(feature = "batch-store")]
#[pyfunction]
fn get_batch_store_dir() -> PyResult<Option<String>> {
    Ok(crate::advanced::batch_store::get_batch_store_dir()
        .map(|p| p.to_string_lossy().into_owned()))
}

#[cfg(feature = "batch-store")]
py_zkp!(list_batch_ids_in_store, Vec<u64>,  => crate::advanced::batch_store::list_batch_ids_in_store());
#[cfg(feature = "batch-store")]
py_zkp!(open_batch_from_store, (), batch_id: u64 => crate::advanced::open_batch_from_store(batch_id));
#[cfg(feature = "batch-store")]
py_zkp!(refresh_batch_from_store, (), batch_id: u64 => crate::advanced::refresh_batch_from_store(batch_id));
#[cfg(feature = "batch-store")]
py_zkp!(export_batch_to_file, (), batch_id: u64, dest: String => crate::advanced::export_batch_to_file(batch_id, dest));
#[cfg(feature = "batch-store")]
py_zkp!(import_batch_from_file, u64, src: String => crate::advanced::import_batch_from_file(src));

#[pyfunction]
fn benchmark_proof_generation(
    py: Python<'_>,
    proof_type: String,
    iterations: u32,
) -> PyResult<PyObject> {
    let m = crate::advanced::benchmark_proof_generation(proof_type, iterations)?;
    Ok(m.into_pyobject(py)?.into_any().unbind())
}

/// Registers all Python-callable functions on the module `m`.
pub fn register_module(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prove_range, m)?)?;
    m.add_function(wrap_pyfunction!(verify_range, m)?)?;
    m.add_function(wrap_pyfunction!(prove_equality, m)?)?;
    m.add_function(wrap_pyfunction!(verify_equality, m)?)?;
    m.add_function(wrap_pyfunction!(verify_equality_with_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(snark_commit_value, m)?)?;
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
    #[cfg(feature = "batch-store")]
    {
        m.add_function(wrap_pyfunction!(set_batch_store_dir, m)?)?;
        m.add_function(wrap_pyfunction!(get_batch_store_dir, m)?)?;
        m.add_function(wrap_pyfunction!(list_batch_ids_in_store, m)?)?;
        m.add_function(wrap_pyfunction!(open_batch_from_store, m)?)?;
        m.add_function(wrap_pyfunction!(refresh_batch_from_store, m)?)?;
        m.add_function(wrap_pyfunction!(export_batch_to_file, m)?)?;
        m.add_function(wrap_pyfunction!(import_batch_from_file, m)?)?;
    }
    Ok(())
}
