pub mod composite;
pub use composite::*;

pub mod batch;
pub use batch::*;

use pyo3::prelude::*;
use std::collections::HashMap;

use crate::proof::Proof;
use crate::utils::{
    performance::{get_global_cache, generate_cache_key, Timer},
    error_handling::ZkpError,
};

/// Clear the global proof cache
#[pyfunction]
pub fn clear_cache() -> PyResult<()> {
    get_global_cache().clear();
    Ok(())
}

/// Get cache statistics
#[pyfunction]
pub fn get_cache_stats() -> PyResult<HashMap<String, u64>> {
    let cache = get_global_cache();
    let mut stats = HashMap::new();
    stats.insert("size".to_string(), cache.size() as u64);
    Ok(stats)
}

/// Enable performance monitoring (placeholder)
#[pyfunction]
pub fn enable_performance_monitoring() -> PyResult<bool> {
    Ok(true)
}

/// Get performance metrics (placeholder values)
#[pyfunction]
pub fn get_performance_metrics() -> PyResult<HashMap<String, f64>> {
    let mut metrics = HashMap::new();
    metrics.insert("cache_hit_rate".to_string(), 0.85);
    metrics.insert("avg_proof_time_ms".to_string(), 125.5);
    Ok(metrics)
}

/// Range proof with caching support
#[pyfunction]
pub fn prove_range_cached(value: u64, min: u64, max: u64) -> PyResult<Vec<u8>> {
    let cache = get_global_cache();
    let params = format!("{}:{}:{}", value, min, max);
    let cache_key = generate_cache_key("range_proof", params.as_bytes());

    if let Some(cached) = cache.get(&cache_key) {
        return Ok(cached);
    }

    let proof = crate::range_proof::prove_range(value, min, max)?;
    cache.put(cache_key, proof.clone());
    Ok(proof)
}

/// Equality proof with optional context extension
#[pyfunction]
pub fn prove_equality_advanced(val1: u64, val2: u64, context: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values must be equal".to_string()).into());
    }

    let mut proof = crate::equality_proof::prove_equality(val1, val2)?;
    if let Some(ctx) = context {
        proof.extend_from_slice(&ctx);
    }
    Ok(proof)
}

/// Verify multiple proofs in parallel using utility helper
#[pyfunction]
pub fn verify_proofs_parallel(proofs: Vec<(Vec<u8>, String)>) -> PyResult<Vec<bool>> {
    use crate::utils::performance::parallel::verify_proofs_parallel;
    Ok(verify_proofs_parallel(&proofs))
}

/// Benchmark proof generation performance for a given proof type
#[pyfunction]
pub fn benchmark_proof_generation(proof_type: String, iterations: u32) -> PyResult<HashMap<String, f64>> {
    let mut timer = Timer::new();
    let mut total_time_ms = 0.0;

    for _ in 0..iterations {
        timer.reset();
        let _ = match proof_type.as_str() {
            "range" => crate::range_proof::prove_range(50, 0, 100),
            "equality" => crate::equality_proof::prove_equality(42, 42),
            _ => return Err(ZkpError::InvalidInput("unsupported proof type".to_string()).into()),
        };
        total_time_ms += timer.elapsed().as_secs_f64() * 1000.0;
    }

    let mut results = HashMap::new();
    results.insert("total_time_ms".to_string(), total_time_ms);
    results.insert("average_time_ms".to_string(), total_time_ms / iterations as f64);
    results.insert("proofs_per_second".to_string(), iterations as f64 / (total_time_ms / 1000.0));
    Ok(results)
}

/// Optimized threshold proof generation with pre-checks
#[pyfunction]
pub fn prove_threshold_optimized(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    if values.is_empty() {
        return Err(ZkpError::InvalidInput("values cannot be empty".to_string()).into());
    }

    let sum: u64 = values.iter().try_fold(0u64, |acc, &v| acc.checked_add(v).ok_or(()))
        .map_err(|_| ZkpError::InvalidInput("integer overflow".to_string()))?;

    if sum < threshold {
        return Err(ZkpError::InvalidInput("sum does not meet threshold".to_string()).into());
    }

    crate::threshold_proof::prove_threshold(values, threshold)
}

/// Validate a chain of proofs for structural integrity
#[pyfunction]
pub fn validate_proof_chain(proof_chain: Vec<Vec<u8>>) -> PyResult<bool> {
    if proof_chain.is_empty() {
        return Ok(true);
    }

    for bytes in &proof_chain {
        if Proof::from_bytes(bytes).is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Extract high-level information from a proof
#[pyfunction]
pub fn get_proof_info(proof_bytes: Vec<u8>) -> PyResult<HashMap<String, u64>> {
    let proof = Proof::from_bytes(&proof_bytes)
        .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof".to_string()))?;

    let mut info = HashMap::new();
    info.insert("version".to_string(), proof.version as u64);
    info.insert("scheme".to_string(), proof.scheme as u64);
    info.insert("proof_size".to_string(), proof.proof.len() as u64);
    info.insert("commitment_size".to_string(), proof.commitment.len() as u64);
    Ok(info)
}