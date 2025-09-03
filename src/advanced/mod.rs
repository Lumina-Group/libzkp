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

/// Enable performance monitoring globally
#[pyfunction]
pub fn enable_performance_monitoring() -> PyResult<bool> {
    // Initialize the global metrics collector by calling it once
    crate::utils::performance::get_global_metrics();
    
    // Set up cache hit/miss recording for future operations
    // This would be used in actual proof operations to record metrics
    
    Ok(true)
}

/// Get performance metrics from the global metrics collector
#[pyfunction] 
pub fn get_performance_metrics() -> PyResult<HashMap<String, f64>> {
    use crate::utils::performance::{get_global_cache, get_global_metrics};
    
    let cache = get_global_cache();
    let metrics_arc = get_global_metrics();
    
    let mut result = HashMap::new();
    
    if let Ok(metrics) = metrics_arc.lock() {
        // Cache metrics
        result.insert("cache_hit_rate".to_string(), metrics.get_cache_hit_rate());
        result.insert("cache_size".to_string(), cache.size() as f64);
        result.insert("cache_hits".to_string(), metrics.cache_hits as f64);
        result.insert("cache_misses".to_string(), metrics.cache_misses as f64);
        
        // Average proof times by operation
        if let Some(avg_time) = metrics.get_average_time("range_proof") {
            result.insert("avg_range_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        if let Some(avg_time) = metrics.get_average_time("equality_proof") {
            result.insert("avg_equality_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        if let Some(avg_time) = metrics.get_average_time("threshold_proof") {
            result.insert("avg_threshold_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        if let Some(avg_time) = metrics.get_average_time("membership_proof") {
            result.insert("avg_membership_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        if let Some(avg_time) = metrics.get_average_time("improvement_proof") {
            result.insert("avg_improvement_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        if let Some(avg_time) = metrics.get_average_time("consistency_proof") {
            result.insert("avg_consistency_proof_time_ms".to_string(), avg_time.as_millis() as f64);
        }
        
        // Operation counts
        for (operation, count) in &metrics.operation_counts {
            result.insert(format!("{}_count", operation), *count as f64);
        }
        
        // Total operations
        let total_operations: u64 = metrics.operation_counts.values().sum();
        result.insert("total_operations".to_string(), total_operations as f64);
    } else {
        // Fallback values if mutex is poisoned
        result.insert("cache_hit_rate".to_string(), 0.0);
        result.insert("cache_size".to_string(), cache.size() as f64);
    }
    
    Ok(result)
}

/// Numeric benchmark result for easier consumption from Python
#[pyfunction]
pub fn benchmark_proof_generation_numeric(proof_type: String, iterations: u32) -> PyResult<HashMap<String, f64>> {
    let mut timer = Timer::new();
    let mut times_ms = Vec::new();
    let mut successful_iterations = 0u32;

    for _ in 0..iterations {
        timer.reset();
        let result = match proof_type.as_str() {
            "range" => crate::proof::range_proof::prove_range(50, 0, 100),
            "equality" => crate::proof::equality_proof::prove_equality(42, 42),
            "threshold" => crate::proof::threshold_proof::prove_threshold(vec![10, 20, 30, 40], 50),
            "membership" => crate::proof::set_membership::prove_membership(25, vec![10, 20, 25, 30, 40]),
            "improvement" => crate::proof::improvement_proof::prove_improvement(30, 50),
            "consistency" => crate::proof::consistency_proof::prove_consistency(vec![10, 20, 30, 40, 50]),
            _ => return Err(ZkpError::InvalidInput(format!("unsupported proof type: {}", proof_type)).into()),
        };

        if result.is_ok() {
            let elapsed = timer.elapsed();
            let op = match proof_type.as_str() { 
                "range" => "range_proof",
                "equality" => "equality_proof",
                "threshold" => "threshold_proof",
                "membership" => "membership_proof",
                "improvement" => "improvement_proof",
                "consistency" => "consistency_proof",
                _ => "unknown",
            };
            crate::utils::performance::record_operation_metric(op, elapsed);

            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            times_ms.push(elapsed_ms);
            successful_iterations += 1;
        }
    }

    if successful_iterations == 0 {
        return Err(ZkpError::InvalidInput("no successful proof generations".to_string()).into());
    }

    let total_time_ms: f64 = times_ms.iter().sum();
    let avg_time_ms = total_time_ms / successful_iterations as f64;
    let min_time_ms = times_ms.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_time_ms = times_ms.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    let variance = times_ms.iter().map(|&x| (x - avg_time_ms).powi(2)).sum::<f64>() / successful_iterations as f64;
    let std_dev_ms = variance.sqrt();

    let mut out = HashMap::new();
    out.insert("iterations".to_string(), iterations as f64);
    out.insert("successful_iterations".to_string(), successful_iterations as f64);
    out.insert("success_rate".to_string(), (successful_iterations as f64 / iterations as f64) * 100.0);
    out.insert("total_time_ms".to_string(), total_time_ms);
    out.insert("avg_time_ms".to_string(), avg_time_ms);
    out.insert("min_time_ms".to_string(), min_time_ms);
    out.insert("max_time_ms".to_string(), max_time_ms);
    out.insert("std_dev_ms".to_string(), std_dev_ms);
    out.insert("proofs_per_second".to_string(), successful_iterations as f64 / (total_time_ms / 1000.0));
    out.insert("throughput_ms_per_proof".to_string(), total_time_ms / successful_iterations as f64);
    Ok(out)
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

    let mut timer = Timer::new();
    let proof = crate::proof::range_proof::prove_range(value, min, max)?;
    let elapsed = timer.elapsed();
    crate::utils::performance::record_operation_metric("range_proof", elapsed);
    cache.put(cache_key, proof.clone());
    Ok(proof)
}

/// Equality proof with optional context extension
#[pyfunction]
pub fn prove_equality_advanced(val1: u64, val2: u64, context: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values must be equal".to_string()).into());
    }

    // Note: To avoid corrupting the serialized proof format, we do not append context
    // bytes directly. If metadata is needed, use `create_proof_with_metadata`.
    let proof = crate::proof::equality_proof::prove_equality(val1, val2)?;
    let _ = context; // currently unused to preserve proof integrity
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
pub fn benchmark_proof_generation(py: Python, proof_type: String, iterations: u32) -> PyResult<PyObject> {
    let mut timer = Timer::new();
    let mut times_ms = Vec::new();
    let mut successful_iterations = 0;

    for _ in 0..iterations {
        timer.reset();
        let result = match proof_type.as_str() {
            "range" => crate::proof::range_proof::prove_range(50, 0, 100),
            "equality" => crate::proof::equality_proof::prove_equality(42, 42),
            "threshold" => crate::proof::threshold_proof::prove_threshold(vec![10, 20, 30, 40], 50),
            "membership" => crate::proof::set_membership::prove_membership(25, vec![10, 20, 25, 30, 40]),
            "improvement" => crate::proof::improvement_proof::prove_improvement(30, 50),
            "consistency" => crate::proof::consistency_proof::prove_consistency(vec![10, 20, 30, 40, 50]),
            _ => return Err(ZkpError::InvalidInput(format!("unsupported proof type: {}", proof_type)).into()),
        };
        
        if result.is_ok() {
            let elapsed = timer.elapsed();
            // Record per-operation timing
            let op = match proof_type.as_str() { 
                "range" => "range_proof",
                "equality" => "equality_proof",
                "threshold" => "threshold_proof",
                "membership" => "membership_proof",
                "improvement" => "improvement_proof",
                "consistency" => "consistency_proof",
                _ => "unknown",
            };
            crate::utils::performance::record_operation_metric(op, elapsed);

            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            times_ms.push(elapsed_ms);
            successful_iterations += 1;
        }
    }

    if successful_iterations == 0 {
        return Err(ZkpError::InvalidInput("no successful proof generations".to_string()).into());
    }

    // Calculate statistics
    let total_time_ms: f64 = times_ms.iter().sum();
    let avg_time_ms = total_time_ms / successful_iterations as f64;
    let min_time_ms = times_ms.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max_time_ms = times_ms.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
    
    // Calculate standard deviation
    let variance = times_ms.iter()
        .map(|&x| (x - avg_time_ms).powi(2))
        .sum::<f64>() / successful_iterations as f64;
    let std_dev_ms = variance.sqrt();

    let mut results = HashMap::new();
    results.insert("proof_type".to_string(), proof_type);
    results.insert("iterations".to_string(), (iterations as f64).to_string());
    results.insert("successful_iterations".to_string(), (successful_iterations as f64).to_string());
    results.insert("success_rate".to_string(), ((successful_iterations as f64 / iterations as f64) * 100.0).to_string());
    results.insert("total_time_ms".to_string(), total_time_ms.to_string());
    results.insert("avg_time_ms".to_string(), avg_time_ms.to_string());
    results.insert("min_time_ms".to_string(), min_time_ms.to_string());
    results.insert("max_time_ms".to_string(), max_time_ms.to_string());
    results.insert("std_dev_ms".to_string(), std_dev_ms.to_string());
    results.insert("proofs_per_second".to_string(), (successful_iterations as f64 / (total_time_ms / 1000.0)).to_string());
    results.insert("throughput_ms_per_proof".to_string(), (total_time_ms / successful_iterations as f64).to_string());
    
    Ok(results.into_py(py))
}

/// Optimized threshold proof generation with pre-checks
#[pyfunction]
pub fn prove_threshold_optimized(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    if values.is_empty() {
        return Err(ZkpError::InvalidInput("values cannot be empty".to_string()).into());
    }

    let sum: u64 = values
        .iter()
        .try_fold(0u64, |acc, &v| acc.checked_add(v).ok_or(()))
        .map_err(|_| ZkpError::IntegerOverflow("integer overflow in sum calculation".to_string()))?;

    if sum < threshold {
        return Err(ZkpError::InvalidInput("sum does not meet threshold".to_string()).into());
    }

    crate::proof::threshold_proof::prove_threshold(values, threshold)
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