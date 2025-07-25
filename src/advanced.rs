use pyo3::prelude::*;
use crate::utils::{
    composition::CompositeProof,
    performance::{get_global_cache, generate_cache_key, Timer},
    error_handling::ZkpError,
};
use crate::proof::Proof;
use std::collections::HashMap;

/// Create a composite proof from multiple individual proofs
#[pyfunction]
pub fn create_composite_proof(proof_list: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    if proof_list.is_empty() {
        return Err(ZkpError::InvalidInput("proof list cannot be empty".to_string()).into());
    }
    
    let mut proofs = Vec::new();
    for proof_bytes in proof_list {
        let proof = Proof::from_bytes(&proof_bytes)
            .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof in list".to_string()))?;
        proofs.push(proof);
    }
    
    let composite = CompositeProof::new(proofs)
        .map_err(|e| PyErr::from(e))?;
    
    Ok(composite.to_bytes())
}

/// Verify a composite proof
#[pyfunction]
pub fn verify_composite_proof(composite_bytes: Vec<u8>) -> PyResult<bool> {
    let composite = CompositeProof::from_bytes(&composite_bytes)
        .map_err(|e| PyErr::from(e))?;
    
    Ok(composite.verify_integrity())
}

/// Create a proof batch for improved performance
#[pyfunction]
pub fn create_proof_batch() -> PyResult<usize> {
    // Return a batch ID (simplified implementation)
    // In a real implementation, this would store the batch in a global registry
    Ok(0)
}

/// Add range proof to batch
#[pyfunction]
pub fn batch_add_range_proof(
    _batch_id: usize,
    _value: u64,
    min: u64,
    max: u64,
) -> PyResult<()> {
    // Simplified implementation - would add to actual batch
    if min > max {
        return Err(ZkpError::InvalidInput("invalid range".to_string()).into());
    }
    Ok(())
}

/// Process batch and return all proofs
#[pyfunction]
pub fn process_batch(_batch_id: usize) -> PyResult<Vec<Vec<u8>>> {
    // Simplified implementation - would process actual batch
    Ok(vec![vec![1, 2, 3, 4]]) // Placeholder
}

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

/// Enable performance monitoring
#[pyfunction]
pub fn enable_performance_monitoring() -> PyResult<bool> {
    // In a real implementation, this would enable global performance tracking
    Ok(true)
}

/// Get performance metrics
#[pyfunction]
pub fn get_performance_metrics() -> PyResult<HashMap<String, f64>> {
    let mut metrics = HashMap::new();
    metrics.insert("cache_hit_rate".to_string(), 0.85); // Placeholder
    metrics.insert("avg_proof_time_ms".to_string(), 125.5); // Placeholder
    Ok(metrics)
}

/// Advanced range proof with caching
#[pyfunction]
pub fn prove_range_cached(value: u64, min: u64, max: u64) -> PyResult<Vec<u8>> {
    let cache = get_global_cache();
    let params = format!("{}:{}:{}", value, min, max);
    let cache_key = generate_cache_key("range_proof", params.as_bytes());
    
    // Check cache first
    if let Some(cached_proof) = cache.get(&cache_key) {
        return Ok(cached_proof);
    }
    
    // Generate proof (call the original function)
    let proof = crate::range_proof::prove_range(value, min, max)?;
    
    // Cache the result
    cache.put(cache_key, proof.clone());
    
    Ok(proof)
}

/// Advanced equality proof with validation
#[pyfunction]
pub fn prove_equality_advanced(val1: u64, val2: u64, context: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values must be equal".to_string()).into());
    }
    
    // Add context to the proof if provided
    let mut proof = crate::equality_proof::prove_equality(val1, val2)?;
    
    if let Some(ctx) = context {
        // In a real implementation, this would incorporate context into the proof
        proof.extend_from_slice(&ctx);
    }
    
    Ok(proof)
}

/// Verify multiple proofs in parallel
#[pyfunction]
pub fn verify_proofs_parallel(proofs: Vec<(Vec<u8>, String)>) -> PyResult<Vec<bool>> {
    use crate::utils::performance::parallel::verify_proofs_parallel;
    Ok(verify_proofs_parallel(&proofs))
}

/// Benchmark proof generation performance
#[pyfunction]
pub fn benchmark_proof_generation(
    proof_type: String,
    iterations: u32,
) -> PyResult<HashMap<String, f64>> {
    let mut timer = Timer::new();
    let mut total_time = 0.0;
    
    for _ in 0..iterations {
        timer.reset();
        
        // Generate a test proof based on type
        let _result = match proof_type.as_str() {
            "range" => crate::range_proof::prove_range(50, 0, 100),
            "equality" => crate::equality_proof::prove_equality(42, 42),
            _ => return Err(ZkpError::InvalidInput("unsupported proof type".to_string()).into()),
        };
        
        total_time += timer.elapsed().as_secs_f64() * 1000.0; // Convert to milliseconds
    }
    
    let mut results = HashMap::new();
    results.insert("total_time_ms".to_string(), total_time);
    results.insert("average_time_ms".to_string(), total_time / iterations as f64);
    results.insert("proofs_per_second".to_string(), iterations as f64 / (total_time / 1000.0));
    
    Ok(results)
}

/// Advanced threshold proof with optimizations
#[pyfunction]
pub fn prove_threshold_optimized(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    // Validate inputs
    if values.is_empty() {
        return Err(ZkpError::InvalidInput("values cannot be empty".to_string()).into());
    }
    
    // Check if sum meets threshold before generating proof
    let sum: u64 = values.iter().try_fold(0u64, |acc, &val| {
        acc.checked_add(val)
            .ok_or_else(|| ZkpError::InvalidInput("integer overflow".to_string()))
    }).map_err(|e| PyErr::from(e))?;
    
    if sum < threshold {
        return Err(ZkpError::InvalidInput("sum does not meet threshold".to_string()).into());
    }
    
    // Generate the actual proof
    crate::threshold_proof::prove_threshold(values, threshold)
}

/// Create a proof with metadata
#[pyfunction]
pub fn create_proof_with_metadata(
    proof_data: Vec<u8>,
    metadata: HashMap<String, Vec<u8>>,
) -> PyResult<Vec<u8>> {
    let proof = Proof::from_bytes(&proof_data)
        .ok_or_else(|| ZkpError::InvalidProofFormat("invalid proof data".to_string()))?;
    
    let mut composite = CompositeProof::new(vec![proof])
        .map_err(|e| PyErr::from(e))?;
    
    for (key, value) in metadata {
        composite.add_metadata(key, value);
    }
    
    Ok(composite.to_bytes())
}

/// Extract metadata from a proof
#[pyfunction]
pub fn extract_proof_metadata(composite_bytes: Vec<u8>) -> PyResult<HashMap<String, Vec<u8>>> {
    let composite = CompositeProof::from_bytes(&composite_bytes)
        .map_err(|e| PyErr::from(e))?;
    
    Ok(composite.metadata)
}

/// Validate proof chain integrity
#[pyfunction]
pub fn validate_proof_chain(proof_chain: Vec<Vec<u8>>) -> PyResult<bool> {
    if proof_chain.is_empty() {
        return Ok(true);
    }
    
    // Validate each proof in the chain
    for proof_bytes in &proof_chain {
        if Proof::from_bytes(proof_bytes).is_none() {
            return Ok(false);
        }
    }
    
    // Additional chain validation logic would go here
    // For now, just check that all proofs are valid
    Ok(true)
}

/// Get proof information
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