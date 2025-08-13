use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Simple LRU cache for proof results
pub struct ProofCache {
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    max_size: usize,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    created_at: Instant,
    access_count: u64,
}

impl ProofCache {
    pub fn new(max_size: usize, ttl_seconds: u64) -> Self {
        ProofCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            ttl: Duration::from_secs(ttl_seconds),
        }
    }
    
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(entry) = cache.get_mut(key) {
            // Check if entry is still valid
            if entry.created_at.elapsed() < self.ttl {
                entry.access_count += 1;
                record_global_cache_hit();
                return Some(entry.data.clone());
            } else {
                // Entry expired, remove it
                cache.remove(key);
            }
        }
        
        // Not found
        record_global_cache_miss();
        None
    }
    
    pub fn put(&self, key: String, data: Vec<u8>) {
        let mut cache = self.cache.lock().unwrap();
        
        // If cache is full, remove least recently used entry
        if cache.len() >= self.max_size {
            let lru_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.access_count)
                .map(|(k, _)| k.clone());
            
            if let Some(lru_key) = lru_key {
                cache.remove(&lru_key);
            }
        }
        
        let entry = CacheEntry {
            data,
            created_at: Instant::now(),
            access_count: 1,
        };
        
        cache.insert(key, entry);
    }
    
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
    
    pub fn size(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }
    
    /// Clean up expired entries
    pub fn cleanup(&self) {
        let mut cache = self.cache.lock().unwrap();
        let now = Instant::now();
        
        cache.retain(|_, entry| now.duration_since(entry.created_at) < self.ttl);
    }
}

/// Global proof cache instance using OnceLock
static GLOBAL_CACHE: OnceLock<ProofCache> = OnceLock::new();
/// Global performance metrics instance using OnceLock
static GLOBAL_METRICS: OnceLock<Arc<Mutex<PerformanceMetrics>>> = OnceLock::new();

pub fn get_global_cache() -> &'static ProofCache {
    GLOBAL_CACHE.get_or_init(|| ProofCache::new(1000, 3600))
}

pub fn get_global_metrics() -> Arc<Mutex<PerformanceMetrics>> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(Mutex::new(PerformanceMetrics::new())))
        .clone()
}

/// Record a performance metric in the global collector
pub fn record_operation_metric(operation: &str, duration: Duration) {
    if let Ok(mut m) = get_global_metrics().lock() {
        m.record_operation(operation, duration);
    }
}

/// Record cache hit in global metrics
pub fn record_global_cache_hit() {
    if let Ok(mut m) = get_global_metrics().lock() {
        m.record_cache_hit();
    }
}

/// Record cache miss in global metrics
pub fn record_global_cache_miss() {
    if let Ok(mut m) = get_global_metrics().lock() {
        m.record_cache_miss();
    }
}

/// Generate cache key for proof operations
pub fn generate_cache_key(operation: &str, params: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    hasher.update(operation.as_bytes());
    hasher.update(params);
    
    format!("{}:{:x}", operation, hasher.finalize())
}

/// Performance metrics collector
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub operation_counts: HashMap<String, u64>,
    pub operation_times: HashMap<String, Vec<Duration>>,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        PerformanceMetrics {
            operation_counts: HashMap::new(),
            operation_times: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }
    
    pub fn record_operation(&mut self, operation: &str, duration: Duration) {
        *self.operation_counts.entry(operation.to_string()).or_insert(0) += 1;
        self.operation_times
            .entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
    }
    
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }
    
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }
    
    pub fn get_average_time(&self, operation: &str) -> Option<Duration> {
        self.operation_times.get(operation).map(|times| {
            let total: Duration = times.iter().sum();
            total / times.len() as u32
        })
    }
    
    pub fn get_cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Timing utilities for performance measurement
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            start: Instant::now(),
        }
    }
    
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
    
    pub fn reset(&mut self) {
        self.start = Instant::now();
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

/// Parallel processing utilities for batch operations
pub mod parallel {
    use rayon::prelude::*;
    use crate::proof::{Proof, PROOF_VERSION};
    use crate::utils::proof_helpers::reconstruct_bulletproofs_proof;
    use crate::backend::{bulletproofs::BulletproofsBackend, snark::SnarkBackend, stark::StarkBackend};
    
    /// Verify multiple proofs in parallel with proper type handling
    pub fn verify_proofs_parallel(proofs: &[(Vec<u8>, String)]) -> Vec<bool> {
        proofs
            .par_iter()
            .map(|(proof_data, proof_type)| {
                verify_single_proof(proof_data, proof_type)
            })
            .collect()
    }
    
    /// Verify a single proof based on its type
    fn verify_single_proof(proof_data: &[u8], proof_type: &str) -> bool {
        // Parse proof bytes
        let proof = match Proof::from_bytes(proof_data) {
            Some(p) => p,
            None => return false,
        };

        if proof.version != PROOF_VERSION {
            return false;
        }

        match proof_type {
            "range" => {
                if proof.scheme != 1 { return false; }
                // Parse min/max from bulletproofs payload
                if proof.proof.len() < 16 { return false; }
                let min = u64::from_le_bytes(proof.proof[0..8].try_into().unwrap());
                let max = u64::from_le_bytes(proof.proof[8..16].try_into().unwrap());
                if min > max { return false; }
                if proof.commitment.len() != 32 { return false; }
                let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
                BulletproofsBackend::verify_range_with_bounds(&backend_proof, min, max)
            }
            "equality" => {
                if proof.scheme != 2 { return false; }
                if proof.commitment.len() != 32 { return false; }
                // Verify SNARK proof with embedded commitment as public input
                SnarkBackend::verify(&proof.proof, &proof.commitment)
            }
            "threshold" => {
                if proof.scheme != 3 { return false; }
                if proof.proof.len() < 8 { return false; }
                let threshold = u64::from_le_bytes(proof.proof[0..8].try_into().unwrap());
                if proof.commitment.len() != 32 { return false; }
                let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
                BulletproofsBackend::verify_threshold(&backend_proof, threshold)
            }
            "membership" => {
                if proof.scheme != 4 { return false; }
                if proof.proof.len() < 4 { return false; }
                // Extract set from proof payload
                let set_size = u32::from_le_bytes(proof.proof[0..4].try_into().unwrap()) as usize;
                let needed = 4 + set_size * 8;
                if proof.proof.len() < needed { return false; }
                let mut set = Vec::with_capacity(set_size);
                let mut offset = 4;
                for _ in 0..set_size {
                    let val = u64::from_le_bytes(proof.proof[offset..offset+8].try_into().unwrap());
                    set.push(val);
                    offset += 8;
                }
                if proof.commitment.len() != 32 { return false; }
                let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
                BulletproofsBackend::verify_set_membership(&backend_proof, set)
            }
            "improvement" => {
                if proof.scheme != 5 { return false; }
                if proof.commitment.len() != 16 { return false; }
                let diff = u64::from_le_bytes(proof.commitment[0..8].try_into().unwrap());
                let new = u64::from_le_bytes(proof.commitment[8..16].try_into().unwrap());
                if diff == 0 { return false; }
                let old = match new.checked_sub(diff) { Some(v) => v, None => return false };
                // Prepare public inputs payload expected by backend verify
                let mut data = Vec::with_capacity(16);
                data.extend_from_slice(&old.to_le_bytes());
                data.extend_from_slice(&new.to_le_bytes());
                StarkBackend::verify(&proof.proof, &data)
            }
            "consistency" => {
                if proof.scheme != 6 { return false; }
                // Reconstruct backend proof and verify
                let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
                BulletproofsBackend::verify_consistency(&backend_proof)
            }
            _ => false,
        }
    }
    
    // Removed simplified internal verifiers in favor of backend verification
    
    /// Generate multiple proofs in parallel
    pub fn generate_proofs_parallel<F, T>(
        inputs: Vec<T>,
        proof_fn: F,
    ) -> Vec<Result<Vec<u8>, String>>
    where
        F: Fn(T) -> Result<Vec<u8>, String> + Sync,
        T: Send,
    {
        inputs
            .into_par_iter()
            .map(|input| proof_fn(input))
            .collect()
    }
    
    /// Batch verify with early termination on failure
    pub fn batch_verify_with_early_termination(
        proofs: &[(Vec<u8>, String)],
    ) -> Result<(), usize> {
        let results: Vec<(usize, bool)> = proofs
            .par_iter()
            .enumerate()
            .map(|(idx, (proof_data, proof_type))| {
                (idx, verify_single_proof(proof_data, proof_type))
            })
            .collect();
        
        // Find first failure
        for (idx, valid) in results {
            if !valid {
                return Err(idx);
            }
        }
        
        Ok(())
    }
}

/// Memory pool for reducing allocations
pub struct MemoryPool {
    buffers: Arc<Mutex<Vec<Vec<u8>>>>,
    buffer_size: usize,
}

impl MemoryPool {
    pub fn new(initial_capacity: usize, buffer_size: usize) -> Self {
        let mut buffers = Vec::with_capacity(initial_capacity);
        for _ in 0..initial_capacity {
            buffers.push(Vec::with_capacity(buffer_size));
        }
        
        MemoryPool {
            buffers: Arc::new(Mutex::new(buffers)),
            buffer_size,
        }
    }
    
    pub fn get_buffer(&self) -> Vec<u8> {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.pop().unwrap_or_else(|| Vec::with_capacity(self.buffer_size))
    }
    
    pub fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        if buffer.capacity() <= self.buffer_size * 2 {
            let mut buffers = self.buffers.lock().unwrap();
            if buffers.len() < 100 { // Limit pool size
                buffers.push(buffer);
            }
        }
    }
}