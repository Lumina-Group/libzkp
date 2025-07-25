use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
                return Some(entry.data.clone());
            } else {
                // Entry expired, remove it
                cache.remove(key);
            }
        }
        
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

/// Global proof cache instance
static mut GLOBAL_CACHE: Option<ProofCache> = None;
static CACHE_INIT: std::sync::Once = std::sync::Once::new();

pub fn get_global_cache() -> &'static ProofCache {
    unsafe {
        CACHE_INIT.call_once(|| {
            GLOBAL_CACHE = Some(ProofCache::new(1000, 3600)); // 1000 entries, 1 hour TTL
        });
        GLOBAL_CACHE.as_ref().unwrap()
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
    
    /// Verify multiple proofs in parallel
    pub fn verify_proofs_parallel(proofs: &[(Vec<u8>, String)]) -> Vec<bool> {
        proofs
            .par_iter()
            .map(|(proof_data, _proof_type)| {
                // Placeholder verification logic
                !proof_data.is_empty()
            })
            .collect()
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