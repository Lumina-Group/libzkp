use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use rand::Rng;

#[cfg(feature = "batch-store")]
use crate::advanced::batch_store::{
    delete_batch_file_if_configured, get_batch_store_dir, persist_batch_if_configured,
    read_batch_file,
};
use crate::utils::{
    composition::{BatchOperation, ProofBatch},
    error_handling::{ZkpError, ZkpResult},
    validation,
};

lazy_static! {
    static ref BATCH_REGISTRY: Mutex<HashMap<u64, ProofBatch>> = Mutex::new(HashMap::new());
}

fn allocate_batch_id(registry: &HashMap<u64, ProofBatch>) -> u64 {
    let mut rng = rand::thread_rng();
    loop {
        let id = rng.gen::<u64>();
        if id != 0 && !registry.contains_key(&id) {
            return id;
        }
    }
}

/// Create a new proof batch and return its identifier.
///
/// IDs are **cryptographically random `u64` values** (never zero), unique within this process.
/// They are not predictable like sequential counters and are **not** persisted across restarts.
pub fn create_proof_batch() -> ZkpResult<u64> {
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    let batch_id = allocate_batch_id(&registry);
    registry.insert(batch_id, ProofBatch::new());
    #[cfg(feature = "batch-store")]
    {
        if let Some(b) = registry.get(&batch_id) {
            persist_batch_if_configured(batch_id, b)?;
        }
    }
    Ok(batch_id)
}

fn with_batch_mut<F>(batch_id: u64, f: F) -> ZkpResult<()>
where
    F: FnOnce(&mut ProofBatch),
{
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    let batch = registry
        .get_mut(&batch_id)
        .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?;
    f(batch);
    #[cfg(feature = "batch-store")]
    {
        if let Some(b) = registry.get(&batch_id) {
            persist_batch_if_configured(batch_id, b)?;
        }
    }
    Ok(())
}

/// Add a range proof operation to the batch
pub fn batch_add_range_proof(batch_id: u64, value: u64, min: u64, max: u64) -> ZkpResult<()> {
    validation::validate_range_params(value, min, max)?;
    with_batch_mut(batch_id, |batch| batch.add_range_proof(value, min, max))
}

/// Add an equality proof operation to the batch
pub fn batch_add_equality_proof(batch_id: u64, val1: u64, val2: u64) -> ZkpResult<()> {
    validation::validate_equality_params(val1, val2)?;
    with_batch_mut(batch_id, |batch| batch.add_equality_proof(val1, val2))
}

/// Add a threshold proof operation to the batch
pub fn batch_add_threshold_proof(batch_id: u64, values: Vec<u64>, threshold: u64) -> ZkpResult<()> {
    validation::validate_threshold_params(&values, threshold)?;
    with_batch_mut(batch_id, |batch| {
        batch.add_threshold_proof(values, threshold)
    })
}

/// Add a membership proof operation to the batch
pub fn batch_add_membership_proof(batch_id: u64, value: u64, set: Vec<u64>) -> ZkpResult<()> {
    validation::validate_membership_params(value, &set)?;
    with_batch_mut(batch_id, |batch| batch.add_membership_proof(value, set))
}

/// Add an improvement proof operation to the batch
pub fn batch_add_improvement_proof(batch_id: u64, old: u64, new: u64) -> ZkpResult<()> {
    validation::validate_improvement_params(old, new)?;
    with_batch_mut(batch_id, |batch| batch.add_improvement_proof(old, new))
}

/// Add a consistency proof operation to the batch
pub fn batch_add_consistency_proof(batch_id: u64, data: Vec<u64>) -> ZkpResult<()> {
    validation::validate_consistency_params(&data)?;
    with_batch_mut(batch_id, |batch| batch.add_consistency_proof(data))
}

/// Process a batch: generate all proofs in parallel and return them as byte vectors
pub fn process_batch(batch_id: u64) -> ZkpResult<Vec<Vec<u8>>> {
    let batch = {
        let mut registry = BATCH_REGISTRY
            .lock()
            .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
        registry
            .remove(&batch_id)
            .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?
    };

    #[cfg(feature = "batch-store")]
    delete_batch_file_if_configured(batch_id)?;

    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        batch
            .operations()
            .par_iter()
            .map(process_batch_operation)
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        batch
            .operations()
            .iter()
            .map(process_batch_operation)
            .collect()
    }
}

/// Retrieve statistics about a batch such as counts per operation type
pub fn get_batch_status(batch_id: u64) -> ZkpResult<HashMap<String, usize>> {
    let registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    let batch = registry
        .get(&batch_id)
        .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?;

    let mut status = HashMap::new();
    status.insert("total_operations".to_string(), batch.len());

    let (mut range, mut equality, mut threshold, mut membership, mut improvement, mut consistency) =
        (0, 0, 0, 0, 0, 0);
    for op in batch.operations() {
        match op {
            BatchOperation::RangeProof { .. } => range += 1,
            BatchOperation::EqualityProof { .. } => equality += 1,
            BatchOperation::ThresholdProof { .. } => threshold += 1,
            BatchOperation::MembershipProof { .. } => membership += 1,
            BatchOperation::ImprovementProof { .. } => improvement += 1,
            BatchOperation::ConsistencyProof { .. } => consistency += 1,
        }
    }

    status.insert("range_proofs".to_string(), range);
    status.insert("equality_proofs".to_string(), equality);
    status.insert("threshold_proofs".to_string(), threshold);
    status.insert("membership_proofs".to_string(), membership);
    status.insert("improvement_proofs".to_string(), improvement);
    status.insert("consistency_proofs".to_string(), consistency);

    Ok(status)
}

/// Remove a batch and release its resources
pub fn clear_batch(batch_id: u64) -> ZkpResult<()> {
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    registry.remove(&batch_id);
    #[cfg(feature = "batch-store")]
    delete_batch_file_if_configured(batch_id)?;
    Ok(())
}

/// Load a batch from the on-disk store into this process registry.
///
/// Fails if `batch_id` is already registered in memory. Requires [`get_batch_store_dir`] or
/// [`crate::advanced::batch_store::set_batch_store_dir`] / `LIBZKP_BATCH_DIR`.
#[cfg(feature = "batch-store")]
pub fn open_batch_from_store(batch_id: u64) -> ZkpResult<()> {
    let dir = get_batch_store_dir().ok_or_else(|| {
        ZkpError::ConfigError(
            "batch store not configured: set_batch_store_dir or LIBZKP_BATCH_DIR".to_string(),
        )
    })?;
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    if registry.contains_key(&batch_id) {
        return Err(ZkpError::InvalidInput(format!(
            "batch {} is already open in this process",
            batch_id
        )));
    }
    let batch = read_batch_file(&dir, batch_id)?;
    registry.insert(batch_id, batch);
    Ok(())
}

/// Replace the in-memory batch with the contents read from disk (e.g. after another process wrote).
#[cfg(feature = "batch-store")]
pub fn refresh_batch_from_store(batch_id: u64) -> ZkpResult<()> {
    let dir = get_batch_store_dir().ok_or_else(|| {
        ZkpError::ConfigError(
            "batch store not configured: set_batch_store_dir or LIBZKP_BATCH_DIR".to_string(),
        )
    })?;
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    if !registry.contains_key(&batch_id) {
        return Err(ZkpError::InvalidInput(format!(
            "batch {} is not loaded in this process",
            batch_id
        )));
    }
    let batch = read_batch_file(&dir, batch_id)?;
    registry.insert(batch_id, batch);
    Ok(())
}

/// Export the in-memory batch to a file (same format as store files).
#[cfg(feature = "batch-store")]
pub fn export_batch_to_file(batch_id: u64, dest: impl AsRef<std::path::Path>) -> ZkpResult<()> {
    let registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    let batch = registry
        .get(&batch_id)
        .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?;
    crate::advanced::batch_store::export_proof_batch_to_path(batch, dest.as_ref())
}

/// Import a batch file into a new in-memory batch (new `batch_id`) and persist if configured.
#[cfg(feature = "batch-store")]
pub fn import_batch_from_file(src: impl AsRef<std::path::Path>) -> ZkpResult<u64> {
    let pb = crate::advanced::batch_store::import_proof_batch_from_path(src.as_ref())?;
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    let batch_id = allocate_batch_id(&registry);
    registry.insert(batch_id, pb);
    if let Some(b) = registry.get(&batch_id) {
        persist_batch_if_configured(batch_id, b)?;
    }
    Ok(batch_id)
}

fn process_batch_operation(op: &BatchOperation) -> ZkpResult<Vec<u8>> {
    match op {
        BatchOperation::RangeProof { value, min, max } => {
            crate::proof::range_proof::prove_range(*value, *min, *max)
        }
        BatchOperation::EqualityProof { val1, val2 } => {
            crate::proof::equality_proof::prove_equality(*val1, *val2)
        }
        BatchOperation::ThresholdProof { values, threshold } => {
            crate::proof::threshold_proof::prove_threshold(values.clone(), *threshold)
        }
        BatchOperation::MembershipProof { value, set } => {
            crate::proof::set_membership::prove_membership(*value, set.clone())
        }
        BatchOperation::ImprovementProof { old, new } => {
            crate::proof::improvement_proof::prove_improvement(*old, *new)
        }
        BatchOperation::ConsistencyProof { data } => {
            crate::proof::consistency_proof::prove_consistency(data.clone())
        }
    }
}
