use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use rayon::prelude::*;

use crate::utils::{
    composition::{BatchOperation, ProofBatch},
    error_handling::{ZkpError, ZkpResult},
    validation,
};

lazy_static! {
    static ref BATCH_REGISTRY: Mutex<HashMap<usize, ProofBatch>> = Mutex::new(HashMap::new());
    static ref BATCH_COUNTER: Mutex<usize> = Mutex::new(0);
}

/// Create a new proof batch and return its identifier
pub fn create_proof_batch() -> ZkpResult<usize> {
    let mut counter = BATCH_COUNTER
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch counter lock poisoned".to_string()))?;
    let batch_id = *counter;
    *counter += 1;

    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    registry.insert(batch_id, ProofBatch::new());

    Ok(batch_id)
}

fn with_batch_mut<F>(batch_id: usize, f: F) -> ZkpResult<()>
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
    Ok(())
}

/// Add a range proof operation to the batch
pub fn batch_add_range_proof(batch_id: usize, value: u64, min: u64, max: u64) -> ZkpResult<()> {
    validation::validate_range_params(value, min, max)?;
    with_batch_mut(batch_id, |batch| batch.add_range_proof(value, min, max))
}

/// Add an equality proof operation to the batch
pub fn batch_add_equality_proof(batch_id: usize, val1: u64, val2: u64) -> ZkpResult<()> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values must be equal".to_string()));
    }
    with_batch_mut(batch_id, |batch| batch.add_equality_proof(val1, val2))
}

/// Add a threshold proof operation to the batch
pub fn batch_add_threshold_proof(
    batch_id: usize,
    values: Vec<u64>,
    threshold: u64,
) -> ZkpResult<()> {
    validation::validate_threshold_params(&values, threshold)?;
    with_batch_mut(batch_id, |batch| {
        batch.add_threshold_proof(values, threshold)
    })
}

/// Add a membership proof operation to the batch
pub fn batch_add_membership_proof(batch_id: usize, value: u64, set: Vec<u64>) -> ZkpResult<()> {
    validation::validate_membership_params(value, &set)?;
    with_batch_mut(batch_id, |batch| batch.add_membership_proof(value, set))
}

/// Add an improvement proof operation to the batch
pub fn batch_add_improvement_proof(batch_id: usize, old: u64, new: u64) -> ZkpResult<()> {
    validation::validate_improvement_params(old, new)?;
    with_batch_mut(batch_id, |batch| batch.add_improvement_proof(old, new))
}

/// Add a consistency proof operation to the batch
pub fn batch_add_consistency_proof(batch_id: usize, data: Vec<u64>) -> ZkpResult<()> {
    validation::validate_consistency_params(&data)?;
    with_batch_mut(batch_id, |batch| batch.add_consistency_proof(data))
}

/// Process a batch: generate all proofs in parallel and return them as byte vectors
pub fn process_batch(batch_id: usize) -> ZkpResult<Vec<Vec<u8>>> {
    let batch = {
        let mut registry = BATCH_REGISTRY
            .lock()
            .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
        registry
            .remove(&batch_id)
            .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?
    };

    batch
        .operations()
        .par_iter()
        .map(process_batch_operation)
        .collect()
}

/// Retrieve statistics about a batch such as counts per operation type
pub fn get_batch_status(batch_id: usize) -> ZkpResult<HashMap<String, usize>> {
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
pub fn clear_batch(batch_id: usize) -> ZkpResult<()> {
    let mut registry = BATCH_REGISTRY
        .lock()
        .map_err(|_| ZkpError::CryptoError("batch registry lock poisoned".to_string()))?;
    registry.remove(&batch_id);
    Ok(())
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
