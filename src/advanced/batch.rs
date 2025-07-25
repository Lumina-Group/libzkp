use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use rayon::prelude::*;

use crate::utils::{
    composition::{BatchOperation, ProofBatch},
    validation,
    error_handling::ZkpError,
};

lazy_static! {
    static ref BATCH_REGISTRY: Mutex<HashMap<usize, ProofBatch>> = Mutex::new(HashMap::new());
    static ref BATCH_COUNTER: Mutex<usize> = Mutex::new(0);
}

/// Create a new proof batch and return its identifier
#[pyfunction]
pub fn create_proof_batch() -> PyResult<usize> {
    let mut counter = BATCH_COUNTER.lock().unwrap();
    let batch_id = *counter;
    *counter += 1;

    let mut registry = BATCH_REGISTRY.lock().unwrap();
    registry.insert(batch_id, ProofBatch::new());

    Ok(batch_id)
}

/// Internal helper to execute an operation on a batch under the registry lock
fn with_batch_mut<F>(batch_id: usize, f: F) -> PyResult<()>
where
    F: FnOnce(&mut ProofBatch),
{
    let mut registry = BATCH_REGISTRY.lock().unwrap();
    let batch = registry
        .get_mut(&batch_id)
        .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)).into())?;
    f(batch);
    Ok(())
}

/// Add a range proof operation to the batch
#[pyfunction]
pub fn batch_add_range_proof(batch_id: usize, value: u64, min: u64, max: u64) -> PyResult<()> {
    validation::validate_range_params(value, min, max).map_err(PyErr::from)?;
    with_batch_mut(batch_id, |batch| batch.add_range_proof(value, min, max))
}

/// Add an equality proof operation to the batch
#[pyfunction]
pub fn batch_add_equality_proof(batch_id: usize, val1: u64, val2: u64) -> PyResult<()> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values must be equal".to_string()).into());
    }
    with_batch_mut(batch_id, |batch| batch.add_equality_proof(val1, val2))
}

/// Add a threshold proof operation to the batch
#[pyfunction]
pub fn batch_add_threshold_proof(
    batch_id: usize,
    values: Vec<u64>,
    threshold: u64,
) -> PyResult<()> {
    validation::validate_threshold_params(&values, threshold).map_err(PyErr::from)?;
    with_batch_mut(batch_id, |batch| batch.add_threshold_proof(values, threshold))
}

/// Process a batch: generate all proofs in parallel and return them as byte vectors
#[pyfunction]
pub fn process_batch(batch_id: usize) -> PyResult<Vec<Vec<u8>>> {
    let batch = {
        let mut registry = BATCH_REGISTRY.lock().unwrap();
        registry
            .remove(&batch_id)
            .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?
    };

    batch
        .operations()
        .par_iter()
        .map(process_batch_operation)
        .collect::<Result<Vec<_>, _>>()
        .map_err(PyErr::from)
}

/// Retrieve statistics about a batch such as counts per operation type
#[pyfunction]
pub fn get_batch_status(batch_id: usize) -> PyResult<HashMap<String, usize>> {
    let registry = BATCH_REGISTRY.lock().unwrap();
    let batch = registry
        .get(&batch_id)
        .ok_or_else(|| ZkpError::InvalidInput(format!("Invalid batch ID: {}", batch_id)))?;

    let mut status = HashMap::new();
    status.insert("total_operations".to_string(), batch.len());

    let (mut range, mut equality, mut threshold, mut membership, mut improvement, mut consistency) = (0, 0, 0, 0, 0, 0);
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
#[pyfunction]
pub fn clear_batch(batch_id: usize) -> PyResult<()> {
    let mut registry = BATCH_REGISTRY.lock().unwrap();
    registry.remove(&batch_id);
    Ok(())
}

/// Helper to generate a single proof for a batch operation
fn process_batch_operation(op: &BatchOperation) -> Result<Vec<u8>, ZkpError> {
    match op {
        BatchOperation::RangeProof { value, min, max } => crate::range_proof::prove_range(*value, *min, *max)
            .map_err(|_| ZkpError::ProofGenerationFailed("Range proof failed".to_string())),
        BatchOperation::EqualityProof { val1, val2 } => crate::equality_proof::prove_equality(*val1, *val2)
            .map_err(|_| ZkpError::ProofGenerationFailed("Equality proof failed".to_string())),
        BatchOperation::ThresholdProof { values, threshold } => crate::threshold_proof::prove_threshold(values.clone(), *threshold)
            .map_err(|_| ZkpError::ProofGenerationFailed("Threshold proof failed".to_string())),
        BatchOperation::MembershipProof { value, set } => crate::set_membership::prove_membership(*value, set.clone())
            .map_err(|_| ZkpError::ProofGenerationFailed("Membership proof failed".to_string())),
        BatchOperation::ImprovementProof { old, new } => crate::improvement_proof::prove_improvement(*old, *new)
            .map_err(|_| ZkpError::ProofGenerationFailed("Improvement proof failed".to_string())),
        BatchOperation::ConsistencyProof { data } => crate::consistency_proof::prove_consistency(data.clone())
            .map_err(|_| ZkpError::ProofGenerationFailed("Consistency proof failed".to_string())),
    }
}