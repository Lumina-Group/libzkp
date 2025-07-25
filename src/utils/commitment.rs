use sha2::{Digest, Sha256};
use crate::utils::error_handling::{ZkpError, ZkpResult};

/// Generate a SHA256 commitment for a single value
pub fn commit_value(value: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&value.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Generate a SHA256 commitment for multiple values
pub fn commit_values(values: &[u64]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for &value in values {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().to_vec()
}

/// Generate a commitment with additional context data
pub fn commit_with_context(values: &[u64], context: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(context);
    for &value in values {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize().to_vec()
}

/// Verify that a commitment matches the expected value
pub fn verify_commitment(commitment: &[u8], value: u64) -> bool {
    let expected = commit_value(value);
    commitment == expected
}

/// Verify that a commitment matches the expected values
pub fn verify_commitment_values(commitment: &[u8], values: &[u64]) -> bool {
    let expected = commit_values(values);
    commitment == expected
}

/// Create a commitment for improvement proof (difference and new value)
pub fn commit_improvement(old: u64, new: u64) -> ZkpResult<Vec<u8>> {
    if new <= old {
        return Err(ZkpError::InvalidInput("new value must be greater than old".to_string()));
    }
    
    let diff = new - old;
    let mut commitment = Vec::new();
    commitment.extend_from_slice(&diff.to_le_bytes());
    commitment.extend_from_slice(&new.to_le_bytes());
    Ok(commitment)
}

/// Extract improvement values from commitment
pub fn extract_improvement_values(commitment: &[u8]) -> ZkpResult<(u64, u64)> {
    if commitment.len() != 16 {
        return Err(ZkpError::InvalidProofFormat("invalid improvement commitment size".to_string()));
    }
    
    let diff = u64::from_le_bytes(commitment[0..8].try_into().unwrap());
    let new = u64::from_le_bytes(commitment[8..16].try_into().unwrap());
    
    if diff == 0 {
        return Err(ZkpError::InvalidProofFormat("improvement difference cannot be zero".to_string()));
    }
    
    Ok((diff, new))
}

/// Validate improvement commitment against old value
pub fn validate_improvement_commitment(commitment: &[u8], old: u64) -> ZkpResult<u64> {
    let (diff, new) = extract_improvement_values(commitment)?;
    
    let calculated_new = old.checked_add(diff)
        .ok_or_else(|| ZkpError::InvalidProofFormat("integer overflow in improvement calculation".to_string()))?;
    
    if new != calculated_new {
        return Err(ZkpError::InvalidProofFormat("inconsistent improvement values".to_string()));
    }
    
    Ok(new)
}