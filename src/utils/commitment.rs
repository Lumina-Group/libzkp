use crate::utils::error_handling::{ZkpError, ZkpResult};
use sha2::{Digest, Sha256};

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

/// Create a 32-byte SHA-256 commitment binding `(old, new)` for improvement proofs.
pub fn commit_improvement(old: u64, new: u64) -> ZkpResult<Vec<u8>> {
    if new <= old {
        return Err(ZkpError::InvalidInput(
            "new value must be greater than old".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"libzkp_improvement_v1");
    hasher.update(&old.to_le_bytes());
    hasher.update(&new.to_le_bytes());
    Ok(hasher.finalize().to_vec())
}

/// Validate that `commitment` matches the expected SHA-256 binding for `(old, new)`.
pub fn validate_improvement_commitment(commitment: &[u8], old: u64, new: u64) -> ZkpResult<()> {
    if commitment.len() != 32 {
        return Err(ZkpError::InvalidProofFormat(
            "invalid improvement commitment size".to_string(),
        ));
    }

    let expected = commit_improvement(old, new)?;
    if commitment != expected.as_slice() {
        return Err(ZkpError::InvalidProofFormat(
            "improvement commitment mismatch".to_string(),
        ));
    }
    Ok(())
}
