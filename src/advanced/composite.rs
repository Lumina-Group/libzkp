use std::collections::HashMap;

use crate::proof::Proof;
use crate::utils::{
    composition::CompositeProof,
    error_handling::{ZkpError, ZkpResult},
};

/// Create a composite proof from multiple individual proofs
pub fn create_composite_proof(proof_list: Vec<Vec<u8>>) -> ZkpResult<Vec<u8>> {
    if proof_list.is_empty() {
        return Err(ZkpError::InvalidInput(
            "proof list cannot be empty".to_string(),
        ));
    }

    let mut proofs = Vec::new();
    for proof_bytes in proof_list {
        let proof = Proof::from_bytes(&proof_bytes)?;
        proofs.push(proof);
    }

    let composite = CompositeProof::new(proofs)?;
    Ok(composite.to_bytes())
}

/// Verify a composite proof: structural hash (proofs + metadata) and each inner ZKP.
pub fn verify_composite_proof(composite_bytes: Vec<u8>) -> ZkpResult<bool> {
    let composite = CompositeProof::from_bytes(&composite_bytes)?;
    Ok(composite.verify_full())
}

/// Verify only the composite encoding hash (proofs + metadata); no cryptographic verification.
pub fn verify_composite_proof_integrity_only(composite_bytes: Vec<u8>) -> ZkpResult<bool> {
    let composite = CompositeProof::from_bytes(&composite_bytes)?;
    Ok(composite.verify_integrity())
}

/// Create a proof with metadata
pub fn create_proof_with_metadata(
    proof_data: Vec<u8>,
    metadata: HashMap<String, Vec<u8>>,
) -> ZkpResult<Vec<u8>> {
    let proof = Proof::from_bytes(&proof_data)?;

    let mut composite = CompositeProof::new(vec![proof])?;

    for (key, value) in metadata {
        composite.add_metadata(key, value);
    }

    Ok(composite.to_bytes())
}

/// Extract metadata from a composite proof
pub fn extract_proof_metadata(composite_bytes: Vec<u8>) -> ZkpResult<HashMap<String, Vec<u8>>> {
    let composite = CompositeProof::from_bytes(&composite_bytes)?;
    Ok(composite.metadata)
}
