use crate::proof::{Proof, PROOF_VERSION};
use crate::utils::error_handling::{ZkpError, ZkpResult};

/// Common proof parsing and validation logic
pub fn parse_and_validate_proof(proof_bytes: &[u8], expected_scheme: u8) -> ZkpResult<Proof> {
    let proof = Proof::from_bytes(proof_bytes)
        .ok_or_else(|| ZkpError::InvalidProofFormat("failed to parse proof".to_string()))?;

    if proof.version != PROOF_VERSION {
        return Err(ZkpError::InvalidProofFormat(format!(
            "unsupported proof version: expected {}, got {}",
            PROOF_VERSION, proof.version
        )));
    }

    if proof.scheme != expected_scheme {
        return Err(ZkpError::InvalidProofFormat(format!(
            "wrong proof scheme: expected {}, got {}",
            expected_scheme, proof.scheme
        )));
    }

    Ok(proof)
}

/// Extract proof and commitment from bulletproofs backend output
pub fn extract_bulletproofs_components(backend_proof: &[u8]) -> ZkpResult<(Vec<u8>, Vec<u8>)> {
    let commit_marker = b"COMMIT:";
    let commit_pos = backend_proof
        .windows(commit_marker.len())
        .position(|window| window == commit_marker)
        .ok_or_else(|| ZkpError::InvalidProofFormat("missing commitment marker".to_string()))?;

    let proof_bytes = &backend_proof[0..commit_pos];
    let commit_start = commit_pos + commit_marker.len();

    if backend_proof.len() < commit_start + 32 {
        return Err(ZkpError::InvalidProofFormat(
            "invalid commitment size".to_string(),
        ));
    }

    let commitment = backend_proof[commit_start..commit_start + 32].to_vec();

    Ok((proof_bytes.to_vec(), commitment))
}

/// Reconstruct bulletproofs backend format from proof components
pub fn reconstruct_bulletproofs_proof(proof_bytes: &[u8], commitment: &[u8]) -> Vec<u8> {
    let mut backend_proof = Vec::new();
    backend_proof.extend_from_slice(proof_bytes);
    backend_proof.extend_from_slice(b"COMMIT:");
    backend_proof.extend_from_slice(commitment);
    backend_proof
}

/// Create a new proof with the given scheme and components
pub fn create_proof(
    scheme_id: u8,
    proof_bytes: Vec<u8>,
    commitment: Vec<u8>,
) -> ZkpResult<Vec<u8>> {
    let proof = Proof::new(scheme_id, proof_bytes, commitment);
    Ok(proof.to_bytes())
}

/// Validate standard 32-byte commitment
pub fn validate_standard_commitment(commitment: &[u8]) -> ZkpResult<()> {
    if commitment.len() != 32 {
        return Err(ZkpError::InvalidProofFormat(format!(
            "invalid commitment size: expected 32 bytes, got {}",
            commitment.len()
        )));
    }
    Ok(())
}

/// Check if values are in ascending order
pub fn is_ascending_order(values: &[u64]) -> bool {
    values.windows(2).all(|w| w[0] <= w[1])
}

/// Calculate sum with overflow check
pub fn safe_sum(values: &[u64]) -> ZkpResult<u64> {
    values.iter().try_fold(0u64, |acc, &val| {
        acc.checked_add(val).ok_or_else(|| {
            ZkpError::InvalidInput("integer overflow in sum calculation".to_string())
        })
    })
}
