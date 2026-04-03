use crate::backend::ZkpBackend;
use crate::backend::{
    bulletproofs::BulletproofsBackend, snark::MAX_SET_SIZE, snark::SnarkBackend,
    stark::StarkBackend,
};
use crate::proof::{Proof, PROOF_VERSION};
use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::limits::{MAX_BULLETPROOFS_BACKEND_PROOF_BYTES, MAX_PROOF_TOTAL_BYTES};

/// Common proof parsing and validation logic
pub fn parse_and_validate_proof(proof_bytes: &[u8], expected_scheme: u8) -> ZkpResult<Proof> {
    if proof_bytes.len() > MAX_PROOF_TOTAL_BYTES {
        return Err(ZkpError::InvalidProofFormat(format!(
            "proof too large: max {} bytes",
            MAX_PROOF_TOTAL_BYTES
        )));
    }
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
    if backend_proof.len() > MAX_BULLETPROOFS_BACKEND_PROOF_BYTES {
        return Err(ZkpError::InvalidProofFormat(format!(
            "backend proof too large: max {} bytes",
            MAX_BULLETPROOFS_BACKEND_PROOF_BYTES
        )));
    }
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

/// Cryptographically verify a single [`Proof`] using its `scheme` field (backends: Bulletproofs, SNARK, STARK).
pub fn verify_proof_cryptographic(proof: &Proof) -> bool {
    if proof.version != PROOF_VERSION {
        return false;
    }
    match proof.scheme {
        1 => {
            if proof.proof.len() < 16 || proof.commitment.len() != 32 {
                return false;
            }
            let min_bytes: [u8; 8] = match proof.proof[0..8].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let max_bytes: [u8; 8] = match proof.proof[8..16].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let min = u64::from_le_bytes(min_bytes);
            let max = u64::from_le_bytes(max_bytes);
            if min > max {
                return false;
            }
            let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
            BulletproofsBackend::verify_range_with_bounds(&backend_proof, min, max)
        }
        2 => {
            if proof.commitment.len() != 32 {
                return false;
            }
            SnarkBackend::verify(&proof.proof, &proof.commitment)
        }
        3 => {
            if proof.proof.len() < 8 || proof.commitment.len() != 32 {
                return false;
            }
            let threshold_bytes: [u8; 8] = match proof.proof[0..8].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let threshold = u64::from_le_bytes(threshold_bytes);
            let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
            BulletproofsBackend::verify_threshold(&backend_proof, threshold)
        }
        4 => {
            if proof.proof.len() < 4 || proof.commitment.len() != 32 {
                return false;
            }
            let set_size_bytes: [u8; 4] = match proof.proof[0..4].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let set_size = u32::from_le_bytes(set_size_bytes) as usize;
            if set_size == 0 || set_size > MAX_SET_SIZE {
                return false;
            }
            let needed = match set_size.checked_mul(8).and_then(|v| v.checked_add(4)) {
                Some(n) => n,
                None => return false,
            };
            if proof.proof.len() <= needed {
                return false;
            }
            let mut set = Vec::with_capacity(set_size);
            let mut offset = 4;
            for _ in 0..set_size {
                let val_bytes: [u8; 8] = match proof.proof.get(offset..offset + 8) {
                    Some(slice) => match slice.try_into() {
                        Ok(arr) => arr,
                        Err(_) => return false,
                    },
                    None => return false,
                };
                set.push(u64::from_le_bytes(val_bytes));
                offset += 8;
            }
            let snark_bytes = &proof.proof[needed..];
            if snark_bytes.is_empty() {
                return false;
            }
            SnarkBackend::verify_membership_zk(snark_bytes, &set, &proof.commitment)
        }
        5 => {
            if proof.commitment.len() != 16 {
                return false;
            }
            let diff_bytes: [u8; 8] = match proof.commitment[0..8].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let new_bytes: [u8; 8] = match proof.commitment[8..16].try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            };
            let diff = u64::from_le_bytes(diff_bytes);
            let new = u64::from_le_bytes(new_bytes);
            if diff == 0 {
                return false;
            }
            let old = match new.checked_sub(diff) {
                Some(v) => v,
                None => return false,
            };
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&old.to_le_bytes());
            data.extend_from_slice(&new.to_le_bytes());
            StarkBackend::verify(&proof.proof, &data)
        }
        6 => {
            let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
            BulletproofsBackend::verify_consistency(&backend_proof)
        }
        _ => false,
    }
}
