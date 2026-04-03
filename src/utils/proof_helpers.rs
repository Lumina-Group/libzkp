use crate::backend::ZkpBackend;
use crate::backend::{
    bulletproofs::BulletproofsBackend, snark::SnarkBackend, snark::MAX_SET_SIZE,
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
    let proof = Proof::from_bytes(proof_bytes)?;

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

/// Extract proof body and commitment from bulletproofs backend output
/// (`[u32 len][proof_body][u32=32][32 byte commit]`).
pub fn extract_bulletproofs_components(backend_proof: &[u8]) -> ZkpResult<(Vec<u8>, Vec<u8>)> {
    if backend_proof.len() > MAX_BULLETPROOFS_BACKEND_PROOF_BYTES {
        return Err(ZkpError::InvalidProofFormat(format!(
            "backend proof too large: max {} bytes",
            MAX_BULLETPROOFS_BACKEND_PROOF_BYTES
        )));
    }
    if backend_proof.len() < 4 + 4 + 32 {
        return Err(ZkpError::InvalidProofFormat(
            "bulletproofs backend payload too short".to_string(),
        ));
    }
    let plen = u32::from_le_bytes(
        backend_proof[0..4]
            .try_into()
            .map_err(|_| ZkpError::InvalidProofFormat("invalid proof length prefix".to_string()))?,
    ) as usize;
    let proof_end = 4usize
        .checked_add(plen)
        .ok_or_else(|| ZkpError::InvalidProofFormat("proof length overflow".to_string()))?;
    if backend_proof.len() < proof_end + 4 + 32 {
        return Err(ZkpError::InvalidProofFormat(
            "truncated bulletproofs backend payload".to_string(),
        ));
    }
    let clen = u32::from_le_bytes(
        backend_proof[proof_end..proof_end + 4]
            .try_into()
            .map_err(|_| {
                ZkpError::InvalidProofFormat("invalid commit length prefix".to_string())
            })?,
    ) as usize;
    if clen != 32 {
        return Err(ZkpError::InvalidProofFormat(
            "invalid commitment length (expected 32)".to_string(),
        ));
    }
    if backend_proof.len() != proof_end + 4 + 32 {
        return Err(ZkpError::InvalidProofFormat(
            "trailing bytes in bulletproofs backend payload".to_string(),
        ));
    }

    let proof_bytes = backend_proof[4..proof_end].to_vec();
    let commitment = backend_proof[proof_end + 4..proof_end + 4 + 32].to_vec();

    Ok((proof_bytes, commitment))
}

/// Reconstruct bulletproofs backend wire format from proof components.
pub fn reconstruct_bulletproofs_proof(proof_bytes: &[u8], commitment: &[u8]) -> Vec<u8> {
    let mut backend_proof = Vec::with_capacity(4 + proof_bytes.len() + 4 + 32);
    backend_proof.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    backend_proof.extend_from_slice(proof_bytes);
    backend_proof.extend_from_slice(&(32u32).to_le_bytes());
    backend_proof.extend_from_slice(commitment);
    backend_proof
}

/// Create a new proof with the given scheme and components
pub fn create_proof(scheme_id: u8, proof_bytes: Vec<u8>, commitment: Vec<u8>) -> Vec<u8> {
    Proof::new(scheme_id, proof_bytes, commitment).to_bytes()
}

/// Deserialize `[u32 set_len][u64 * set_len]` from the start of `data`, returning the set and the remaining bytes (e.g. SNARK proof).
pub fn deserialize_embedded_set_prefix(data: &[u8], max_set_len: usize) -> Option<(Vec<u64>, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let set_size = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
    if set_size == 0 || set_size > max_set_len {
        return None;
    }
    let needed = set_size.checked_mul(8)?.checked_add(4)?;
    if data.len() <= needed {
        return None;
    }
    let mut set = Vec::with_capacity(set_size);
    let mut offset = 4usize;
    for _ in 0..set_size {
        let val_bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
        set.push(u64::from_le_bytes(val_bytes));
        offset += 8;
    }
    Some((set, &data[needed..]))
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
            // New format: [min:8][max:8][n_bits:4][...] — minimum 20 bytes
            if proof.proof.len() < 20 || proof.commitment.len() != 32 {
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
            // New format: [threshold:8][n_bits:4][...] — minimum 12 bytes
            if proof.proof.len() < 12 || proof.commitment.len() != 32 {
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
            if proof.commitment.len() != 32 {
                return false;
            }
            let (set, snark_bytes) = match deserialize_embedded_set_prefix(&proof.proof, MAX_SET_SIZE)
            {
                Some(p) => p,
                None => return false,
            };
            if snark_bytes.is_empty() {
                return false;
            }
            SnarkBackend::verify_membership_zk(snark_bytes, &set, &proof.commitment)
        }
        5 => {
            if proof.commitment.len() != 32 || proof.proof.len() < 16 {
                return false;
            }
            let old = match proof.proof[0..8].try_into() {
                Ok(arr) => u64::from_le_bytes(arr),
                Err(_) => return false,
            };
            let new = match proof.proof[8..16].try_into() {
                Ok(arr) => u64::from_le_bytes(arr),
                Err(_) => return false,
            };
            if crate::utils::commitment::validate_improvement_commitment(
                &proof.commitment,
                old,
                new,
            )
            .is_err()
            {
                return false;
            }
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&old.to_le_bytes());
            data.extend_from_slice(&new.to_le_bytes());
            StarkBackend::verify(&proof.proof[16..], &data)
        }
        6 => {
            let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
            BulletproofsBackend::verify_consistency(&backend_proof)
        }
        _ => false,
    }
}
