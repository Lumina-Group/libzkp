use crate::backend::snark::{SnarkBackend, MAX_SET_SIZE};
use crate::proof::Proof;
use crate::utils::commitment::commit_value;
use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::proof_helpers::{parse_and_validate_proof, validate_standard_commitment};
use crate::utils::validation::{validate_membership_params, validate_set_size};

const SCHEME_ID: u8 = 4;

pub fn prove_membership(value: u64, set: Vec<u64>) -> ZkpResult<Vec<u8>> {
    validate_membership_params(value, &set)?;
    validate_set_size(&set, MAX_SET_SIZE)?;

    let commitment = commit_value(value);
    let commitment_arr: [u8; 32] = commitment
        .clone()
        .try_into()
        .map_err(|_| ZkpError::InvalidProofFormat("invalid commitment size".to_string()))?;

    let snark_proof = SnarkBackend::prove_membership_zk(value, set.clone(), commitment_arr);
    if snark_proof.is_empty() {
        return Err(ZkpError::ProofGenerationFailed(
            "SNARK membership proof generation failed".to_string(),
        ));
    }

    let mut payload = Vec::with_capacity(4 + set.len() * 8 + snark_proof.len());
    payload.extend_from_slice(&(set.len() as u32).to_le_bytes());
    for v in &set {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    payload.extend_from_slice(&snark_proof);

    let proof = Proof::new(SCHEME_ID, payload, commitment);
    Ok(proof.to_bytes())
}

pub fn verify_membership(proof: Vec<u8>, set: Vec<u64>) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if validate_standard_commitment(&proof.commitment).is_err() {
        return false;
    }

    if proof.proof.len() < 4 {
        return false;
    }
    let set_size_bytes: [u8; 4] = match proof.proof[0..4].try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let set_size = u32::from_le_bytes(set_size_bytes) as usize;
    let needed = match set_size.checked_mul(8).and_then(|v| v.checked_add(4)) {
        Some(n) => n,
        None => return false,
    };
    if proof.proof.len() <= needed {
        return false;
    }
    let mut embedded_set = Vec::with_capacity(set_size);
    let mut offset = 4;
    for _ in 0..set_size {
        let val_bytes: [u8; 8] = match proof.proof.get(offset..offset + 8) {
            Some(slice) => match slice.try_into() {
                Ok(arr) => arr,
                Err(_) => return false,
            },
            None => return false,
        };
        let val = u64::from_le_bytes(val_bytes);
        embedded_set.push(val);
        offset += 8;
    }
    let snark_bytes = &proof.proof[needed..];

    if set.len() != embedded_set.len() {
        return false;
    }
    let mut a = set.clone();
    let mut b = embedded_set.clone();
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        return false;
    }

    SnarkBackend::verify_membership_zk(snark_bytes, &embedded_set, &proof.commitment)
}
