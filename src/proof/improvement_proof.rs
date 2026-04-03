use crate::backend::{stark::StarkBackend, ZkpBackend};
use crate::proof::Proof;
use crate::utils::commitment::{commit_improvement, validate_improvement_commitment};
use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::proof_helpers::parse_and_validate_proof;
use crate::utils::validation::validate_improvement_params;

const SCHEME_ID: u8 = 5;

pub fn prove_improvement(old: u64, new: u64) -> ZkpResult<Vec<u8>> {
    validate_improvement_params(old, new)?;

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    let stark_proof = StarkBackend::prove(&data);

    if stark_proof.is_empty() {
        return Err(ZkpError::ProofGenerationFailed(
            "STARK proof generation failed".to_string(),
        ));
    }

    let commitment = commit_improvement(old, new)?;

    // Prefix `old` and `new` for verification (including composite cryptographic checks).
    let mut payload = Vec::with_capacity(16 + stark_proof.len());
    payload.extend_from_slice(&old.to_le_bytes());
    payload.extend_from_slice(&new.to_le_bytes());
    payload.extend_from_slice(&stark_proof);

    let proof = Proof::new(SCHEME_ID, payload, commitment);
    Ok(proof.to_bytes())
}

pub fn verify_improvement(proof: Vec<u8>, old: u64) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if proof.proof.len() < 16 {
        return false;
    }
    let stored_old = match proof.proof[0..8].try_into() {
        Ok(arr) => u64::from_le_bytes(arr),
        Err(_) => return false,
    };
    if stored_old != old {
        return false;
    }
    let new = match proof.proof[8..16].try_into() {
        Ok(arr) => u64::from_le_bytes(arr),
        Err(_) => return false,
    };

    if validate_improvement_commitment(&proof.commitment, old, new).is_err() {
        return false;
    }

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    StarkBackend::verify(&proof.proof[16..], &data)
}
