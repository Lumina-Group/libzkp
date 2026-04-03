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

    let proof = Proof::new(SCHEME_ID, stark_proof, commitment);
    Ok(proof.to_bytes())
}

pub fn verify_improvement(proof: Vec<u8>, old: u64) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let new = match validate_improvement_commitment(&proof.commitment, old) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    StarkBackend::verify(&proof.proof, &data)
}
