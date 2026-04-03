use crate::backend::bulletproofs::BulletproofsBackend;
use crate::utils::error_handling::ZkpResult;
use crate::utils::proof_helpers::{
    create_proof, extract_bulletproofs_components, parse_and_validate_proof,
    reconstruct_bulletproofs_proof, validate_standard_commitment,
};

const SCHEME_ID: u8 = 3;

pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> ZkpResult<Vec<u8>> {
    let backend_proof = BulletproofsBackend::prove_threshold(values, threshold)
        .map_err(|e| crate::utils::error_handling::ZkpError::InvalidInput(e))?;

    let (proof_bytes, commitment) = extract_bulletproofs_components(&backend_proof)?;

    create_proof(SCHEME_ID, proof_bytes, commitment)
}

pub fn verify_threshold(proof: Vec<u8>, threshold: u64) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if validate_standard_commitment(&proof.commitment).is_err() {
        return false;
    }

    let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
    BulletproofsBackend::verify_threshold(&backend_proof, threshold)
}
