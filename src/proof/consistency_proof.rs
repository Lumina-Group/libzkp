use crate::backend::bulletproofs::BulletproofsBackend;
use crate::utils::error_handling::ZkpResult;
use crate::utils::proof_helpers::{
    create_proof, extract_bulletproofs_components, parse_and_validate_proof,
    reconstruct_bulletproofs_proof,
};
use crate::utils::validation::validate_consistency_params;

const SCHEME_ID: u8 = 6;

pub fn prove_consistency(data: Vec<u64>) -> ZkpResult<Vec<u8>> {
    validate_consistency_params(&data)?;

    let backend_proof = BulletproofsBackend::prove_consistency(data)
        .map_err(|e| crate::utils::error_handling::ZkpError::InvalidInput(e))?;

    let (proof_bytes, commitment) = extract_bulletproofs_components(&backend_proof)?;

    create_proof(SCHEME_ID, proof_bytes, commitment)
}

pub fn verify_consistency(proof: Vec<u8>) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);
    BulletproofsBackend::verify_consistency(&backend_proof)
}
