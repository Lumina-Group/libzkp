use crate::backend::bulletproofs::BulletproofsBackend;
use crate::utils::{
    error_handling::{ZkpError, ZkpResult},
    proof_helpers::{create_proof, extract_bulletproofs_components},
    validation::validate_range_params,
};

const SCHEME_ID: u8 = 1;

pub fn prove_range(value: u64, min: u64, max: u64) -> ZkpResult<Vec<u8>> {
    prove_range_with_bits(value, min, max, 64)
}

/// Range proof with configurable Bulletproofs bit-width (e.g. 8 for values in [0, 255]).
/// Use 8 when `value - min` and `max - value` both fit in n_bits (i.e., < 2^n_bits).
pub fn prove_range_with_bits(value: u64, min: u64, max: u64, n_bits: usize) -> ZkpResult<Vec<u8>> {
    validate_range_params(value, min, max)?;

    let backend_proof = BulletproofsBackend::prove_range_with_bounds_bits(value, min, max, n_bits)
        .map_err(|e| ZkpError::BackendError(e))?;

    let (proof_bytes, commitment) = extract_bulletproofs_components(&backend_proof)?;

    Ok(create_proof(SCHEME_ID, proof_bytes, commitment))
}

pub fn verify_range(proof: Vec<u8>, min: u64, max: u64) -> bool {
    use crate::utils::proof_helpers::{
        parse_and_validate_proof, reconstruct_bulletproofs_proof, validate_standard_commitment,
    };

    if min > max {
        return false;
    }

    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if validate_standard_commitment(&proof.commitment).is_err() {
        return false;
    }

    let backend_proof = reconstruct_bulletproofs_proof(&proof.proof, &proof.commitment);

    BulletproofsBackend::verify_range_with_bounds(&backend_proof, min, max)
}
