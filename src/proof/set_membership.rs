use crate::backend::snark::{SnarkBackend, MAX_SET_SIZE};
use crate::proof::Proof;
use crate::utils::commitment::commit_value_snark;
use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::proof_helpers::{
    deserialize_embedded_set_prefix, parse_and_validate_proof, validate_standard_commitment,
};
use crate::utils::validation::{validate_membership_params, validate_set_size};

const SCHEME_ID: u8 = 4;

pub fn prove_membership(value: u64, set: Vec<u64>) -> ZkpResult<Vec<u8>> {
    validate_membership_params(value, &set)?;
    validate_set_size(&set, MAX_SET_SIZE)?;

    let commitment = commit_value_snark(value);
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

    let (embedded_set, snark_bytes) =
        match deserialize_embedded_set_prefix(&proof.proof, MAX_SET_SIZE) {
            Some(p) => p,
            None => return false,
        };
    if snark_bytes.is_empty() {
        return false;
    }

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
