use crate::backend::snark::SnarkBackend;
use crate::proof::Proof;
use crate::utils::commitment::commit_value_snark;
use crate::utils::error_handling::ZkpResult;
use crate::utils::proof_helpers::{parse_and_validate_proof, validate_standard_commitment};
use crate::utils::validation::validate_equality_params;

const SCHEME_ID: u8 = 2;

pub fn prove_equality(val1: u64, val2: u64) -> ZkpResult<Vec<u8>> {
    validate_equality_params(val1, val2)?;

    let commitment = commit_value_snark(val1);
    let commitment_arr: [u8; 32] = commitment.clone().try_into().map_err(|_| {
        crate::utils::error_handling::ZkpError::InvalidProofFormat(
            "invalid commitment size".to_string(),
        )
    })?;

    let snark_proof = SnarkBackend::prove_equality_zk(val1, val2, commitment_arr);

    if snark_proof.is_empty() {
        return Err(crate::utils::error_handling::ZkpError::ProofGenerationFailed(
            "SNARK proof generation failed".to_string(),
        ));
    }

    let proof = Proof::new(SCHEME_ID, snark_proof, commitment);
    Ok(proof.to_bytes())
}

fn verify_equality_inner(proof: Vec<u8>, expected_commitment: Vec<u8>) -> bool {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return false,
    };

    if validate_standard_commitment(&expected_commitment).is_err() {
        return false;
    }
    if proof.commitment != expected_commitment {
        return false;
    }

    SnarkBackend::verify_equality_zk(&proof.proof, &expected_commitment)
}

pub fn verify_equality(proof: Vec<u8>, val1: u64, val2: u64) -> bool {
    if val1 != val2 {
        return false;
    }

    let expected_commitment = commit_value_snark(val1);
    verify_equality_inner(proof, expected_commitment)
}

pub fn verify_equality_with_commitment(proof: Vec<u8>, expected_commitment: Vec<u8>) -> bool {
    verify_equality_inner(proof, expected_commitment)
}
