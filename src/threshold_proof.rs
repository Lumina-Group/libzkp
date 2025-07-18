use crate::proof::{Proof, PROOF_VERSION};
use crate::utils::{pedersen_commit, pedersen_commit_with_blind};
use curve25519_dalek::scalar::Scalar;
use pyo3::prelude::*;

const SCHEME_ID: u8 = 3;

#[pyfunction]
pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> PyResult<Vec<u8>> {
    let sum: u64 = values.iter().sum();
    if sum < threshold {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "threshold not met",
        ));
    }
    let (commit, blind) = pedersen_commit(sum);
    let mut proof_bytes = Vec::with_capacity(8 + 32);
    proof_bytes.extend_from_slice(&sum.to_le_bytes());
    proof_bytes.extend_from_slice(&blind.to_bytes());
    let proof = Proof::new(SCHEME_ID, proof_bytes, commit.as_bytes().to_vec());
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_threshold(proof: Vec<u8>, threshold: u64) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };
    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }
    if proof.commitment.len() != 32 || proof.proof.len() != 40 {
        return Ok(false);
    }
    let sum = u64::from_le_bytes(proof.proof[0..8].try_into().unwrap());
    if sum < threshold {
        return Ok(false);
    }
    let blind_ct = Scalar::from_canonical_bytes(proof.proof[8..40].try_into().unwrap());
    if blind_ct.is_none().into() {
        return Ok(false);
    }
    let blind = blind_ct.unwrap();
    let commit = pedersen_commit_with_blind(sum, blind);
    Ok(commit.as_bytes() == proof.commitment.as_slice())
}
