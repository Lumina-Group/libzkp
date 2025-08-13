use crate::backend::{snark::SnarkBackend, ZkpBackend};
use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

const SCHEME_ID: u8 = 2;

#[pyfunction]
pub fn prove_equality(val1: u64, val2: u64) -> PyResult<Vec<u8>> {
    if val1 != val2 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "values are not equal",
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(&val1.to_le_bytes());
    let commitment = hasher.finalize().to_vec();

    let mut data = Vec::new();
    data.extend_from_slice(&val1.to_le_bytes());
    data.extend_from_slice(&val2.to_le_bytes());
    data.extend_from_slice(&commitment);

    let snark_proof = SnarkBackend::prove(&data);

    if snark_proof.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "SNARK proof generation failed",
        ));
    }

    let proof = Proof::new(SCHEME_ID, snark_proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_equality(proof: Vec<u8>, val1: u64, val2: u64) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };

    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }

    if val1 != val2 {
        return Ok(false);
    }

    // Generate expected commitment
    let mut hasher = Sha256::new();
    hasher.update(&val1.to_le_bytes());
    let expected_commitment = hasher.finalize().to_vec();

    if proof.commitment != expected_commitment {
        return Ok(false);
    }

    Ok(SnarkBackend::verify(&proof.proof, &expected_commitment))
}

#[pyfunction]
pub fn verify_equality_with_commitment(proof: Vec<u8>, expected_commitment: Vec<u8>) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };

    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }

    if expected_commitment.len() != 32 {
        return Ok(false);
    }

    if proof.commitment != expected_commitment {
        return Ok(false);
    }

    Ok(SnarkBackend::verify(&proof.proof, &expected_commitment))
}

fn hash_string(_s: &str) -> u64 {
    // No longer used; keep for potential future compatibility
    let mut hasher = Sha256::new();
    hasher.update(_s.as_bytes());
    let result = hasher.finalize();

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[..8]);
    u64::from_le_bytes(bytes)
}
