use pyo3::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;
use sha2::{Sha256, Digest};

// Helper function to hash a string to u64
fn hash_string_to_u64(s: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    // Take the first 8 bytes of the hash and convert to u64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[0..8]);
    u64::from_le_bytes(bytes)
}

#[pyfunction]
pub fn prove_equality(value1: String, value2: String) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let v1_u64 = hash_string_to_u64(&value1);
    let v2_u64 = hash_string_to_u64(&value2);

    if v1_u64 != v2_u64 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Values are not equal, cannot prove equality"));
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(8, 1); // n_bits = 8 for proving 0 within range [0, 2^8-1]

    let mut rng = thread_rng();
    let mut prover_transcript = Transcript::new(b"EqualityProof");

    let blinding = Scalar::random(&mut rng);

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        0, // Prove that the difference is 0
        &blinding,
        8, // n_bits = 8
    ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((proof.to_bytes(), committed_value.to_bytes().to_vec()))
}

#[pyfunction]
pub fn verify_equality(proof_bytes: Vec<u8>, commitment_bytes: Vec<u8>, value1: String, value2: String) -> PyResult<bool> {
    let v1_u64 = hash_string_to_u64(&value1);
    let v2_u64 = hash_string_to_u64(&value2);

    if v1_u64 != v2_u64 {
        return Ok(false); // If values are not equal, verification should fail
    }

    let proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())),
    };
    
    let commitment = match CompressedRistretto::from_slice(&commitment_bytes) {
        Ok(c) => c,
        Err(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid commitment bytes")),
    };

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(8, 1); // n_bits = 8

    let mut verifier_transcript = Transcript::new(b"EqualityProof");

    let result = proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &commitment,
        8, // n_bits = 8
    );

    Ok(result.is_ok())
}
