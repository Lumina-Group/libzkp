use pyo3::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

#[pyfunction]
pub fn prove_threshold(value: u64, threshold: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if value < threshold {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Value is less than threshold, cannot prove threshold"));
    }

    let value_to_prove = value - threshold;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1); // Max bit length for generators

    let mut rng = thread_rng();
    let mut prover_transcript = Transcript::new(b"ThresholdProof");

    let blinding = Scalar::random(&mut rng);

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        value_to_prove,
        &blinding,
        64, // n_bits = 64 for proving non-negativity
    ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((proof.to_bytes(), committed_value.to_bytes().to_vec()))
}

#[pyfunction]
pub fn verify_threshold(proof_bytes: Vec<u8>, commitment_bytes: Vec<u8>, threshold: u64) -> PyResult<bool> {
    let proof = match RangeProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())),
    };
    
    let commitment = match CompressedRistretto::from_slice(&commitment_bytes) {
        Ok(c) => c,
        Err(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid commitment bytes")),
    };

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1); // Max bit length for generators

    let mut verifier_transcript = Transcript::new(b"ThresholdProof");

    let result = proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &commitment,
        64, // n_bits = 64
    );

    Ok(result.is_ok())
}