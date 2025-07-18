use pyo3::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

#[pyfunction]
pub fn prove_consistency(values: Vec<u64>) -> PyResult<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, values.len()); // Max bit length for generators, and number of proofs

    let mut proofs = Vec::new();
    let mut commitments = Vec::new();

    for value in values {
        let mut rng = thread_rng();
        let mut prover_transcript = Transcript::new(b"ConsistencyProof");
        let blinding = Scalar::random(&mut rng);

        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            value,
            &blinding,
            64, // n_bits = 64 for proving any u64 value
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

        proofs.push(proof.to_bytes());
        commitments.push(committed_value.to_bytes().to_vec());
    }

    Ok((proofs, commitments))
}

#[pyfunction]
pub fn verify_consistency(proof_bytes_list: Vec<Vec<u8>>, commitment_bytes_list: Vec<Vec<u8>>, values: Vec<u64>) -> PyResult<bool> {
    if proof_bytes_list.len() != commitment_bytes_list.len() || proof_bytes_list.len() != values.len() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Mismatched lengths of proofs, commitments, and values"));
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, values.len()); // Max bit length for generators, and number of proofs

    for i in 0..proof_bytes_list.len() {
        let proof = match RangeProof::from_bytes(&proof_bytes_list[i]) {
            Ok(p) => p,
            Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())),
        };
        
        let commitment = match CompressedRistretto::from_slice(&commitment_bytes_list[i]) {
            Ok(c) => c,
            Err(_) => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid commitment bytes")),
        };

        let mut verifier_transcript = Transcript::new(b"ConsistencyProof");

        let result = proof.verify_single(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &commitment,
            64, // n_bits = 64
        );

        if result.is_err() {
            return Ok(false);
        }
    }

    Ok(true)
}