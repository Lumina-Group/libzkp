use pyo3::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

#[pyfunction]
pub fn prove_range(value: u64, min: u64, max: u64) -> PyResult<(Vec<u8>, Vec<u8>)> {
    if min > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("min cannot be greater than max"));
    }
    if value < min || value > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("value is outside the specified range [min, max]"));
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1); // Max bit length for generators

    let mut rng = thread_rng();
    let mut prover_transcript = Transcript::new(b"RangeProofDemo");

    let blinding = Scalar::random(&mut rng);

    let adjusted_value = value - min;
    let range_diff = max - min;

    let n_bits = if range_diff == 0 {
        1 // For a single point, we need at least 1 bit to represent 0
    } else {
        // Smallest n such that 2^n >= range_diff + 1
        (range_diff + 1).checked_next_power_of_two().unwrap_or(1).trailing_zeros() as u8
    };

    if n_bits > 64 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Range too large for 64-bit proof"));
    }

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        adjusted_value,
        &blinding,
        n_bits as usize, // Use calculated n_bits
    ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    Ok((proof.to_bytes(), committed_value.to_bytes().to_vec()))
}

#[pyfunction]
pub fn verify_range(proof_bytes: Vec<u8>, commitment_bytes: Vec<u8>, min: u64, max: u64) -> PyResult<bool> {
    if min > max {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("min cannot be greater than max"));
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
    let bp_gens = BulletproofGens::new(64, 1); // Max bit length for generators

    let mut verifier_transcript = Transcript::new(b"RangeProofDemo");

    let range_diff = max - min;
    let n_bits = if range_diff == 0 {
        1 // For a single point, we need at least 1 bit to represent 0
    } else {
        // Smallest n such that 2^n >= range_diff + 1
        (range_diff + 1).checked_next_power_of_two().unwrap_or(1).trailing_zeros() as u8
    };

    if n_bits > 64 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Range too large for 64-bit proof"));
    }
    
    let result = proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &commitment,
        n_bits as usize, // Use calculated n_bits
    );

    Ok(result.is_ok())
}