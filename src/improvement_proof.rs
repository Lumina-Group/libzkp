use crate::backend::{stark::StarkBackend, ZkpBackend};
use crate::proof::{Proof, PROOF_VERSION};
use pyo3::prelude::*;

const SCHEME_ID: u8 = 5;

#[pyfunction]
pub fn prove_improvement(old: u64, new: u64) -> PyResult<Vec<u8>> {
    if new <= old {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "no improvement",
        ));
    }

    let diff = new - old;

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    let stark_proof = StarkBackend::prove(&data);

    if stark_proof.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "STARK proof generation failed",
        ));
    }

    let mut commitment = Vec::new();
    commitment.extend_from_slice(&diff.to_le_bytes());
    commitment.extend_from_slice(&new.to_le_bytes());

    let proof = Proof::new(SCHEME_ID, stark_proof, commitment);
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_improvement(proof: Vec<u8>, old: u64) -> PyResult<bool> {
    let proof = match Proof::from_bytes(&proof) {
        Some(p) => p,
        None => return Ok(false),
    };

    if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
        return Ok(false);
    }

    if proof.commitment.len() != 16 {
        return Ok(false);
    }

    let diff = u64::from_le_bytes(proof.commitment[0..8].try_into().unwrap());
    let new = u64::from_le_bytes(proof.commitment[8..16].try_into().unwrap());

    if diff == 0 {
        return Ok(false);
    }

    if new != old + diff {
        return Ok(false);
    }

    let mut data = Vec::new();
    data.extend_from_slice(&old.to_le_bytes());
    data.extend_from_slice(&new.to_le_bytes());

    Ok(StarkBackend::verify(&proof.proof, &data))
}
