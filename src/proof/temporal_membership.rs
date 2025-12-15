use crate::backend::snark::{SnarkBackend, MAX_SET_SIZE};
use crate::proof::Proof;
use crate::utils::proof_helpers::parse_and_validate_proof;
use pyo3::prelude::*;

const SCHEME_ID: u8 = 7;

#[pyfunction]
pub fn prove_temporal_membership(code: Vec<u8>, set: Vec<u64>) -> PyResult<Vec<u8>> {
    if code.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "code must be 32 bytes",
        ));
    }
    if set.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "set cannot be empty",
        ));
    }
    if set.len() > MAX_SET_SIZE {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "set too large: max {}",
            MAX_SET_SIZE
        )));
    }

    let code_arr: [u8; 32] = code
        .try_into()
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("invalid code size"))?;

    let snark_proof = SnarkBackend::prove_temporal_membership_zk(code_arr, set.clone());
    if snark_proof.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            "SNARK temporal membership proof generation failed",
        ));
    }

    // Embed set into proof payload for auditability and consistent verification
    let mut payload = Vec::with_capacity(4 + set.len() * 8 + snark_proof.len());
    payload.extend_from_slice(&(set.len() as u32).to_le_bytes());
    for v in &set {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    payload.extend_from_slice(&snark_proof);

    // No public commitment is required; keep this empty to avoid linkability.
    let proof = Proof::new(SCHEME_ID, payload, Vec::new());
    Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_temporal_membership(proof: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
    let proof = match parse_and_validate_proof(&proof, SCHEME_ID) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    // commitment is intentionally empty for this scheme
    if !proof.commitment.is_empty() {
        return Ok(false);
    }

    // Parse embedded set and SNARK proof
    if proof.proof.len() < 4 {
        return Ok(false);
    }
    let set_size_bytes: [u8; 4] = match proof.proof[0..4].try_into() {
        Ok(arr) => arr,
        Err(_) => return Ok(false),
    };
    let set_size = u32::from_le_bytes(set_size_bytes) as usize;
    if set_size == 0 || set_size > MAX_SET_SIZE {
        return Ok(false);
    }
    let needed = match set_size.checked_mul(8).and_then(|v| v.checked_add(4)) {
        Some(n) => n,
        None => return Ok(false),
    };
    if proof.proof.len() <= needed {
        return Ok(false);
    }

    let mut embedded_set = Vec::with_capacity(set_size);
    let mut offset = 4;
    for _ in 0..set_size {
        let val_bytes: [u8; 8] = match proof.proof.get(offset..offset + 8) {
            Some(slice) => match slice.try_into() {
                Ok(arr) => arr,
                Err(_) => return Ok(false),
            },
            None => return Ok(false),
        };
        let val = u64::from_le_bytes(val_bytes);
        embedded_set.push(val);
        offset += 8;
    }
    let snark_bytes = &proof.proof[needed..];

    // Optional: Check provided set matches embedded set (as a set)
    if set.len() != embedded_set.len() {
        return Ok(false);
    }
    let mut a = set.clone();
    let mut b = embedded_set.clone();
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        return Ok(false);
    }

    Ok(SnarkBackend::verify_temporal_membership_zk(
        snark_bytes,
        &embedded_set,
    ))
}

