
use crate::backend::snark::SnarkBackend;
use crate::proof::{Proof, PROOF_VERSION};
use crate::utils::commitment::commit_value;
use pyo3::prelude::*;

const SCHEME_ID: u8 = 4;

#[pyfunction]
pub fn prove_membership(value: u64, set: Vec<u64>) -> PyResult<Vec<u8>> {
	if set.is_empty() {
		return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
			"set cannot be empty",
		));
	}

	let commitment = commit_value(value);
	let commitment_arr: [u8; 32] = commitment
		.clone()
		.try_into()
		.map_err(|_| PyErr::new::<pyo3::exceptions::PyTypeError, _>(
			"invalid commitment size",
		))?;

	let snark_proof = SnarkBackend::prove_membership_zk(value, set.clone(), commitment_arr);
	if snark_proof.is_empty() {
		return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
			"SNARK membership proof generation failed",
		));
	}

	// Embed set into proof payload for parallel verification and auditability
	let mut payload = Vec::with_capacity(4 + set.len() * 8 + snark_proof.len());
	payload.extend_from_slice(&(set.len() as u32).to_le_bytes());
	for v in &set {
		payload.extend_from_slice(&v.to_le_bytes());
	}
	payload.extend_from_slice(&snark_proof);

	let proof = Proof::new(SCHEME_ID, payload, commitment);
	Ok(proof.to_bytes())
}

#[pyfunction]
pub fn verify_membership(proof: Vec<u8>, set: Vec<u64>) -> PyResult<bool> {
	let proof = match Proof::from_bytes(&proof) {
		Some(p) => p,
		None => return Ok(false),
	};

	if proof.version != PROOF_VERSION || proof.scheme != SCHEME_ID {
		return Ok(false);
	}

	if proof.commitment.len() != 32 {
		return Ok(false);
	}

	// Parse embedded set and SNARK proof
	if proof.proof.len() < 4 {
		return Ok(false);
	}
	let set_size = u32::from_le_bytes(proof.proof[0..4].try_into().unwrap()) as usize;
	let needed = 4 + set_size * 8;
	if proof.proof.len() <= needed {
		return Ok(false);
	}
	let mut embedded_set = Vec::with_capacity(set_size);
	let mut offset = 4;
	for _ in 0..set_size {
		let val = u64::from_le_bytes(proof.proof[offset..offset+8].try_into().unwrap());
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

	Ok(SnarkBackend::verify_membership_zk(snark_bytes, &embedded_set, &proof.commitment))
}
