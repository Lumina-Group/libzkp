use wasm_bindgen::prelude::*;

use crate::proof::range_proof;
use crate::proof::set_membership;
use crate::proof::threshold_proof;
use crate::utils::commitment;
use crate::utils::performance::{generate_cache_key, get_global_cache};

#[wasm_bindgen]
pub fn prove_range_wasm(value: u64, min: u64, max: u64) -> Result<Vec<u8>, JsError> {
    range_proof::prove_range(value, min, max).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_range_wasm(proof: &[u8], min: u64, max: u64) -> bool {
    range_proof::verify_range(proof.to_vec(), min, max)
}

#[wasm_bindgen]
pub fn prove_membership_wasm(value: u64, set: &[u64]) -> Result<Vec<u8>, JsError> {
    set_membership::prove_membership(value, set.to_vec()).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_membership_wasm(proof: &[u8], set: &[u64]) -> bool {
    set_membership::verify_membership(proof.to_vec(), set.to_vec())
}

#[wasm_bindgen]
pub fn prove_threshold_wasm(values: &[u64], threshold: u64) -> Result<Vec<u8>, JsError> {
    threshold_proof::prove_threshold(values.to_vec(), threshold)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_threshold_wasm(proof: &[u8], threshold: u64) -> bool {
    threshold_proof::verify_threshold(proof.to_vec(), threshold)
}

#[wasm_bindgen]
pub fn commit_value_wasm(value: u64) -> Vec<u8> {
    commitment::commit_value(value)
}

#[wasm_bindgen]
pub fn commit_with_context_wasm(values: &[u64], context: &[u8]) -> Vec<u8> {
    commitment::commit_with_context(values, context)
}

#[wasm_bindgen]
pub fn create_composite_proof_wasm(
    proofs_flat: &[u8],
    lengths: &[u32],
) -> Result<Vec<u8>, JsError> {
    let mut proof_list = Vec::new();
    let mut offset = 0usize;
    for &len in lengths {
        let len = len as usize;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| JsError::new("overflow"))?;
        if end > proofs_flat.len() {
            return Err(JsError::new("proof data out of bounds"));
        }
        proof_list.push(proofs_flat[offset..end].to_vec());
        offset = end;
    }
    crate::advanced::composite::create_composite_proof(proof_list)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_composite_proof_wasm(data: &[u8]) -> Result<bool, JsError> {
    crate::advanced::composite::verify_composite_proof(data.to_vec())
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn cache_get_wasm(key: &str) -> Option<Vec<u8>> {
    get_global_cache().get(key)
}

#[wasm_bindgen]
pub fn cache_put_wasm(key: &str, data: &[u8]) {
    get_global_cache().put(key.to_string(), data.to_vec());
}

#[wasm_bindgen]
pub fn cache_clear_wasm() {
    get_global_cache().clear();
}

#[wasm_bindgen]
pub fn generate_cache_key_wasm(operation: &str, params: &[u8]) -> String {
    generate_cache_key(operation, params)
}
