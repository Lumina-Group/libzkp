//! Prove/verify round-trips for all schemes.

use libzkp::advanced::{
    benchmark_proof_generation_numeric, create_composite_proof, verify_composite_proof,
    verify_composite_proof_integrity_only,
};
use libzkp::proof::{
    consistency_proof, equality_proof, improvement_proof, range_proof, set_membership,
    threshold_proof,
};

#[test]
fn range_prove_verify() {
    let proof = range_proof::prove_range(7, 0, 10).expect("prove");
    assert!(range_proof::verify_range(proof, 0, 10));
}

#[test]
fn equality_prove_verify() {
    let proof = equality_proof::prove_equality(3, 3).expect("prove");
    assert!(equality_proof::verify_equality(proof, 3, 3));
}

#[test]
fn threshold_prove_verify() {
    let proof = threshold_proof::prove_threshold(vec![3, 4, 5], 10).expect("prove");
    assert!(threshold_proof::verify_threshold(proof, 10));
}

#[test]
fn membership_prove_verify() {
    let proof = set_membership::prove_membership(2, vec![1, 2, 3]).expect("prove");
    assert!(set_membership::verify_membership(proof, vec![1, 2, 3]));
}

#[test]
fn consistency_prove_verify() {
    let proof = consistency_proof::prove_consistency(vec![1, 2, 3]).expect("prove");
    assert!(consistency_proof::verify_consistency(proof));
}

#[test]
fn improvement_prove_verify() {
    let proof = improvement_proof::prove_improvement(1, 5).expect("prove");
    assert!(improvement_proof::verify_improvement(proof, 1));
}

#[test]
fn composite_full_and_integrity_only() {
    let a = range_proof::prove_range(5, 0, 10).unwrap();
    let bytes = create_composite_proof(vec![a]).expect("composite");
    assert!(verify_composite_proof(bytes.clone()).expect("full"));
    assert!(verify_composite_proof_integrity_only(bytes).expect("integrity"));
}

#[test]
fn benchmark_numeric_smoke() {
    let m = benchmark_proof_generation_numeric("range".to_string(), 2).expect("bench");
    assert!(m.contains_key("avg_time_ms"));
}
