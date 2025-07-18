use libzkp::range_proof::*;

#[test]
fn test_range() {
    let proof = prove_range(10, 0, 20).unwrap();
    assert!(verify_range(proof, 0, 20).unwrap());
}

use libzkp::equality_proof::*;

#[test]
fn test_equality() {
    let proof = prove_equality(5, 5).unwrap();
    assert!(verify_equality(proof, 5, 5).unwrap());
}

use libzkp::threshold_proof::*;

#[test]
fn test_threshold() {
    let proof = prove_threshold(vec![1, 2, 3], 5).unwrap();
    assert!(verify_threshold(proof, 5).unwrap());
}

use libzkp::set_membership::*;

#[test]
fn test_membership() {
    let proof = prove_membership(3, vec![1, 2, 3]).unwrap();
    assert!(verify_membership(proof, vec![1, 2, 3]).unwrap());
}

use libzkp::improvement_proof::*;

#[test]
fn test_improvement() {
    let proof = prove_improvement(1, 8).unwrap();
    assert!(verify_improvement(proof, 1).unwrap());
}

use libzkp::consistency_proof::*;

#[test]
fn test_consistency() {
    let proof = prove_consistency(vec![1, 2, 3]).unwrap();
    assert!(verify_consistency(proof).unwrap());
}
