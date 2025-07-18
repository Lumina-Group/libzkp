use libzkp::range_proof::*;

#[test]
fn test_range() {
    let (proof, comm) = prove_range(10, 0, 20).unwrap();
    assert!(verify_range(proof, comm, 0, 20).unwrap());
}

use libzkp::equality_proof::*;

#[test]
fn test_equality() {
    let (proof, comm) = prove_equality(5, 5).unwrap();
    assert!(verify_equality(proof, comm, 5, 5).unwrap());
}

use libzkp::threshold_proof::*;

#[test]
fn test_threshold() {
    let (proof, comm) = prove_threshold(vec![1, 2, 3], 5).unwrap();
    assert!(verify_threshold(proof, comm, 5).unwrap());
}

use libzkp::set_membership::*;

#[test]
fn test_membership() {
    let (proof, comm) = prove_membership(3, vec![1, 2, 3]).unwrap();
    assert!(verify_membership(proof, comm, vec![1, 2, 3]).unwrap());
}

use libzkp::improvement_proof::*;

#[test]
fn test_improvement() {
    let (proof, comm) = prove_improvement(1, 2).unwrap();
    assert!(verify_improvement(proof, comm, 1).unwrap());
}

use libzkp::consistency_proof::*;

#[test]
fn test_consistency() {
    let (proof, comm) = prove_consistency(vec![1, 2, 3]).unwrap();
    assert!(verify_consistency(proof, comm).unwrap());
}
