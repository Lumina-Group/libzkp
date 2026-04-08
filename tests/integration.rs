//! Prove/verify round-trips for all schemes.

use libzkp::advanced::{
    benchmark_proof_generation_numeric, create_composite_proof, verify_composite_proof,
    verify_composite_proof_integrity_only,
};
use libzkp::proof::{
    consistency_proof, equality_proof, improvement_proof, range_proof, set_membership,
    threshold_proof,
};
use libzkp::utils::commitment::commit_value_snark;

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
fn equality_verify_with_snark_commitment_roundtrip() {
    let proof = equality_proof::prove_equality(42, 42).expect("prove");
    let expected = commit_value_snark(42);
    assert!(equality_proof::verify_equality_with_commitment(
        proof, expected
    ));
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

#[test]
fn range_prove_rejects_out_of_range() {
    assert!(range_proof::prove_range(100, 0, 10).is_err());
}

#[test]
fn verify_rejects_tampered_range_proof() {
    let mut proof = range_proof::prove_range(7, 0, 10).expect("prove");
    if proof.len() > 12 {
        proof[12] ^= 0xFF;
    }
    assert!(!range_proof::verify_range(proof, 0, 10));
}

#[test]
fn equality_verify_rejects_mismatched_public_values() {
    let proof = equality_proof::prove_equality(3, 3).expect("prove");
    assert!(!equality_proof::verify_equality(proof, 3, 4));
}

#[test]
fn composite_rejects_trailing_bytes() {
    let a = range_proof::prove_range(5, 0, 10).unwrap();
    let mut bytes = create_composite_proof(vec![a]).expect("composite");
    bytes.push(0x01);
    assert!(verify_composite_proof(bytes).is_err());
}

#[cfg(feature = "batch-store")]
mod batch_store_tests {
    use std::sync::Mutex;

    use libzkp::advanced::batch_store::{
        get_batch_store_dir, set_batch_store_dir, write_batch_file,
    };
    use libzkp::advanced::{
        batch_add_range_proof, create_proof_batch, get_batch_status, open_batch_from_store,
        refresh_batch_from_store,
    };
    use libzkp::utils::composition::ProofBatch;

    /// `set_batch_store_dir` is process-global; serialize batch-store tests.
    static BATCH_STORE_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn persist_add_and_refresh() {
        let _guard = BATCH_STORE_TEST_LOCK.lock().expect("batch store test lock");
        let dir = std::env::temp_dir().join(format!("libzkp_bs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_batch_store_dir(&dir).unwrap();
        assert_eq!(get_batch_store_dir().unwrap(), dir);

        let id = create_proof_batch().unwrap();
        batch_add_range_proof(id, 5, 0, 10).unwrap();
        let s = get_batch_status(id).unwrap();
        assert_eq!(s["total_operations"], 1);

        refresh_batch_from_store(id).unwrap();
        let s2 = get_batch_status(id).unwrap();
        assert_eq!(s2["total_operations"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_batch_from_disk() {
        let _guard = BATCH_STORE_TEST_LOCK.lock().expect("batch store test lock");
        let dir = std::env::temp_dir().join(format!("libzkp_bs2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_batch_store_dir(&dir).unwrap();

        let mut b = ProofBatch::new();
        b.add_range_proof(7, 1, 20);
        write_batch_file(&dir, 0xdeadbeefcafeu64, &b).unwrap();

        open_batch_from_store(0xdeadbeefcafeu64).unwrap();
        let st = get_batch_status(0xdeadbeefcafeu64).unwrap();
        assert_eq!(st["total_operations"], 1);
        assert_eq!(st["range_proofs"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
