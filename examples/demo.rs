use std::collections::HashMap;
use sha2::{Digest, Sha256};

fn temporal_token_from_code(code: &[u8; 32]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(code);
    let digest = hasher.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[0..8]);
    u64::from_le_bytes(first8)
}

fn main() -> Result<(), pyo3::PyErr> {
    // Persist Groth16 keys to speed up subsequent runs.
    // Must be set BEFORE the first equality/membership proof is generated or verified.
    let _ = libzkp::advanced::set_snark_key_dir("/workspace/.libzkp_snark_keys".to_string());

    // 1) Range proof
    let range_proof = libzkp::proof::range_proof::prove_range(10, 0, 20)?;
    let range_ok = libzkp::proof::range_proof::verify_range(range_proof.clone(), 0, 20)?;
    println!("range_ok={}", range_ok);

    // 2) Equality proof (Groth16)
    let eq_proof = libzkp::proof::equality_proof::prove_equality(5, 5)?;
    let eq_ok = libzkp::proof::equality_proof::verify_equality(eq_proof.clone(), 5, 5)?;
    let commitment = libzkp::utils::commitment::commit_value(5);
    let eq_ok_commit = libzkp::proof::equality_proof::verify_equality_with_commitment(
        eq_proof.clone(),
        commitment,
    )?;
    println!("equality_ok={} equality_ok_commit={}", eq_ok, eq_ok_commit);

    // 3) Threshold proof
    let threshold_proof = libzkp::proof::threshold_proof::prove_threshold(vec![1, 2, 3], 5)?;
    let threshold_ok =
        libzkp::proof::threshold_proof::verify_threshold(threshold_proof.clone(), 5)?;
    println!("threshold_ok={}", threshold_ok);

    // 4) Set membership proof (Groth16)
    let set = vec![1, 2, 3];
    let membership_proof = libzkp::proof::set_membership::prove_membership(3, set.clone())?;
    let membership_ok =
        libzkp::proof::set_membership::verify_membership(membership_proof.clone(), set)?;
    println!("membership_ok={}", membership_ok);

    // 5) Improvement proof (STARK)
    let improvement_proof = libzkp::proof::improvement_proof::prove_improvement(1, 8)?;
    let improvement_ok =
        libzkp::proof::improvement_proof::verify_improvement(improvement_proof.clone(), 1)?;
    println!("improvement_ok={}", improvement_ok);

    // 6) Consistency proof
    let consistency_proof = libzkp::proof::consistency_proof::prove_consistency(vec![1, 2, 3])?;
    let consistency_ok =
        libzkp::proof::consistency_proof::verify_consistency(consistency_proof.clone())?;
    println!("consistency_ok={}", consistency_ok);

    // 7) Composite proof (+metadata)
    let composite = libzkp::advanced::create_composite_proof(vec![
        range_proof.clone(),
        eq_proof.clone(),
        threshold_proof.clone(),
    ])?;
    let composite_ok = libzkp::advanced::verify_composite_proof(composite.clone())?;
    println!("composite_ok={}", composite_ok);

    // Note: `create_proof_with_metadata` wraps a *single* Proof into a CompositeProof.
    let mut metadata = HashMap::new();
    metadata.insert("purpose".to_string(), b"demo".to_vec());
    metadata.insert("issued_by".to_string(), b"examples/demo.rs".to_vec());
    let proof_with_meta =
        libzkp::advanced::create_proof_with_metadata(range_proof.clone(), metadata)?;
    let extracted = libzkp::advanced::extract_proof_metadata(proof_with_meta)?;
    println!("metadata_keys={:?}", extracted.keys().collect::<Vec<_>>());

    // 8) Batch proof generation + parallel verification
    let batch_id = libzkp::advanced::create_proof_batch()?;
    libzkp::advanced::batch_add_range_proof(batch_id, 25, 18, 65)?;
    libzkp::advanced::batch_add_equality_proof(batch_id, 42, 42)?;
    libzkp::advanced::batch_add_threshold_proof(batch_id, vec![10, 20, 30], 50)?;
    libzkp::advanced::batch_add_membership_proof(batch_id, 2, vec![1, 2, 3, 4])?;
    libzkp::advanced::batch_add_improvement_proof(batch_id, 10, 11)?;
    libzkp::advanced::batch_add_consistency_proof(batch_id, vec![10, 20, 20, 30])?;

    let status = libzkp::advanced::get_batch_status(batch_id)?;
    println!("batch_status={:?}", status);

    let batch_proofs = libzkp::advanced::process_batch(batch_id)?;
    println!("batch_proofs_len={}", batch_proofs.len());

    // Note: order is preserved (operations are stored in a Vec).
    let typed = vec![
        (batch_proofs[0].clone(), "range".to_string()),
        (batch_proofs[1].clone(), "equality".to_string()),
        (batch_proofs[2].clone(), "threshold".to_string()),
        (batch_proofs[3].clone(), "membership".to_string()),
        (batch_proofs[4].clone(), "improvement".to_string()),
        (batch_proofs[5].clone(), "consistency".to_string()),
    ];

    let results = libzkp::advanced::verify_proofs_parallel(typed)?;
    println!("parallel_verify_results={:?}", results);

    // 9) Numeric benchmark (no Python objects)
    let bench = libzkp::advanced::benchmark_proof_generation_numeric("range".to_string(), 10)?;
    println!("benchmark_range={:?}", bench);

    // 10) Temporal Visual Code × ZKP (proof of observing a valid temporal code)
    //
    // Server-side conceptually:
    //   code = SHA256(session_secret || time_slot)
    //   set  = { LE_u64(SHA256(code_i)[0..8]) } for allowed time slots
    // Client proves (in ZK): "I know some 32-byte code whose token is in set"
    let session_secret = Sha256::digest(b"demo-session-secret").to_vec();
    let time_slot: u64 = 12345;
    let mut server_hasher = Sha256::new();
    server_hasher.update(&session_secret);
    server_hasher.update(&time_slot.to_le_bytes());
    let code_bytes = server_hasher.finalize();
    let code_arr: [u8; 32] = code_bytes
        .as_slice()
        .try_into()
        .expect("sha256 digest is 32 bytes");

    // Build allowed set (toy window)
    let allowed_slots = vec![12343u64, 12344u64, 12345u64, 12346u64, 12347u64];
    let mut allowed_tokens = Vec::with_capacity(allowed_slots.len());
    for t in allowed_slots {
        let mut h = Sha256::new();
        h.update(&session_secret);
        h.update(&t.to_le_bytes());
        let c = h.finalize();
        let c_arr: [u8; 32] = c.as_slice().try_into().unwrap();
        allowed_tokens.push(temporal_token_from_code(&c_arr));
    }

    // Client-side: code_arr is what would be recovered by Temporal Visual Code decoding.
    let tvc_proof = libzkp::proof::temporal_membership::prove_temporal_membership(
        code_arr.to_vec(),
        allowed_tokens.clone(),
    )?;
    let tvc_ok = libzkp::proof::temporal_membership::verify_temporal_membership(
        tvc_proof,
        allowed_tokens,
    )?;
    println!("temporal_membership_ok={}", tvc_ok);

    assert!(
        range_ok
            && eq_ok
            && eq_ok_commit
            && threshold_ok
            && membership_ok
            && improvement_ok
            && consistency_ok
            && composite_ok
            && tvc_ok
    );
    assert!(results.iter().all(|v| *v));

    Ok(())
}
