use super::ZkpBackend;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Bulletproofs backend wire format (no ambiguous delimiters):
/// `[u32 proof_body_len][proof_body][u32=32][32 byte commitment]`.
fn encode_proof_body_with_commit(proof_body: &[u8], commit: &[u8]) -> Result<Vec<u8>, String> {
    if commit.len() != 32 {
        return Err("commitment must be 32 bytes".to_string());
    }
    let mut out = Vec::with_capacity(4 + proof_body.len() + 4 + 32);
    out.extend_from_slice(&(proof_body.len() as u32).to_le_bytes());
    out.extend_from_slice(proof_body);
    out.extend_from_slice(&(32u32).to_le_bytes());
    out.extend_from_slice(commit);
    Ok(out)
}

fn decode_proof_body_and_commit(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 4 + 4 + 32 {
        return None;
    }
    let plen = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?) as usize;
    let proof_end = 4usize.checked_add(plen)?;
    if data.len() < proof_end.checked_add(4)?.checked_add(32)? {
        return None;
    }
    let clen = u32::from_le_bytes(data.get(proof_end..proof_end + 4)?.try_into().ok()?) as usize;
    if clen != 32 {
        return None;
    }
    if data.len() != proof_end + 4 + 32 {
        return None;
    }
    Some((
        data.get(4..proof_end)?,
        data.get(proof_end + 4..proof_end + 4 + 32)?,
    ))
}

pub struct BulletproofsBackend;

impl BulletproofsBackend {
    pub fn prove_range_with_bounds(value: u64, min: u64, max: u64) -> Result<Vec<u8>, String> {
        if value < min || value > max {
            return Err("value out of range".to_string());
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 2);
        let mut rng = OsRng;

        let mut blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut blinding_bytes);
        let blinding = Scalar::from_bytes_mod_order(blinding_bytes);

        let value_commit = pc_gens.commit(Scalar::from(value), blinding).compress();

        let diff_min = value - min;
        // Tie diff_min commitment to value commitment: use the SAME blinding
        let diff_min_blinding = blinding;

        let mut transcript_min = Transcript::new(b"libzkp_range_min");
        let (range_proof_min, diff_min_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript_min,
            diff_min,
            &diff_min_blinding,
            64,
        )
        .map_err(|_| "min range proof generation failed".to_string())?;

        let diff_max = max - value;
        // Ensure linkage: use the NEGATED blinding so that (max*B - C_v) equals commit(diff_max, -blinding)
        let diff_max_blinding = -blinding;

        let mut transcript_max = Transcript::new(b"libzkp_range_max");
        let (range_proof_max, diff_max_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript_max,
            diff_max,
            &diff_max_blinding,
            64,
        )
        .map_err(|_| "max range proof generation failed".to_string())?;

        let mut proof_bytes = Vec::new();

        proof_bytes.extend_from_slice(&min.to_le_bytes());
        proof_bytes.extend_from_slice(&max.to_le_bytes());

        let rp_min_bytes = range_proof_min.to_bytes();
        proof_bytes.extend_from_slice(&(rp_min_bytes.len() as u32).to_le_bytes());
        proof_bytes.extend_from_slice(&rp_min_bytes);

        let rp_max_bytes = range_proof_max.to_bytes();
        proof_bytes.extend_from_slice(&(rp_max_bytes.len() as u32).to_le_bytes());
        proof_bytes.extend_from_slice(&rp_max_bytes);

        proof_bytes.extend_from_slice(diff_min_commit.as_bytes());
        proof_bytes.extend_from_slice(diff_max_commit.as_bytes());

        encode_proof_body_with_commit(&proof_bytes, value_commit.as_bytes())
    }

    pub fn verify_range_with_bounds(proof_data: &[u8], min: u64, max: u64) -> bool {
        let (proof_bytes, commit_slice) = match decode_proof_body_and_commit(proof_data) {
            Some(p) => p,
            None => return false,
        };

        let value_commit = match CompressedRistretto::from_slice(commit_slice) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let value_commit_point: RistrettoPoint = match value_commit.decompress() {
            Some(p) => p,
            None => return false,
        };

        let mut reader = proof_bytes;

        if reader.len() < 16 {
            return false;
        }
        let proof_min = match reader[0..8].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return false,
        };
        let proof_max = match reader[8..16].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return false,
        };
        if proof_min != min || proof_max != max {
            return false;
        }
        reader = &reader[16..];

        if reader.len() < 4 {
            return false;
        }
        let rp_min_len = match reader[0..4].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return false,
        };
        reader = &reader[4..];

        if reader.len() < rp_min_len {
            return false;
        }
        let rp_min_bytes = &reader[0..rp_min_len];
        let range_proof_min = match RangeProof::from_bytes(rp_min_bytes) {
            Ok(rp) => rp,
            Err(_) => return false,
        };
        reader = &reader[rp_min_len..];

        if reader.len() < 4 {
            return false;
        }
        let rp_max_len = match reader[0..4].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return false,
        };
        reader = &reader[4..];

        if reader.len() < rp_max_len {
            return false;
        }
        let rp_max_bytes = &reader[0..rp_max_len];
        let range_proof_max = match RangeProof::from_bytes(rp_max_bytes) {
            Ok(rp) => rp,
            Err(_) => return false,
        };
        reader = &reader[rp_max_len..];

        if reader.len() < 64 {
            return false;
        }
        let diff_min_commit = match CompressedRistretto::from_slice(&reader[0..32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let diff_max_commit = match CompressedRistretto::from_slice(&reader[32..64]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        // No further payload is expected after this point.

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 2);

        // Recompute expected diff commitments from the value commitment
        let expected_min_commit = (value_commit_point - (Scalar::from(min) * pc_gens.B)).compress();
        let expected_max_commit = ((Scalar::from(max) * pc_gens.B) - value_commit_point).compress();

        // Optional: check included commits match expected linkage
        if expected_min_commit != diff_min_commit || expected_max_commit != diff_max_commit {
            return false;
        }

        let mut transcript_min = Transcript::new(b"libzkp_range_min");
        if range_proof_min
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript_min,
                &expected_min_commit,
                64,
            )
            .is_err()
        {
            return false;
        }
        let mut transcript_max = Transcript::new(b"libzkp_range_max");
        if range_proof_max
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript_max,
                &expected_max_commit,
                64,
            )
            .is_err()
        {
            return false;
        }

        true
    }

    pub fn prove_threshold(values: Vec<u64>, threshold: u64) -> Result<Vec<u8>, String> {
        if values.is_empty() {
            return Err("values cannot be empty".to_string());
        }

        // Calculate sum with overflow checking
        let mut sum: u64 = 0;
        for &value in &values {
            sum = sum
                .checked_add(value)
                .ok_or_else(|| "integer overflow in sum calculation".to_string())?;
        }

        if sum < threshold {
            return Err("threshold not met".to_string());
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, values.len() + 1);
        let mut rng = OsRng;

        let mut sum_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut sum_blinding_bytes);
        let sum_blinding = Scalar::from_bytes_mod_order(sum_blinding_bytes);

        let sum_commit = pc_gens.commit(Scalar::from(sum), sum_blinding).compress();

        let diff = sum - threshold;
        // Link diff to sum: use the same blinding
        let diff_blinding = sum_blinding;

        let mut transcript = Transcript::new(b"libzkp_threshold");
        let (range_proof, diff_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            diff,
            &diff_blinding,
            64,
        )
        .map_err(|_| "range proof generation failed".to_string())?;

        let mut proof_bytes = Vec::new();

        proof_bytes.extend_from_slice(&threshold.to_le_bytes());

        let rp_bytes = range_proof.to_bytes();
        proof_bytes.extend_from_slice(&(rp_bytes.len() as u32).to_le_bytes());
        proof_bytes.extend_from_slice(&rp_bytes);

        proof_bytes.extend_from_slice(diff_commit.as_bytes());

        encode_proof_body_with_commit(&proof_bytes, sum_commit.as_bytes())
    }

    pub fn prove_consistency(data: Vec<u64>) -> Result<Vec<u8>, String> {
        if data.is_empty() {
            return Err("data cannot be empty".to_string());
        }

        if data.windows(2).any(|w| w[0] > w[1]) {
            return Err("data inconsistent".to_string());
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, data.len() * 2);
        let mut rng = OsRng;

        let mut blindings = Vec::with_capacity(data.len());
        for _ in 0..data.len() {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            blindings.push(Scalar::from_bytes_mod_order(bytes));
        }
        let mut commitments = Vec::with_capacity(data.len());
        for (i, &value) in data.iter().enumerate() {
            let commit = pc_gens.commit(Scalar::from(value), blindings[i]).compress();
            commitments.push(commit);
        }

        let mut range_proofs = Vec::new();
        let mut diff_commitments = Vec::new();

        for i in 1..data.len() {
            let diff = data[i] - data[i - 1];
            let diff_blinding = blindings[i] - blindings[i - 1];

            let mut transcript = Transcript::new(b"libzkp_consistency");
            let (range_proof, diff_commit) = RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                diff,
                &diff_blinding,
                64,
            )
            .map_err(|_| "range proof generation failed".to_string())?;

            range_proofs.push(range_proof);
            diff_commitments.push(diff_commit);
        }

        let mut proof_bytes = Vec::new();

        proof_bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());

        for commit in &commitments {
            proof_bytes.extend_from_slice(commit.as_bytes());
        }

        for range_proof in &range_proofs {
            let rp_bytes = range_proof.to_bytes();
            proof_bytes.extend_from_slice(&(rp_bytes.len() as u32).to_le_bytes());
            proof_bytes.extend_from_slice(&rp_bytes);
        }

        for diff_commit in &diff_commitments {
            proof_bytes.extend_from_slice(diff_commit.as_bytes());
        }

        // Commit to the full commitment list with a fixed-size digest (32 bytes),
        // so it fits our `Proof` serialization limits and can be embedded safely.
        let mut commitment_bytes = Vec::new();
        for commit in &commitments {
            commitment_bytes.extend_from_slice(commit.as_bytes());
        }
        let commitment_digest: [u8; 32] = Sha256::digest(&commitment_bytes).into();

        encode_proof_body_with_commit(&proof_bytes, commitment_digest.as_slice())
    }

    pub fn verify_consistency(proof_data: &[u8]) -> bool {
        let (proof_bytes, commitment_hash) = match decode_proof_body_and_commit(proof_data) {
            Some(p) => p,
            None => return false,
        };
        if commitment_hash.len() != 32 {
            return false;
        }

        let mut reader = proof_bytes;

        if reader.len() < 4 {
            return false;
        }
        let num_values = match reader[0..4].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return false,
        };
        reader = &reader[4..];

        if num_values == 0 {
            return false;
        }

        if reader.len() < num_values * 32 {
            return false;
        }
        let mut commitments = Vec::with_capacity(num_values);
        for _ in 0..num_values {
            let commit_bytes = &reader[0..32];
            let commit = match CompressedRistretto::from_slice(commit_bytes) {
                Ok(c) => c,
                Err(_) => return false,
            };
            commitments.push(commit);
            reader = &reader[32..];
        }

        let mut expected_commitment = Vec::new();
        for commit in &commitments {
            expected_commitment.extend_from_slice(commit.as_bytes());
        }
        let expected_digest: [u8; 32] = Sha256::digest(&expected_commitment).into();
        if commitment_hash != expected_digest.as_slice() {
            return false;
        }

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, num_values * 2);

        // Read range proofs into memory
        let mut range_proofs = Vec::with_capacity(num_values.saturating_sub(1));
        for _i in 1..num_values {
            if reader.len() < 4 {
                return false;
            }
            let rp_len = match reader[0..4].try_into() {
                Ok(arr) => u32::from_le_bytes(arr) as usize,
                Err(_) => return false,
            };
            reader = &reader[4..];

            if reader.len() < rp_len {
                return false;
            }
            let rp_bytes = &reader[0..rp_len];
            let range_proof = match RangeProof::from_bytes(rp_bytes) {
                Ok(rp) => rp,
                Err(_) => return false,
            };
            range_proofs.push(range_proof);
            reader = &reader[rp_len..];
        }

        for i in 1..num_values {
            if reader.len() < 32 {
                return false;
            }
            let diff_commit = match CompressedRistretto::from_slice(&reader[0..32]) {
                Ok(c) => c,
                Err(_) => return false,
            };
            reader = &reader[32..];

            let commit_i = commitments[i].decompress();
            let commit_prev = commitments[i - 1].decompress();

            if commit_i.is_none() || commit_prev.is_none() {
                return false;
            }

            let expected_diff = match (commit_i, commit_prev) {
                (Some(ci), Some(cp)) => ci - cp,
                _ => return false,
            };
            if expected_diff.compress() != diff_commit {
                return false;
            }
            // Verify non-negativity of the difference via the corresponding range proof
            let mut transcript = Transcript::new(b"libzkp_consistency");
            if range_proofs[i - 1]
                .verify_single(&bp_gens, &pc_gens, &mut transcript, &diff_commit, 64)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    pub fn verify_threshold(proof_data: &[u8], threshold: u64) -> bool {
        let (proof_bytes, sum_commit_slice) = match decode_proof_body_and_commit(proof_data) {
            Some(p) => p,
            None => return false,
        };

        let mut reader = proof_bytes;

        if reader.len() < 8 {
            return false;
        }
        let proof_threshold = match reader[0..8].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return false,
        };
        if proof_threshold != threshold {
            return false;
        }
        reader = &reader[8..];

        if reader.len() < 4 {
            return false;
        }
        let rp_len = match reader[0..4].try_into() {
            Ok(arr) => u32::from_le_bytes(arr) as usize,
            Err(_) => return false,
        };
        reader = &reader[4..];

        if reader.len() < rp_len {
            return false;
        }
        let rp_bytes = &reader[0..rp_len];
        let range_proof = match RangeProof::from_bytes(rp_bytes) {
            Ok(rp) => rp,
            Err(_) => return false,
        };
        reader = &reader[rp_len..];

        if reader.len() < 32 {
            return false;
        }
        let diff_commit = match CompressedRistretto::from_slice(&reader[0..32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        // No further payload is expected after this point.

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 2);

        // Recompute expected diff commit from sum commit and threshold linkage
        let sum_commit = match CompressedRistretto::from_slice(sum_commit_slice) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let sum_commit_point = match sum_commit.decompress() {
            Some(p) => p,
            None => return false,
        };
        let expected_diff_commit =
            (sum_commit_point - (Scalar::from(threshold) * pc_gens.B)).compress();

        if expected_diff_commit != diff_commit {
            return false;
        }

        let mut transcript = Transcript::new(b"libzkp_threshold");
        range_proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &expected_diff_commit,
                64,
            )
            .is_ok()
    }
}

impl ZkpBackend for BulletproofsBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 8 {
            return vec![];
        }
        let value = match data.try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => return vec![],
        };

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let blinding = Scalar::from_bytes_mod_order(bytes);

        let mut transcript = Transcript::new(b"libzkp_bulletproof");
        let (proof, commit) = match RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            value,
            &blinding,
            64,
        ) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        let mut out = proof.to_bytes();
        out.extend_from_slice(commit.as_bytes());
        out
    }

    fn verify(proof: &[u8], _data: &[u8]) -> bool {
        if proof.len() < 32 {
            return false;
        }
        let proof_len = proof.len() - 32;
        let (proof_bytes, commit_bytes) = proof.split_at(proof_len);

        let proof = match RangeProof::from_bytes(proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let commit = match CompressedRistretto::from_slice(commit_bytes) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut transcript = Transcript::new(b"libzkp_bulletproof");

        proof
            .verify_single(&bp_gens, &pc_gens, &mut transcript, &commit, 64)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulletproofs_wire_encode_decode_roundtrip() {
        let body = b"hello proof body".to_vec();
        let commit = [7u8; 32];
        let w = encode_proof_body_with_commit(&body, &commit).unwrap();
        let (db, cc) = decode_proof_body_and_commit(&w).unwrap();
        assert_eq!(db, body.as_slice());
        assert_eq!(cc, commit.as_slice());
    }

    #[test]
    fn prove_range_roundtrip() {
        let p = BulletproofsBackend::prove_range_with_bounds(5, 0, 10).unwrap();
        assert!(BulletproofsBackend::verify_range_with_bounds(&p, 0, 10));
        assert!(!BulletproofsBackend::verify_range_with_bounds(&p, 0, 4));
    }
}
