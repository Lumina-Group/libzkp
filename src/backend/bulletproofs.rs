use super::ZkpBackend;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

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
        let mut diff_min_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut diff_min_blinding_bytes);
        let diff_min_blinding = Scalar::from_bytes_mod_order(diff_min_blinding_bytes);
        
        let mut transcript_min = Transcript::new(b"libzkp_range_min");
        let (range_proof_min, diff_min_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript_min,
            diff_min,
            &diff_min_blinding,
            64
        ).map_err(|_| "min range proof generation failed".to_string())?;
        
        let diff_max = max - value;
        let mut diff_max_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut diff_max_blinding_bytes);
        let diff_max_blinding = Scalar::from_bytes_mod_order(diff_max_blinding_bytes);
        
        let mut transcript_max = Transcript::new(b"libzkp_range_max");
        let (range_proof_max, diff_max_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript_max,
            diff_max,
            &diff_max_blinding,
            64
        ).map_err(|_| "max range proof generation failed".to_string())?;
        
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
        
        proof_bytes.extend_from_slice(&blinding.to_bytes());
        proof_bytes.extend_from_slice(&diff_min_blinding.to_bytes());
        proof_bytes.extend_from_slice(&diff_max_blinding.to_bytes());
        
        let mut result = Vec::new();
        result.extend_from_slice(&proof_bytes);
        result.extend_from_slice(b"COMMIT:");
        result.extend_from_slice(value_commit.as_bytes());
        
        Ok(result)
    }
    
    pub fn verify_range_with_bounds(proof_data: &[u8], min: u64, max: u64) -> bool {
        let commit_marker = b"COMMIT:";
        let commit_pos = match proof_data.windows(commit_marker.len())
            .position(|window| window == commit_marker) {
            Some(pos) => pos,
            None => return false,
        };
        
        let proof_bytes = &proof_data[0..commit_pos];
        let commit_start = commit_pos + commit_marker.len();
        
        if proof_data.len() < commit_start + 32 {
            return false;
        }
        
        let _value_commit = match CompressedRistretto::from_slice(&proof_data[commit_start..commit_start + 32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let mut reader = proof_bytes;
        
        if reader.len() < 16 {
            return false;
        }
        let proof_min = u64::from_le_bytes(reader[0..8].try_into().unwrap());
        let proof_max = u64::from_le_bytes(reader[8..16].try_into().unwrap());
        if proof_min != min || proof_max != max {
            return false;
        }
        reader = &reader[16..];
        
        if reader.len() < 4 {
            return false;
        }
        let rp_min_len = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
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
        let rp_max_len = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
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
        reader = &reader[64..];
        
        if reader.len() < 96 {
            return false;
        }
        let _value_blinding = match Scalar::from_canonical_bytes(reader[0..32].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        let _diff_min_blinding = match Scalar::from_canonical_bytes(reader[32..64].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        let _diff_max_blinding = match Scalar::from_canonical_bytes(reader[64..96].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 2);
        
        let mut transcript_min = Transcript::new(b"libzkp_range_min");
        if range_proof_min.verify_single(&bp_gens, &pc_gens, &mut transcript_min, &diff_min_commit, 64).is_err() {
            return false;
        }
        
        let mut transcript_max = Transcript::new(b"libzkp_range_max");
        if range_proof_max.verify_single(&bp_gens, &pc_gens, &mut transcript_max, &diff_max_commit, 64).is_err() {
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
            sum = sum.checked_add(value)
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
        let mut diff_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut diff_blinding_bytes);
        let diff_blinding = Scalar::from_bytes_mod_order(diff_blinding_bytes);
        
        let mut transcript = Transcript::new(b"libzkp_threshold");
        let (range_proof, diff_commit) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            diff,
            &diff_blinding,
            64
        ).map_err(|_| "range proof generation failed".to_string())?;
        
        let mut proof_bytes = Vec::new();
        
        proof_bytes.extend_from_slice(&threshold.to_le_bytes());
        
        let rp_bytes = range_proof.to_bytes();
        proof_bytes.extend_from_slice(&(rp_bytes.len() as u32).to_le_bytes());
        proof_bytes.extend_from_slice(&rp_bytes);
        
        proof_bytes.extend_from_slice(diff_commit.as_bytes());
        
        proof_bytes.extend_from_slice(&sum_blinding.to_bytes());
        
        proof_bytes.extend_from_slice(&diff_blinding.to_bytes());
        
        let mut result = Vec::new();
        result.extend_from_slice(&proof_bytes);
        result.extend_from_slice(b"COMMIT:");
        result.extend_from_slice(sum_commit.as_bytes());
        
        Ok(result)
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
            let diff = data[i] - data[i-1];
            let diff_blinding = blindings[i] - blindings[i-1];
            
            let mut transcript = Transcript::new(b"libzkp_consistency");
            let (range_proof, diff_commit) = RangeProof::prove_single(
                &bp_gens, 
                &pc_gens, 
                &mut transcript, 
                diff, 
                &diff_blinding, 
                64
            ).map_err(|_| "range proof generation failed".to_string())?;
            
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
        
        let mut commitment_hash = Vec::new();
        for commit in &commitments {
            commitment_hash.extend_from_slice(commit.as_bytes());
        }
        
        let mut result = Vec::new();
        result.extend_from_slice(&proof_bytes);
        result.extend_from_slice(b"COMMIT:");
        result.extend_from_slice(&commitment_hash);
        
        Ok(result)
    }
    
    pub fn verify_consistency(proof_data: &[u8]) -> bool {
        let commit_marker = b"COMMIT:";
        let commit_pos = match proof_data.windows(commit_marker.len())
            .position(|window| window == commit_marker) {
            Some(pos) => pos,
            None => return false,
        };
        
        let proof_bytes = &proof_data[0..commit_pos];
        let commit_start = commit_pos + commit_marker.len();
        let commitment_hash = &proof_data[commit_start..];
        
        let mut reader = proof_bytes;
        
        if reader.len() < 4 {
            return false;
        }
        let num_values = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
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
        if commitment_hash != expected_commitment {
            return false;
        }
        
        let _pc_gens = PedersenGens::default();
        let _bp_gens = BulletproofGens::new(64, num_values * 2);
        
        for _i in 1..num_values {
            if reader.len() < 4 {
                return false;
            }
            let rp_len = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
            reader = &reader[4..];
            
            if reader.len() < rp_len {
                return false;
            }
            let rp_bytes = &reader[0..rp_len];
            let _range_proof = match RangeProof::from_bytes(rp_bytes) {
                Ok(rp) => rp,
                Err(_) => return false,
            };
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
            let commit_prev = commitments[i-1].decompress();
            
            if commit_i.is_none() || commit_prev.is_none() {
                return false;
            }
            
            let expected_diff = commit_i.unwrap() - commit_prev.unwrap();
            if expected_diff.compress() != diff_commit {
                return false;
            }
        }
        
        true
    }

    pub fn prove_set_membership(value: u64, set: Vec<u64>) -> Result<Vec<u8>, String> {
        if set.is_empty() {
            return Err("set cannot be empty".to_string());
        }
        
        let set_hash: std::collections::HashSet<u64> = set.iter().cloned().collect();
        if !set_hash.contains(&value) {
            return Err("value not in set".to_string());
        }
        
        let pc_gens = PedersenGens::default();
        let mut rng = OsRng;
        
        let mut value_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut value_blinding_bytes);
        let value_blinding = Scalar::from_bytes_mod_order(value_blinding_bytes);
        
        let value_commit = pc_gens.commit(Scalar::from(value), value_blinding).compress();
        
        let set_vec: Vec<u64> = set.into_iter().collect();
        let mut transcript = Transcript::new(b"libzkp_membership");
        
        let value_index = set_vec.iter().position(|&x| x == value).unwrap();
        
        let mut index_blinding_bytes = [0u8; 32];
        rng.fill_bytes(&mut index_blinding_bytes);
        let index_blinding = Scalar::from_bytes_mod_order(index_blinding_bytes);
        
        let index_commit = pc_gens.commit(Scalar::from(value_index as u64), index_blinding).compress();
        
        transcript.append_message(b"value_commit", value_commit.as_bytes());
        transcript.append_message(b"index_commit", index_commit.as_bytes());
        for &set_val in &set_vec {
            transcript.append_u64(b"set_element", set_val);
        }
        
        let mut challenge_bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
        let challenge = Scalar::from_bytes_mod_order(challenge_bytes);
        
        let response = index_blinding + challenge * value_blinding;
        
        let mut proof_bytes = Vec::new();
        
        proof_bytes.extend_from_slice(&(set_vec.len() as u32).to_le_bytes());
        
        for &set_val in &set_vec {
            proof_bytes.extend_from_slice(&set_val.to_le_bytes());
        }
        proof_bytes.extend_from_slice(index_commit.as_bytes());
        
        proof_bytes.extend_from_slice(&challenge.to_bytes());
        
        proof_bytes.extend_from_slice(&response.to_bytes());
        
        proof_bytes.extend_from_slice(&value_blinding.to_bytes());
        
        let mut result = Vec::new();
        result.extend_from_slice(&proof_bytes);
        result.extend_from_slice(b"COMMIT:");
        result.extend_from_slice(value_commit.as_bytes());
        
        Ok(result)
    }
    
    pub fn verify_set_membership(proof_data: &[u8], set: Vec<u64>) -> bool {
        let commit_marker = b"COMMIT:";
        let commit_pos = match proof_data.windows(commit_marker.len())
            .position(|window| window == commit_marker) {
            Some(pos) => pos,
            None => return false,
        };
        
        let proof_bytes = &proof_data[0..commit_pos];
        let commit_start = commit_pos + commit_marker.len();
        
        if proof_data.len() < commit_start + 32 {
            return false;
        }
        
        let value_commit = match CompressedRistretto::from_slice(&proof_data[commit_start..commit_start + 32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let mut reader = proof_bytes;
        
        if reader.len() < 4 {
            return false;
        }
        let set_size = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
        reader = &reader[4..];
        
        if set_size == 0 || set_size != set.len() {
            return false;
        }
        
        if reader.len() < set_size * 8 {
            return false;
        }
        let mut proof_set = Vec::with_capacity(set_size);
        for _ in 0..set_size {
            let set_val = u64::from_le_bytes(reader[0..8].try_into().unwrap());
            proof_set.push(set_val);
            reader = &reader[8..];
        }
        
        let proof_set_hash: std::collections::HashSet<u64> = proof_set.iter().cloned().collect();
        let input_set_hash: std::collections::HashSet<u64> = set.iter().cloned().collect();
        if proof_set_hash != input_set_hash {
            return false;
        }
        
        if reader.len() < 32 {
            return false;
        }
        let index_commit = match CompressedRistretto::from_slice(&reader[0..32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        reader = &reader[32..];
        
        if reader.len() < 32 {
            return false;
        }
        let challenge = match Scalar::from_canonical_bytes(reader[0..32].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        reader = &reader[32..];
        
        if reader.len() < 32 {
            return false;
        }
        let response = match Scalar::from_canonical_bytes(reader[0..32].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        reader = &reader[32..];
        
        if reader.len() < 32 {
            return false;
        }
        let value_blinding = match Scalar::from_canonical_bytes(reader[0..32].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        
        let pc_gens = PedersenGens::default();
        
        let mut transcript = Transcript::new(b"libzkp_membership");
        transcript.append_message(b"value_commit", value_commit.as_bytes());
        transcript.append_message(b"index_commit", index_commit.as_bytes());
        for &set_val in &proof_set {
            transcript.append_u64(b"set_element", set_val);
        }
        
        let mut expected_challenge_bytes = [0u8; 32];
        transcript.challenge_bytes(b"challenge", &mut expected_challenge_bytes);
        let expected_challenge = Scalar::from_bytes_mod_order(expected_challenge_bytes);
        
        if challenge != expected_challenge {
            return false;
        }
        
        for (i, &set_val) in proof_set.iter().enumerate() {
            let expected_value_commit = pc_gens.commit(Scalar::from(set_val), value_blinding).compress();
            if expected_value_commit == value_commit {
                let expected_index_commit = pc_gens.commit(Scalar::from(i as u64), response - challenge * value_blinding).compress();
                if expected_index_commit == index_commit {
                    return true;
                }
            }
        }
        
        false
    }

    pub fn verify_threshold(proof_data: &[u8], threshold: u64) -> bool {
        let commit_marker = b"COMMIT:";
        let commit_pos = proof_data.windows(commit_marker.len())
            .position(|window| window == commit_marker);
        
        let commit_pos = match commit_pos {
            Some(pos) => pos,
            None => return false,
        };
        
        let proof_bytes = &proof_data[0..commit_pos];
        let commit_start = commit_pos + commit_marker.len();
        
        if proof_data.len() < commit_start + 32 {
            return false;
        }
        
        let _sum_commit = match CompressedRistretto::from_slice(&proof_data[commit_start..commit_start + 32]) {
            Ok(c) => c,
            Err(_) => return false,
        };
        
        let mut reader = proof_bytes;
        
        if reader.len() < 8 {
            return false;
        }
        let proof_threshold = u64::from_le_bytes(reader[0..8].try_into().unwrap());
        if proof_threshold != threshold {
            return false;
        }
        reader = &reader[8..];
        
        if reader.len() < 4 {
            return false;
        }
        let rp_len = u32::from_le_bytes(reader[0..4].try_into().unwrap()) as usize;
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
        reader = &reader[32..];
        
        if reader.len() < 64 {
            return false;
        }
        let _sum_blinding = match Scalar::from_canonical_bytes(reader[0..32].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        let _diff_blinding = match Scalar::from_canonical_bytes(reader[32..64].try_into().unwrap()) {
            ct if ct.is_some().into() => ct.unwrap(),
            _ => return false,
        };
        
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 2);
        
        let mut transcript = Transcript::new(b"libzkp_threshold");
        range_proof.verify_single(&bp_gens, &pc_gens, &mut transcript, &diff_commit, 64).is_ok()
    }
}

impl ZkpBackend for BulletproofsBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        let value = u64::from_le_bytes(data.try_into().expect("invalid data"));

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let blinding = Scalar::from_bytes_mod_order(bytes);

        let mut transcript = Transcript::new(b"libzkp_bulletproof");
        let (proof, commit) =
            RangeProof::prove_single(&bp_gens, &pc_gens, &mut transcript, value, &blinding, 64)
                .expect("range proof failure");

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
