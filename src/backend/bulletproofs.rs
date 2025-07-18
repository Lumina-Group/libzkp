use super::ZkpBackend;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct BulletproofsBackend;

impl ZkpBackend for BulletproofsBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        let value = u64::from_le_bytes(data.try_into().expect("invalid data"));

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut rng = OsRng;
        let mut bytes = [0u8; 32];
        use rand::RngCore;
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
