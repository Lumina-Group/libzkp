use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};


pub fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn pedersen_commit(value: u64) -> (CompressedRistretto, Scalar) {
    let pc_gens = PedersenGens::default();
    let mut rng = OsRng;
    let blinding = Scalar::random(&mut rng);
    let commit = pc_gens.commit(Scalar::from(value), blinding).compress();
    (commit, blinding)
}

pub fn pedersen_commit_with_blind(value: u64, blind: Scalar) -> CompressedRistretto {
    let pc_gens = PedersenGens::default();
    pc_gens.commit(Scalar::from(value), blind).compress()
}


pub fn hash_with_label(label: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(data);
    hasher.finalize().to_vec()
}
