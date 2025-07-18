use super::ZkpBackend;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

struct TrivialCircuit;

impl ConstraintSynthesizer<Fr> for TrivialCircuit {
    fn generate_constraints(self, _cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        Ok(())
    }
}

pub struct SnarkBackend;

impl ZkpBackend for SnarkBackend {
    fn prove(_data: &[u8]) -> Vec<u8> {
        let rng = &mut OsRng;
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, rng).expect("setup failed");
        let proof =
            Groth16::<Bn254>::prove(&pk, TrivialCircuit, rng).expect("proof generation failed");
        let mut bytes = Vec::new();
        vk.serialize_uncompressed(&mut bytes).expect("serialize vk");
        proof
            .serialize_uncompressed(&mut bytes)
            .expect("serialize proof");
        bytes
    }

    fn verify(proof: &[u8], _data: &[u8]) -> bool {
        let mut reader = proof;
        let vk = match VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let pf = match Proof::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk failed");
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[], &pf).unwrap_or(false)
    }
}
