use super::ZkpBackend;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

#[derive(Clone)]
struct EqualityCircuit {
    a: Fr,
    b: Fr,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::{LinearCombination, Variable};
        let a_var = cs.new_input_variable(|| Ok(self.a))?;
        let b_var = cs.new_input_variable(|| Ok(self.b))?;
        cs.enforce_constraint(
            LinearCombination::from(a_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(b_var),
        )?;
        Ok(())
    }
}

pub struct SnarkBackend;

impl ZkpBackend for SnarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            return vec![];
        }
        let a = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let circ = EqualityCircuit {
            a: Fr::from(a),
            b: Fr::from(b),
        };
        let rng = &mut OsRng;
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(circ.clone(), rng).expect("setup failed");
        let proof = Groth16::<Bn254>::prove(&pk, circ, rng).expect("proof generation failed");
        let mut bytes = Vec::new();
        vk.serialize_uncompressed(&mut bytes).expect("serialize vk");
        proof
            .serialize_uncompressed(&mut bytes)
            .expect("serialize proof");
        bytes
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        let mut reader = proof;
        let vk = match VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let pf = match Proof::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(p) => p,
            Err(_) => return false,
        };
        if data.len() != 16 {
            return false;
        }
        let a = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk failed");
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[Fr::from(a), Fr::from(b)], &pf)
            .unwrap_or(false)
    }
}
