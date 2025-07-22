use super::ZkpBackend;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use ark_std::UniformRand;
use std::sync::OnceLock;

#[derive(Clone)]
struct EqualityCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
    commit_a: Fr,
    commit_b: Fr,
    blinding_a: Option<Fr>,
    blinding_b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::{LinearCombination, Variable};

        let a_var = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b_var = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let blinding_a_var =
            cs.new_witness_variable(|| self.blinding_a.ok_or(SynthesisError::AssignmentMissing))?;
        let blinding_b_var =
            cs.new_witness_variable(|| self.blinding_b.ok_or(SynthesisError::AssignmentMissing))?;

        let commit_a_var = cs.new_input_variable(|| Ok(self.commit_a))?;
        let commit_b_var = cs.new_input_variable(|| Ok(self.commit_b))?;

        cs.enforce_constraint(
            LinearCombination::from(a_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(b_var),
        )?;

        cs.enforce_constraint(
            LinearCombination::from(a_var) + LinearCombination::from(blinding_a_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(commit_a_var),
        )?;

        cs.enforce_constraint(
            LinearCombination::from(b_var) + LinearCombination::from(blinding_b_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(commit_b_var),
        )?;

        Ok(())
    }
}

pub struct SnarkBackend;

static UNIVERSAL_SETUP: OnceLock<(
    ark_groth16::ProvingKey<Bn254>,
    ark_groth16::VerifyingKey<Bn254>,
)> = OnceLock::new();

impl SnarkBackend {
    fn get_universal_setup() -> &'static (
        ark_groth16::ProvingKey<Bn254>,
        ark_groth16::VerifyingKey<Bn254>,
    ) {
        UNIVERSAL_SETUP.get_or_init(|| {
            let rng = &mut OsRng;
            let dummy_circuit = EqualityCircuit {
                a: Some(Fr::from(0u64)),
                b: Some(Fr::from(0u64)),
                commit_a: Fr::from(0u64),
                commit_b: Fr::from(0u64),
                blinding_a: Some(Fr::from(0u64)),
                blinding_b: Some(Fr::from(0u64)),
            };
            Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng).expect("setup failed")
        })
    }

    pub fn prove_equality_zk(a: u64, b: u64, blinding_a: Fr, blinding_b: Fr) -> Vec<u8> {
        if a != b {
            return vec![];
        }

        let commit_a = Fr::from(a) + blinding_a;
        let commit_b = Fr::from(b) + blinding_b;

        let circuit = EqualityCircuit {
            a: Some(Fr::from(a)),
            b: Some(Fr::from(b)),
            commit_a,
            commit_b,
            blinding_a: Some(blinding_a),
            blinding_b: Some(blinding_b),
        };

        let setup = Self::get_universal_setup();
        let rng = &mut OsRng;
        let proof =
            Groth16::<Bn254>::prove(&setup.0, circuit, rng).expect("proof generation failed");

        let mut bytes = Vec::new();
        setup
            .1
            .serialize_uncompressed(&mut bytes)
            .expect("serialize vk");
        proof
            .serialize_uncompressed(&mut bytes)
            .expect("serialize proof");
        commit_a
            .serialize_uncompressed(&mut bytes)
            .expect("serialize commit_a");
        commit_b
            .serialize_uncompressed(&mut bytes)
            .expect("serialize commit_b");
        bytes
    }

    pub fn verify_equality_zk(proof_data: &[u8]) -> bool {
        let mut reader = proof_data;

        let vk = match VerifyingKey::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(vk) => vk,
            Err(_) => return false,
        };

        let proof = match ark_groth16::Proof::<Bn254>::deserialize_uncompressed(&mut reader) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let commit_a = match Fr::deserialize_uncompressed(&mut reader) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let commit_b = match Fr::deserialize_uncompressed(&mut reader) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk failed");
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[commit_a, commit_b], &proof)
            .unwrap_or(false)
    }
}

impl ZkpBackend for SnarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 16 {
            return vec![];
        }
        let a = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(data[8..16].try_into().unwrap());

        let rng = &mut OsRng;
        let blinding_a = Fr::rand(rng);
        let blinding_b = Fr::rand(rng);

        Self::prove_equality_zk(a, b, blinding_a, blinding_b)
    }

    fn verify(proof: &[u8], _data: &[u8]) -> bool {
        Self::verify_equality_zk(proof)
    }
}
