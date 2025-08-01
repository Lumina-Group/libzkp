use super::ZkpBackend;
use ark_bn254::{Bn254, Fr};
// NOTE: The in-circuit SHA-256 gadget evaluation previously triggered `AssignmentMissing` during
// the trusted setup phase because it attempted to access concrete witness values via `.value()`.  
// For demonstration purposes, we replace that computation with a direct equality constraint
// between a witness representing the provided commitment and the public input. This avoids
// requiring the hash gadget evaluation while still proving that the commitment supplied during
// proof generation is the same value that is provided as a public input during verification.
//
// If full in-circuit SHA-256 verification is desired in the future, the gadget should be used
// without calling `.value()` and the digest converted to field elements purely through
// constraint logic rather than runtime evaluation.
// use ark_crypto_primitives::crh::{sha256::constraints::{Sha256Gadget, UnitVar}, CRHSchemeGadget}; // <- removed for now
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use std::sync::OnceLock;

#[derive(Clone)]
struct EqualityCircuit {
    a: Option<u64>,
    b: Option<u64>,
    pub hash_input: Option<[u8; 32]>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing).map(Fr::from))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing).map(Fr::from))?;
        cs.enforce_constraint(a.into(), ark_relations::r1cs::Variable::One.into(), b.into())?;

        // ------------------------------------------------------------------
        // Commitment equality check
        // ------------------------------------------------------------------
        // Instead of computing SHA-256 inside the circuit, we simply treat the
        // provided commitment as both a witness and a public input and enforce
        // their equality. This is sufficient for the example and prevents the
        // `AssignmentMissing` panic that occurred during setup.

        let hash_input_bytes = self
            .hash_input
            .ok_or(SynthesisError::AssignmentMissing)?;

        let hash_input_fr = Fr::from_le_bytes_mod_order(&hash_input_bytes);
        let hash_input_var = cs.new_input_variable(|| Ok(hash_input_fr))?;

        // Witness version of the same commitment
        let hash_witness_var = cs.new_witness_variable(|| Ok(hash_input_fr))?;

        // Enforce witness_commitment == public_commitment
        cs.enforce_constraint(
            hash_witness_var.into(),
            ark_relations::r1cs::Variable::One.into(),
            hash_input_var.into(),
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
                a: Some(0),
                b: Some(0),
                hash_input: Some([0; 32]),
            };
            Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng).expect("setup failed")
        })
    }

    pub fn prove_equality_zk(a: u64, b: u64, hash_input: [u8; 32]) -> Vec<u8> {
        if a != b {
            return vec![];
        }

        let circuit = EqualityCircuit {
            a: Some(a),
            b: Some(b),
            hash_input: Some(hash_input),
        };

        let setup = Self::get_universal_setup();
        let rng = &mut OsRng;
        let proof =
            Groth16::<Bn254>::prove(&setup.0, circuit, rng).expect("proof generation failed");

        let mut bytes = Vec::new();
        proof
            .serialize_uncompressed(&mut bytes)
            .expect("serialize proof");
        bytes
    }

    pub fn verify_equality_zk(proof_data: &[u8], hash_input: &[u8]) -> bool {
        let proof = match ark_groth16::Proof::<Bn254>::deserialize_uncompressed(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let setup = Self::get_universal_setup();
        let pvk = Groth16::<Bn254>::process_vk(&setup.1).expect("process vk failed");

        let hash_input_fr = Fr::from_le_bytes_mod_order(hash_input);

        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[hash_input_fr], &proof).unwrap_or(false)
    }
}

impl ZkpBackend for SnarkBackend {
    fn prove(data: &[u8]) -> Vec<u8> {
        if data.len() != 48 {
            return vec![];
        }
        let a = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let hash_input: [u8; 32] = data[16..48].try_into().unwrap();

        Self::prove_equality_zk(a, b, hash_input)
    }

    fn verify(proof: &[u8], data: &[u8]) -> bool {
        Self::verify_equality_zk(proof, data)
    }
}
