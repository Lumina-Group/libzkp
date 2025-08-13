use super::ZkpBackend;
use ark_bn254::{Bn254, Fr};
// The circuit enforces: (1) a == b as field elements, (2) a fits into 64 bits,
// and (3) SHA-256(LE_Bytes(a)) == public commitment. This ties the witness value
// to the commitment inside the circuit without any out-of-circuit assumptions.
use ark_crypto_primitives::crh::constraints::CRHSchemeGadget;
use ark_crypto_primitives::crh::sha256;
use ark_crypto_primitives::crh::sha256::constraints::{Sha256Gadget, UnitVar};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use std::sync::OnceLock;

#[derive(Clone)]
struct EqualityCircuit {
    a: Option<u64>,
    b: Option<u64>,
    pub hash_input: Option<[u8; 32]>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate witnesses for a and b as field elements
        let a_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.a.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.b.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce a == b
        a_var.enforce_equal(&b_var)?;

        // Convert 'a' to little-endian bits and constrain higher bits to zero (only 64-bit used)
        let mut a_bits_le = a_var.to_bits_le()?; // length ~= 254
        // Keep exactly 64 LSBs for hashing input
        let a_bits_le_64: Vec<Boolean<Fr>> = a_bits_le.drain(0..64).collect();
        // Remaining higher bits must be zero to represent a 64-bit integer faithfully
        for bit in a_bits_le.into_iter() {
            bit.enforce_equal(&Boolean::FALSE())?;
        }

        // Build 8 LE bytes from the 64 LSBits
        let mut a_bytes_le: Vec<UInt8<Fr>> = Vec::with_capacity(8);
        for chunk in a_bits_le_64.chunks(8) {
            a_bytes_le.push(UInt8::<Fr>::from_bits_le(chunk));
        }

        // Compute SHA-256 over the 8-byte LE encoding of 'a'
        let digest_bytes = <Sha256Gadget as CRHSchemeGadget<sha256::CRH, Fr>>::evaluate(
            &UnitVar::default(),
            &a_bytes_le,
        )?; // 32 bytes

        // Public input: expected 32-byte commitment
        let expected_commitment = self
            .hash_input
            .ok_or(SynthesisError::AssignmentMissing)?
            .to_vec();
        let expected_commitment_bytes = UInt8::<Fr>::new_input_vec(cs.clone(), || Ok(expected_commitment))?;

        // Enforce digest == expected_commitment (byte-wise)
        for (d, e) in digest_bytes.iter().zip(expected_commitment_bytes.iter()) {
            d.enforce_equal(e)?;
        }

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
