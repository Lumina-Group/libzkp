use super::circuit::TvcCircuit;
use super::signal::{TemporalCode, Waveform};
use crate::utils::error_handling::{ZkpError, ZkpResult};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use rand::rngs::OsRng;
// use ark_ff::Field;

pub struct TvcSystem {
    pk: ProvingKey<Bn254>,
    vk: VerifyingKey<Bn254>,
}

impl TvcSystem {
    pub fn setup() -> Self {
        let mut rng = OsRng;
        let circuit = TvcCircuit {
            s: None,
            t: None,
            public_commitment: None,
            current_time: None,
            time_tolerance: None,
        };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).unwrap();
        Self { pk, vk }
    }

    /// Helper to compute the commitment in the same way as the circuit
    pub fn compute_commitment(s: u64, t: u64) -> Fr {
        let s_fr = Fr::from(s);
        let t_fr = Fr::from(t);
        let sum = s_fr + t_fr;
        sum * sum
    }

    pub fn prove(
        &self,
        code: &TemporalCode,
        current_time: u64,
        tolerance: u64,
    ) -> ZkpResult<(Vec<u8>, Vec<u8>)> { // Returns (proof_bytes, public_inputs_bytes)
        let mut rng = OsRng;
        
        let commitment = Self::compute_commitment(code.s, code.t);
        
        let circuit = TvcCircuit {
            s: Some(Fr::from(code.s)),
            t: Some(Fr::from(code.t)),
            public_commitment: Some(commitment),
            current_time: Some(Fr::from(current_time)),
            time_tolerance: Some(Fr::from(tolerance)),
        };

        let proof = Groth16::<Bn254>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| ZkpError::ProofGenerationFailed(e.to_string()))?;

        // Serialize proof
        let mut proof_bytes = Vec::new();
        use ark_serialize::CanonicalSerialize;
        proof.serialize_compressed(&mut proof_bytes)
             .map_err(|e| ZkpError::SerializationError(e.to_string()))?;

        // Serialize public inputs (commitment, current_time, tolerance)
        let mut public_inputs = Vec::new();
        commitment.serialize_compressed(&mut public_inputs)
            .map_err(|e| ZkpError::SerializationError(e.to_string()))?;
        Fr::from(current_time).serialize_compressed(&mut public_inputs)
            .map_err(|e| ZkpError::SerializationError(e.to_string()))?;
        Fr::from(tolerance).serialize_compressed(&mut public_inputs)
            .map_err(|e| ZkpError::SerializationError(e.to_string()))?;

        Ok((proof_bytes, public_inputs))
    }

    pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> ZkpResult<bool> {
        use ark_serialize::CanonicalDeserialize;
        
        let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Proof deserialization error: {}", e)))?;

        // Deserialize public inputs manually
        // Since we know the order: commitment (32 bytes), current_time (32 bytes), tolerance (32 bytes)
        // Note: Fr size depends on curve, for Bn254 it is 32 bytes compressed.
        
        let mut reader = public_inputs_bytes;
        let commitment = Fr::deserialize_compressed(&mut reader)
            .map_err(|e| ZkpError::SerializationError(format!("Deserialization error: {}", e)))?;
        let current_time = Fr::deserialize_compressed(&mut reader)
            .map_err(|e| ZkpError::SerializationError(format!("Deserialization error: {}", e)))?;
        let tolerance = Fr::deserialize_compressed(&mut reader)
            .map_err(|e| ZkpError::SerializationError(format!("Deserialization error: {}", e)))?;

        let public_inputs = vec![commitment, current_time, tolerance];

        let result = Groth16::<Bn254>::verify(&self.vk, &public_inputs, &proof)
            .map_err(|e| ZkpError::VerificationFailed(e.to_string()))?;

        Ok(result)
    }
}
