use crate::utils::error_handling::{ZkpError, ZkpResult};

pub const PROOF_VERSION: u8 = 2;

#[derive(Debug, Clone)]
pub struct Proof {
    pub version: u8,
    pub scheme: u8,
    pub proof: Vec<u8>,
    pub commitment: Vec<u8>,
}

impl Proof {
    pub fn new(scheme: u8, proof: Vec<u8>, commitment: Vec<u8>) -> Self {
        Self {
            version: PROOF_VERSION,
            scheme,
            proof,
            commitment,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Avoid producing invalid encodings due to u32 truncation.
        if self.proof.len() > u32::MAX as usize || self.commitment.len() > u32::MAX as usize {
            return Vec::new();
        }
        let mut out = Vec::new();
        out.push(self.version);
        out.push(self.scheme);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.commitment.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&self.commitment);
        out
    }

    pub fn from_bytes(data: &[u8]) -> ZkpResult<Self> {
        use crate::utils::limits::{
            MAX_COMMITMENT_BYTES, MAX_PROOF_PAYLOAD_BYTES, MAX_PROOF_TOTAL_BYTES,
        };

        if data.len() > MAX_PROOF_TOTAL_BYTES {
            return Err(ZkpError::InvalidProofFormat(format!(
                "proof too large: max {} bytes",
                MAX_PROOF_TOTAL_BYTES
            )));
        }
        if data.len() < 10 {
            return Err(ZkpError::InvalidProofFormat(
                "proof too short for header".to_string(),
            ));
        }
        let version = data[0];
        let scheme = data[1];
        let proof_len =
            u32::from_le_bytes(data[2..6].try_into().map_err(|_| {
                ZkpError::InvalidProofFormat("invalid proof length field".to_string())
            })?) as usize;
        let comm_len = u32::from_le_bytes(data[6..10].try_into().map_err(|_| {
            ZkpError::InvalidProofFormat("invalid commitment length field".to_string())
        })?) as usize;
        if proof_len > MAX_PROOF_PAYLOAD_BYTES || comm_len > MAX_COMMITMENT_BYTES {
            return Err(ZkpError::InvalidProofFormat(
                "proof or commitment payload exceeds limit".to_string(),
            ));
        }
        let total = 10usize
            .checked_add(proof_len)
            .and_then(|t| t.checked_add(comm_len))
            .ok_or_else(|| ZkpError::InvalidProofFormat("proof length overflow".to_string()))?;
        if data.len() != total {
            return Err(ZkpError::InvalidProofFormat(
                "proof byte length mismatch".to_string(),
            ));
        }
        let proof = data[10..10 + proof_len].to_vec();
        let commitment = data[10 + proof_len..].to_vec();
        Ok(Proof {
            version,
            scheme,
            proof,
            commitment,
        })
    }
}

pub mod consistency_proof;
pub mod equality_proof;
pub mod improvement_proof;
pub mod range_proof;
pub mod set_membership;
pub mod threshold_proof;
