pub const PROOF_VERSION: u8 = 1;

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
        let mut out = Vec::new();
        out.push(self.version);
        out.push(self.scheme);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.commitment.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&self.commitment);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let version = data[0];
        let scheme = data[1];
        let proof_len = u32::from_le_bytes(data[2..6].try_into().ok()?) as usize;
        let comm_len = u32::from_le_bytes(data[6..10].try_into().ok()?) as usize;
        if data.len() != 10 + proof_len + comm_len {
            return None;
        }
        let proof = data[10..10 + proof_len].to_vec();
        let commitment = data[10 + proof_len..].to_vec();
        Some(Proof {
            version,
            scheme,
            proof,
            commitment,
        })
    }
}
