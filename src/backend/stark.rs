use super::ZkpBackend;

pub struct StarkBackend;

impl ZkpBackend for StarkBackend {
    fn prove(_data: &[u8]) -> Vec<u8> {
        b"stark".to_vec()
    }

    fn verify(_proof: &[u8], _data: &[u8]) -> bool {
        true
    }
}
