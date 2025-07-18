use super::ZkpBackend;

pub struct BulletproofsBackend;

impl ZkpBackend for BulletproofsBackend {
    fn prove(_data: &[u8]) -> Vec<u8> {
        b"bulletproof".to_vec()
    }

    fn verify(_proof: &[u8], _data: &[u8]) -> bool {
        true
    }
}
