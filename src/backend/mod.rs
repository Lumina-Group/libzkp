pub mod bulletproofs;
pub mod snark;
pub mod stark;

pub trait ZkpBackend {
    fn prove(data: &[u8]) -> Vec<u8>;
    fn verify(_proof: &[u8], _data: &[u8]) -> bool;
}
