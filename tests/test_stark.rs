#[cfg(test)]
mod tests {
    use libzkp::backend::stark::StarkBackend;
    use libzkp::backend::ZkpBackend;

    #[test]
    fn test_stark_prove_and_verify() {
        // Test data: old value = 100, new value = 200
        let old: u64 = 100;
        let new: u64 = 200;
        
        // Encode the data
        let mut data = Vec::new();
        data.extend_from_slice(&old.to_le_bytes());
        data.extend_from_slice(&new.to_le_bytes());
        
        // Generate proof
        let proof = StarkBackend::prove(&data);
        assert!(!proof.is_empty(), "Proof should not be empty");
        
        // Verify proof
        let is_valid = StarkBackend::verify(&proof, &data);
        assert!(is_valid, "Proof should be valid");
    }

    #[test]
    fn test_stark_invalid_proof() {
        // Test data: old value = 200, new value = 100 (invalid: new < old)
        let old: u64 = 200;
        let new: u64 = 100;
        
        // Encode the data
        let mut data = Vec::new();
        data.extend_from_slice(&old.to_le_bytes());
        data.extend_from_slice(&new.to_le_bytes());
        
        // Try to generate proof (should fail)
        let proof = StarkBackend::prove(&data);
        assert!(proof.is_empty(), "Proof should be empty for invalid data");
    }

    #[test]
    fn test_stark_invalid_verification() {
        // Generate a valid proof
        let old: u64 = 100;
        let new: u64 = 200;
        
        let mut data = Vec::new();
        data.extend_from_slice(&old.to_le_bytes());
        data.extend_from_slice(&new.to_le_bytes());
        
        let proof = StarkBackend::prove(&data);
        assert!(!proof.is_empty());
        
        // Try to verify with different data
        let wrong_old: u64 = 150;
        let wrong_new: u64 = 250;
        
        let mut wrong_data = Vec::new();
        wrong_data.extend_from_slice(&wrong_old.to_le_bytes());
        wrong_data.extend_from_slice(&wrong_new.to_le_bytes());
        
        let is_valid = StarkBackend::verify(&proof, &wrong_data);
        assert!(!is_valid, "Proof should not be valid for different data");
    }
}