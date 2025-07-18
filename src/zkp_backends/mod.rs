// ZKP Backend abstraction layer
// This module provides a unified interface for different ZKP systems

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Generic result type for ZKP operations
pub type ZKPResult<T> = Result<T, ZKPError>;

/// Unified error type for all ZKP backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZKPError {
    ProofGenerationFailed(String),
    VerificationFailed(String),
    InvalidInput(String),
    BackendNotSupported(String),
    CircuitCompilationFailed(String),
}

impl std::fmt::Display for ZKPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZKPError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            ZKPError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            ZKPError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ZKPError::BackendNotSupported(msg) => write!(f, "Backend not supported: {}", msg),
            ZKPError::CircuitCompilationFailed(msg) => write!(f, "Circuit compilation failed: {}", msg),
        }
    }
}

impl std::error::Error for ZKPError {}

/// Generic proof structure that can hold different types of proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericProof {
    pub backend_type: String,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Generic commitment structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericCommitment {
    pub backend_type: String,
    pub commitment_data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Circuit description for generic ZKP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    pub circuit_id: String,
    pub circuit_type: CircuitType,
    pub constraints: Vec<Constraint>,
    pub public_inputs: Vec<String>,
    pub private_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircuitType {
    Range,
    Equality,
    Threshold,
    Improvement,
    Consistency,
    SetMembership,
    Generic(String), // For custom circuits
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub constraint_type: ConstraintType,
    pub variables: Vec<String>,
    pub coefficients: Vec<i64>,
    pub constant: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintType {
    Linear,
    Quadratic,
    Boolean,
    Range { min: i64, max: i64 },
}

/// Trait that all ZKP backends must implement
pub trait ZKPBackend: Send + Sync {
    /// Get the name of this backend
    fn name(&self) -> &str;
    
    /// Check if this backend supports the given circuit type
    fn supports_circuit(&self, circuit_type: &CircuitType) -> bool;
    
    /// Compile a circuit for this backend
    fn compile_circuit(&self, circuit: &Circuit) -> ZKPResult<Vec<u8>>;
    
    /// Generate a proof for the given circuit and inputs
    fn prove(
        &self,
        compiled_circuit: &[u8],
        public_inputs: &[u8],
        private_inputs: &[u8],
    ) -> ZKPResult<(GenericProof, GenericCommitment)>;
    
    /// Verify a proof
    fn verify(
        &self,
        compiled_circuit: &[u8],
        proof: &GenericProof,
        commitment: &GenericCommitment,
    ) -> ZKPResult<bool>;
    
    /// Generate a batch proof (optional, default implementation generates individual proofs)
    fn prove_batch(
        &self,
        compiled_circuits: &[Vec<u8>],
        public_inputs: &[Vec<u8>],
        private_inputs: &[Vec<u8>],
    ) -> ZKPResult<(Vec<GenericProof>, Vec<GenericCommitment>)> {
        let mut proofs = Vec::new();
        let mut commitments = Vec::new();
        
        for i in 0..compiled_circuits.len() {
            let (proof, commitment) = self.prove(
                &compiled_circuits[i],
                &public_inputs[i],
                &private_inputs[i],
            )?;
            proofs.push(proof);
            commitments.push(commitment);
        }
        
        Ok((proofs, commitments))
    }
    
    /// Verify a batch of proofs (optional, default implementation verifies individually)
    fn verify_batch(
        &self,
        compiled_circuits: &[Vec<u8>],
        proofs: &[GenericProof],
        commitments: &[GenericCommitment],
    ) -> ZKPResult<bool> {
        for i in 0..compiled_circuits.len() {
            if !self.verify(&compiled_circuits[i], &proofs[i], &commitments[i])? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Registry for managing multiple ZKP backends
pub struct BackendRegistry {
    backends: HashMap<String, Box<dyn ZKPBackend>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }
    
    pub fn register_backend(&mut self, backend: Box<dyn ZKPBackend>) {
        let name = backend.name().to_string();
        self.backends.insert(name, backend);
    }
    
    pub fn get_backend(&self, name: &str) -> Option<&dyn ZKPBackend> {
        self.backends.get(name).map(|b| b.as_ref())
    }
    
    pub fn find_suitable_backend(&self, circuit_type: &CircuitType) -> Option<&dyn ZKPBackend> {
        for backend in self.backends.values() {
            if backend.supports_circuit(circuit_type) {
                return Some(backend.as_ref());
            }
        }
        None
    }
    
    pub fn list_backends(&self) -> Vec<&str> {
        self.backends.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}