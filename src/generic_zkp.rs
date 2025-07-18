// Generic ZKP API for unified access to different proof systems

use pyo3::prelude::*;
use crate::zkp_backends::{BackendRegistry, ZKPBackend, GenericProof, GenericCommitment, ZKPError};
use crate::zkp_backends::bulletproofs_backend::BulletproofsBackend;
use crate::circuits::generic_circuit::{GenericCircuitCompiler, CircuitTemplates, CircuitDescription};
use crate::circuits::set_membership::{SetMembershipProver, BatchSetMembershipProver};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde_json;

/// Main ZKP engine that provides unified access to all proof systems
#[pyclass]
pub struct ZKPEngine {
    registry: Arc<Mutex<BackendRegistry>>,
    compiler: GenericCircuitCompiler,
    set_provers: Arc<Mutex<HashMap<String, SetMembershipProver>>>,
    batch_set_prover: Arc<Mutex<BatchSetMembershipProver>>,
}

#[pymethods]
impl ZKPEngine {
    #[new]
    pub fn new() -> Self {
        let mut registry = BackendRegistry::new();
        registry.register_backend(Box::new(BulletproofsBackend::new()));
        
        Self {
            registry: Arc::new(Mutex::new(registry)),
            compiler: GenericCircuitCompiler::new(),
            set_provers: Arc::new(Mutex::new(HashMap::new())),
            batch_set_prover: Arc::new(Mutex::new(BatchSetMembershipProver::new())),
        }
    }
    
    /// List available ZKP backends
    #[pyfn(m)]
    pub fn list_backends(&self) -> PyResult<Vec<String>> {
        let registry = self.registry.lock().unwrap();
        Ok(registry.list_backends().iter().map(|s| s.to_string()).collect())
    }
    
    /// Prove using a generic circuit description
    #[pyfn(m)]
    pub fn prove_generic(
        &self,
        circuit_json: String,
        public_inputs_json: String,
        private_inputs_json: String,
        backend_name: Option<String>,
    ) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let circuit_desc: CircuitDescription = serde_json::from_str(&circuit_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let circuit = self.compiler.compile_circuit(&circuit_desc)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        
        let registry = self.registry.lock().unwrap();
        let backend = if let Some(name) = backend_name {
            registry.get_backend(&name)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", name)
                ))?
        } else {
            registry.find_suitable_backend(&circuit.circuit_type)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "No suitable backend found for circuit type"
                ))?
        };
        
        let compiled_circuit = backend.compile_circuit(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let (proof, commitment) = backend.prove(
            &compiled_circuit,
            public_inputs_json.as_bytes(),
            private_inputs_json.as_bytes(),
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let proof_bytes = serde_json::to_vec(&proof)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let commitment_bytes = serde_json::to_vec(&commitment)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok((proof_bytes, commitment_bytes))
    }
    
    /// Verify using a generic circuit description
    #[pyfn(m)]
    pub fn verify_generic(
        &self,
        circuit_json: String,
        proof_bytes: Vec<u8>,
        commitment_bytes: Vec<u8>,
        backend_name: Option<String>,
    ) -> PyResult<bool> {
        let circuit_desc: CircuitDescription = serde_json::from_str(&circuit_json)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let circuit = self.compiler.compile_circuit(&circuit_desc)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        
        let proof: GenericProof = serde_json::from_slice(&proof_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let commitment: GenericCommitment = serde_json::from_slice(&commitment_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let registry = self.registry.lock().unwrap();
        let backend = if let Some(name) = backend_name {
            registry.get_backend(&name)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", name)
                ))?
        } else {
            registry.get_backend(&proof.backend_type)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", proof.backend_type)
                ))?
        };
        
        let compiled_circuit = backend.compile_circuit(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let result = backend.verify(&compiled_circuit, &proof, &commitment)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok(result)
    }
    
    /// Generate a range proof circuit template
    #[pyfn(m)]
    pub fn create_range_circuit(&self, min: i64, max: i64) -> PyResult<String> {
        let circuit = CircuitTemplates::range_proof(min, max);
        serde_json::to_string(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
    
    /// Generate an equality proof circuit template
    #[pyfn(m)]
    pub fn create_equality_circuit(&self) -> PyResult<String> {
        let circuit = CircuitTemplates::equality_proof();
        serde_json::to_string(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
    
    /// Generate a threshold proof circuit template
    #[pyfn(m)]
    pub fn create_threshold_circuit(&self, threshold: i64) -> PyResult<String> {
        let circuit = CircuitTemplates::threshold_proof(threshold);
        serde_json::to_string(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
    
    /// Create a circuit from a logical expression
    #[pyfn(m)]
    pub fn create_circuit_from_expression(&self, expression: String) -> PyResult<String> {
        let circuit = CircuitTemplates::from_expression(&expression)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
        serde_json::to_string(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }
    
    /// Create a set for membership proofs
    #[pyfn(m)]
    pub fn create_membership_set(&self, set_name: String, elements: Vec<Vec<u8>>) -> PyResult<String> {
        let prover = SetMembershipProver::from_elements(elements);
        let root_hash = prover.root_hash()
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Failed to create set"))?;
        
        {
            let mut provers = self.set_provers.lock().unwrap();
            provers.insert(set_name.clone(), prover);
        }
        
        {
            let mut batch_prover = self.batch_set_prover.lock().unwrap();
            batch_prover.add_set(set_name, elements);
        }
        
        Ok(hex::encode(root_hash))
    }
    
    /// Prove membership in a set
    #[pyfn(m)]
    pub fn prove_set_membership(&self, set_name: String, element: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let batch_prover = self.batch_set_prover.lock().unwrap();
        let (circuit, witness) = batch_prover.prove_membership(&set_name, &element)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Element not found in set or set does not exist"
            ))?;
        
        let circuit_bytes = serde_json::to_vec(&circuit)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let witness_bytes = serde_json::to_vec(&witness)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok((circuit_bytes, witness_bytes))
    }
    
    /// Verify membership in a set
    #[pyfn(m)]
    pub fn verify_set_membership(
        &self,
        set_name: String,
        circuit_bytes: Vec<u8>,
        witness_bytes: Vec<u8>,
    ) -> PyResult<bool> {
        let circuit = serde_json::from_slice(&circuit_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let witness = serde_json::from_slice(&witness_bytes)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let batch_prover = self.batch_set_prover.lock().unwrap();
        Ok(batch_prover.verify_membership(&set_name, &circuit, &witness))
    }
    
    /// Prove membership in multiple sets (intersection proof)
    #[pyfn(m)]
    pub fn prove_multi_set_membership(
        &self,
        set_names: Vec<String>,
        element: Vec<u8>,
    ) -> PyResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let batch_prover = self.batch_set_prover.lock().unwrap();
        let proofs = batch_prover.prove_multi_membership(&set_names, &element);
        
        let mut result = Vec::new();
        for (circuit, witness) in proofs {
            let circuit_bytes = serde_json::to_vec(&circuit)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            let witness_bytes = serde_json::to_vec(&witness)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            result.push((circuit_bytes, witness_bytes));
        }
        
        Ok(result)
    }
    
    /// Get information about all sets
    #[pyfn(m)]
    pub fn get_set_info(&self) -> PyResult<HashMap<String, (String, usize)>> {
        let batch_prover = self.batch_set_prover.lock().unwrap();
        let info = batch_prover.get_set_info();
        
        let mut result = HashMap::new();
        for (name, (root_opt, size)) in info {
            let root_hex = root_opt.map(|r| hex::encode(r)).unwrap_or_else(|| "none".to_string());
            result.insert(name, (root_hex, size));
        }
        
        Ok(result)
    }
    
    /// Batch prove multiple circuits
    #[pyfn(m)]
    pub fn prove_batch(
        &self,
        circuit_jsons: Vec<String>,
        public_inputs_jsons: Vec<String>,
        private_inputs_jsons: Vec<String>,
        backend_name: Option<String>,
    ) -> PyResult<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        if circuit_jsons.len() != public_inputs_jsons.len() || 
           circuit_jsons.len() != private_inputs_jsons.len() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "All input arrays must have the same length"
            ));
        }
        
        let mut compiled_circuits = Vec::new();
        let mut public_inputs = Vec::new();
        let mut private_inputs = Vec::new();
        
        // Compile all circuits
        for i in 0..circuit_jsons.len() {
            let circuit_desc: CircuitDescription = serde_json::from_str(&circuit_jsons[i])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
            let circuit = self.compiler.compile_circuit(&circuit_desc)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
            
            let registry = self.registry.lock().unwrap();
            let backend = if let Some(ref name) = backend_name {
                registry.get_backend(name)
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        format!("Backend '{}' not found", name)
                    ))?
            } else {
                registry.find_suitable_backend(&circuit.circuit_type)
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "No suitable backend found for circuit type"
                    ))?
            };
            
            let compiled_circuit = backend.compile_circuit(&circuit)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
            compiled_circuits.push(compiled_circuit);
            public_inputs.push(public_inputs_jsons[i].as_bytes().to_vec());
            private_inputs.push(private_inputs_jsons[i].as_bytes().to_vec());
        }
        
        // Generate batch proof
        let registry = self.registry.lock().unwrap();
        let backend = if let Some(ref name) = backend_name {
            registry.get_backend(name)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", name)
                ))?
        } else {
            // Use the first available backend
            registry.list_backends().first()
                .and_then(|name| registry.get_backend(name))
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "No backends available"
                ))?
        };
        
        let public_inputs_refs: Vec<&[u8]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        let private_inputs_refs: Vec<&[u8]> = private_inputs.iter().map(|v| v.as_slice()).collect();
        
        let (proofs, commitments) = backend.prove_batch(
            &compiled_circuits,
            &public_inputs_refs,
            &private_inputs_refs,
        ).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let proof_bytes: Result<Vec<Vec<u8>>, _> = proofs.iter()
            .map(|p| serde_json::to_vec(p))
            .collect();
        let commitment_bytes: Result<Vec<Vec<u8>>, _> = commitments.iter()
            .map(|c| serde_json::to_vec(c))
            .collect();
        
        let proof_bytes = proof_bytes
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let commitment_bytes = commitment_bytes
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok((proof_bytes, commitment_bytes))
    }
    
    /// Batch verify multiple proofs
    #[pyfn(m)]
    pub fn verify_batch(
        &self,
        circuit_jsons: Vec<String>,
        proof_bytes_list: Vec<Vec<u8>>,
        commitment_bytes_list: Vec<Vec<u8>>,
        backend_name: Option<String>,
    ) -> PyResult<bool> {
        if circuit_jsons.len() != proof_bytes_list.len() || 
           circuit_jsons.len() != commitment_bytes_list.len() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "All input arrays must have the same length"
            ));
        }
        
        let mut compiled_circuits = Vec::new();
        let mut proofs = Vec::new();
        let mut commitments = Vec::new();
        
        // Compile circuits and deserialize proofs/commitments
        for i in 0..circuit_jsons.len() {
            let circuit_desc: CircuitDescription = serde_json::from_str(&circuit_jsons[i])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
            let circuit = self.compiler.compile_circuit(&circuit_desc)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e))?;
            
            let proof: GenericProof = serde_json::from_slice(&proof_bytes_list[i])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            let commitment: GenericCommitment = serde_json::from_slice(&commitment_bytes_list[i])
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
            let registry = self.registry.lock().unwrap();
            let backend = if let Some(ref name) = backend_name {
                registry.get_backend(name)
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        format!("Backend '{}' not found", name)
                    ))?
            } else {
                registry.get_backend(&proof.backend_type)
                    .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        format!("Backend '{}' not found", proof.backend_type)
                    ))?
            };
            
            let compiled_circuit = backend.compile_circuit(&circuit)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
            
            compiled_circuits.push(compiled_circuit);
            proofs.push(proof);
            commitments.push(commitment);
        }
        
        // Verify batch
        let registry = self.registry.lock().unwrap();
        let backend = if let Some(ref name) = backend_name {
            registry.get_backend(name)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", name)
                ))?
        } else {
            // Use the backend from the first proof
            registry.get_backend(&proofs[0].backend_type)
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!("Backend '{}' not found", proofs[0].backend_type)
                ))?
        };
        
        let result = backend.verify_batch(&compiled_circuits, &proofs, &commitments)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Ok(result)
    }
}

impl Default for ZKPEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Python module functions for the generic ZKP API
#[pyfunction]
pub fn create_zkp_engine() -> ZKPEngine {
    ZKPEngine::new()
}