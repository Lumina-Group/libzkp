use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};

#[derive(Debug, Clone)]
pub enum ZkpError {
    InvalidInput(String),
    ProofGenerationFailed(String),
    VerificationFailed(String),
    InvalidProofFormat(String),
    BackendError(String),
    SerializationError(String),
    ValidationError(String),
}

impl std::fmt::Display for ZkpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkpError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ZkpError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            ZkpError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            ZkpError::InvalidProofFormat(msg) => write!(f, "Invalid proof format: {}", msg),
            ZkpError::BackendError(msg) => write!(f, "Backend error: {}", msg),
            ZkpError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ZkpError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ZkpError {}

impl From<ZkpError> for PyErr {
    fn from(err: ZkpError) -> Self {
        match err {
            ZkpError::InvalidInput(msg) | ZkpError::ValidationError(msg) => {
                PyValueError::new_err(msg)
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

pub type ZkpResult<T> = Result<T, ZkpError>;

pub fn validate_range(min: u64, max: u64) -> ZkpResult<()> {
    if min > max {
        return Err(ZkpError::InvalidInput("min cannot be greater than max".to_string()));
    }
    Ok(())
}

pub fn validate_value_in_range(value: u64, min: u64, max: u64) -> ZkpResult<()> {
    validate_range(min, max)?;
    if value < min || value > max {
        return Err(ZkpError::InvalidInput(format!("value {} is not in range [{}, {}]", value, min, max)));
    }
    Ok(())
}

pub fn validate_non_empty_slice<T>(slice: &[T], name: &str) -> ZkpResult<()> {
    if slice.is_empty() {
        return Err(ZkpError::InvalidInput(format!("{} cannot be empty", name)));
    }
    Ok(())
}

pub fn validate_improvement(old: u64, new: u64) -> ZkpResult<u64> {
    if new <= old {
        return Err(ZkpError::InvalidInput("new value must be greater than old value".to_string()));
    }
    Ok(new - old)
}

pub fn validate_commitment_size(commitment: &[u8], expected_size: usize) -> ZkpResult<()> {
    if commitment.len() != expected_size {
        return Err(ZkpError::InvalidProofFormat(format!(
            "expected commitment size {}, got {}",
            expected_size,
            commitment.len()
        )));
    }
    Ok(())
}