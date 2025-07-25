use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError, PyTypeError};
use std::fmt;

#[derive(Debug, Clone)]
pub enum ZkpError {
    InvalidInput(String),
    ProofGenerationFailed(String),
    VerificationFailed(String),
    InvalidProofFormat(String),
    BackendError(String),
    SerializationError(String),
    ValidationError(String),
    IntegerOverflow(String),
    CryptoError(String),
    ConfigError(String),
}

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkpError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ZkpError::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            ZkpError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            ZkpError::InvalidProofFormat(msg) => write!(f, "Invalid proof format: {}", msg),
            ZkpError::BackendError(msg) => write!(f, "Backend error: {}", msg),
            ZkpError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ZkpError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ZkpError::IntegerOverflow(msg) => write!(f, "Integer overflow: {}", msg),
            ZkpError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            ZkpError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
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
            ZkpError::IntegerOverflow(msg) => {
                PyErr::new::<pyo3::exceptions::PyOverflowError, _>(msg)
            }
            ZkpError::InvalidProofFormat(msg) | ZkpError::ConfigError(msg) => {
                PyTypeError::new_err(msg)
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

// Error context wrapper for adding additional information
#[derive(Debug)]
pub struct ErrorContext<E> {
    error: E,
    context: String,
}

impl<E: fmt::Display> fmt::Display for ErrorContext<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.context, self.error)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ErrorContext<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub trait WithContext<T, E> {
    fn with_context<F>(self, f: F) -> Result<T, ErrorContext<E>>
    where
        F: FnOnce() -> String;
}

impl<T, E> WithContext<T, E> for Result<T, E> {
    fn with_context<F>(self, f: F) -> Result<T, ErrorContext<E>>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|error| ErrorContext {
            error,
            context: f(),
        })
    }
}

pub type ZkpResult<T> = Result<T, ZkpError>;

// Enhanced validation functions with better error messages
pub fn validate_range(min: u64, max: u64) -> ZkpResult<()> {
    if min > max {
        return Err(ZkpError::InvalidInput(
            format!("Invalid range: min ({}) cannot be greater than max ({})", min, max)
        ));
    }
    Ok(())
}

pub fn validate_value_in_range(value: u64, min: u64, max: u64) -> ZkpResult<()> {
    validate_range(min, max)?;
    if value < min || value > max {
        return Err(ZkpError::InvalidInput(
            format!("Value {} is outside the valid range [{}, {}]", value, min, max)
        ));
    }
    Ok(())
}

pub fn validate_non_empty_slice<T>(slice: &[T], name: &str) -> ZkpResult<()> {
    if slice.is_empty() {
        return Err(ZkpError::InvalidInput(
            format!("{} cannot be empty", name)
        ));
    }
    Ok(())
}

pub fn validate_improvement(old: u64, new: u64) -> ZkpResult<u64> {
    if new <= old {
        return Err(ZkpError::InvalidInput(
            format!("No improvement: new value ({}) must be greater than old value ({})", new, old)
        ));
    }
    
    // Check for overflow
    match new.checked_sub(old) {
        Some(diff) => Ok(diff),
        None => Err(ZkpError::IntegerOverflow(
            format!("Integer overflow when calculating improvement: {} - {}", new, old)
        )),
    }
}

pub fn validate_commitment_size(commitment: &[u8], expected_size: usize) -> ZkpResult<()> {
    if commitment.len() != expected_size {
        return Err(ZkpError::InvalidProofFormat(
            format!(
                "Invalid commitment size: expected {} bytes, got {} bytes",
                expected_size,
                commitment.len()
            )
        ));
    }
    Ok(())
}

// Additional validation functions
pub fn validate_proof_size(proof: &[u8], min_size: usize) -> ZkpResult<()> {
    if proof.len() < min_size {
        return Err(ZkpError::InvalidProofFormat(
            format!(
                "Proof too small: expected at least {} bytes, got {} bytes",
                min_size,
                proof.len()
            )
        ));
    }
    Ok(())
}

pub fn validate_set_membership<T: Eq>(value: &T, set: &[T]) -> ZkpResult<usize> {
    match set.iter().position(|x| x == value) {
        Some(index) => Ok(index),
        None => Err(ZkpError::InvalidInput(
            "Value is not a member of the provided set".to_string()
        )),
    }
}

pub fn safe_add(a: u64, b: u64) -> ZkpResult<u64> {
    a.checked_add(b).ok_or_else(|| {
        ZkpError::IntegerOverflow(
            format!("Integer overflow in addition: {} + {}", a, b)
        )
    })
}

pub fn safe_mul(a: u64, b: u64) -> ZkpResult<u64> {
    a.checked_mul(b).ok_or_else(|| {
        ZkpError::IntegerOverflow(
            format!("Integer overflow in multiplication: {} * {}", a, b)
        )
    })
}