#[cfg(feature = "python")]
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
#[cfg(feature = "python")]
use pyo3::prelude::*;
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

#[cfg(feature = "python")]
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

pub type ZkpResult<T> = Result<T, ZkpError>;
