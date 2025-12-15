//! Production safety limits to prevent excessive allocations / DoS.
//!
//! These limits are intentionally conservative and can be adjusted if needed.

/// Maximum size (in bytes) accepted for a single serialized `Proof`.
pub const MAX_PROOF_TOTAL_BYTES: usize = 1 * 1024 * 1024; // 1 MiB

/// Maximum size (in bytes) accepted for the `proof` payload within a `Proof`.
pub const MAX_PROOF_PAYLOAD_BYTES: usize = 900 * 1024; // leave room for header/commitment

/// Maximum size (in bytes) accepted for the `commitment` field within a `Proof`.
pub const MAX_COMMITMENT_BYTES: usize = 256;

/// Maximum number of u64 elements allowed when deserializing u64 vectors.
pub const MAX_U64_VEC_LEN: usize = 4096;

/// Maximum size (in bytes) accepted for backend payloads (operation + params).
pub const MAX_BACKEND_PAYLOAD_BYTES: usize = 256 * 1024; // 256 KiB

/// Maximum length (in bytes) accepted for the backend operation string.
pub const MAX_BACKEND_OPERATION_LEN: usize = 64;

/// Maximum additional metadata payload length (in bytes).
pub const MAX_METADATA_ADDITIONAL_BYTES: usize = 64 * 1024; // 64 KiB

/// Maximum size (in bytes) accepted for a serialized `CompositeProof`.
pub const MAX_COMPOSITE_PROOF_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
