use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::limits::{MAX_BACKEND_OPERATION_LEN, MAX_BACKEND_PAYLOAD_BYTES, MAX_U64_VEC_LEN};

/// Serialize a vector of u64 values to bytes
pub fn serialize_u64_vec(values: &[u64]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for &value in values {
        result.extend_from_slice(&value.to_le_bytes());
    }
    result
}

/// Deserialize bytes to a vector of u64 values
pub fn deserialize_u64_vec(data: &[u8]) -> ZkpResult<Vec<u64>> {
    if data.len() < 4 {
        return Err(ZkpError::SerializationError(
            "data too short for length field".to_string(),
        ));
    }

    let len = match data[0..4].try_into() {
        Ok(arr) => u32::from_le_bytes(arr) as usize,
        Err(_) => {
            return Err(ZkpError::SerializationError(
                "invalid length field".to_string(),
            ))
        }
    };
    if len > MAX_U64_VEC_LEN {
        return Err(ZkpError::SerializationError(format!(
            "vector too large: len={}, max={}",
            len, MAX_U64_VEC_LEN
        )));
    }
    let expected_size = len
        .checked_mul(8)
        .and_then(|v| v.checked_add(4))
        .ok_or_else(|| ZkpError::SerializationError("size overflow".to_string()))?;

    if data.len() != expected_size {
        return Err(ZkpError::SerializationError(format!(
            "data size mismatch: expected {}, got {}",
            expected_size,
            data.len()
        )));
    }

    let mut values = Vec::with_capacity(len);
    for i in 0..len {
        let start = 4 + i * 8;
        let end = start + 8;
        let value = match data[start..end].try_into() {
            Ok(arr) => u64::from_le_bytes(arr),
            Err(_) => {
                return Err(ZkpError::SerializationError(
                    "invalid u64 element".to_string(),
                ))
            }
        };
        values.push(value);
    }

    Ok(values)
}

/// Create a standardized data payload for backend processing
pub fn create_backend_payload(operation: &str, params: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let op_bytes = operation.as_bytes();

    // Production safety: keep payloads bounded.
    if op_bytes.len() > MAX_BACKEND_OPERATION_LEN {
        return Vec::new();
    }
    if params
        .len()
        .checked_add(8)
        .and_then(|v| v.checked_add(op_bytes.len()))
        .is_none()
    {
        return Vec::new();
    }
    if 8 + op_bytes.len() + params.len() > MAX_BACKEND_PAYLOAD_BYTES {
        return Vec::new();
    }

    payload.extend_from_slice(&(op_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(op_bytes);
    payload.extend_from_slice(&(params.len() as u32).to_le_bytes());
    payload.extend_from_slice(params);

    payload
}

/// Parse a backend payload (must match [`create_backend_payload`]:
/// `[u32 op_len][op bytes][u32 params_len][params bytes]`).
pub fn parse_backend_payload(data: &[u8]) -> ZkpResult<(String, Vec<u8>)> {
    if data.len() > MAX_BACKEND_PAYLOAD_BYTES {
        return Err(ZkpError::SerializationError(format!(
            "payload too large: max {} bytes",
            MAX_BACKEND_PAYLOAD_BYTES
        )));
    }
    if data.len() < 4 {
        return Err(ZkpError::SerializationError(
            "payload too short".to_string(),
        ));
    }

    let op_len = match data[0..4].try_into() {
        Ok(arr) => u32::from_le_bytes(arr) as usize,
        Err(_) => {
            return Err(ZkpError::SerializationError(
                "invalid op length".to_string(),
            ))
        }
    };

    if op_len > MAX_BACKEND_OPERATION_LEN {
        return Err(ZkpError::SerializationError(
            "operation too long".to_string(),
        ));
    }

    let op_end = 4usize
        .checked_add(op_len)
        .ok_or_else(|| ZkpError::SerializationError("payload size overflow".to_string()))?;
    if data.len() < op_end.saturating_add(4) {
        return Err(ZkpError::SerializationError(
            "truncated before params length".to_string(),
        ));
    }

    let params_len = match data[op_end..op_end + 4].try_into() {
        Ok(arr) => u32::from_le_bytes(arr) as usize,
        Err(_) => {
            return Err(ZkpError::SerializationError(
                "invalid params length".to_string(),
            ))
        }
    };

    let expected = op_end
        .checked_add(4)
        .and_then(|v| v.checked_add(params_len))
        .ok_or_else(|| ZkpError::SerializationError("payload size overflow".to_string()))?;
    if data.len() != expected {
        return Err(ZkpError::SerializationError(
            "payload size mismatch".to_string(),
        ));
    }

    let operation = String::from_utf8(data[4..op_end].to_vec())
        .map_err(|_| ZkpError::SerializationError("invalid operation string".to_string()))?;

    let params = data[op_end + 4..].to_vec();

    Ok((operation, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::limits::MAX_BACKEND_OPERATION_LEN;

    #[test]
    fn backend_payload_roundtrip() {
        let p = create_backend_payload("range_proof", &[1u8, 2, 3]);
        let (op, params) = parse_backend_payload(&p).unwrap();
        assert_eq!(op, "range_proof");
        assert_eq!(params, vec![1u8, 2, 3]);
    }

    #[test]
    fn backend_payload_rejects_long_operation() {
        let op = "a".repeat(MAX_BACKEND_OPERATION_LEN + 1);
        let p = create_backend_payload(&op, &[]);
        assert!(p.is_empty());
    }

    #[test]
    fn u64_vec_roundtrip() {
        let v = vec![1u64, 2, 3];
        let b = serialize_u64_vec(&v);
        assert_eq!(deserialize_u64_vec(&b).unwrap(), v);
    }
}
