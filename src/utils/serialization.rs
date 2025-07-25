use crate::utils::error_handling::{ZkpError, ZkpResult};

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
        return Err(ZkpError::SerializationError("data too short for length field".to_string()));
    }
    
    let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let expected_size = 4 + len * 8;
    
    if data.len() != expected_size {
        return Err(ZkpError::SerializationError(format!(
            "data size mismatch: expected {}, got {}",
            expected_size, data.len()
        )));
    }
    
    let mut values = Vec::with_capacity(len);
    for i in 0..len {
        let start = 4 + i * 8;
        let end = start + 8;
        let value = u64::from_le_bytes(data[start..end].try_into().unwrap());
        values.push(value);
    }
    
    Ok(values)
}

/// Serialize proof metadata
pub fn serialize_proof_metadata(
    scheme_id: u8,
    version: u8,
    additional_data: &[u8],
) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(version);
    result.push(scheme_id);
    result.extend_from_slice(&(additional_data.len() as u32).to_le_bytes());
    result.extend_from_slice(additional_data);
    result
}

/// Deserialize proof metadata
pub fn deserialize_proof_metadata(data: &[u8]) -> ZkpResult<(u8, u8, Vec<u8>)> {
    if data.len() < 6 {
        return Err(ZkpError::SerializationError("metadata too short".to_string()));
    }
    
    let version = data[0];
    let scheme_id = data[1];
    let additional_len = u32::from_le_bytes(data[2..6].try_into().unwrap()) as usize;
    
    if data.len() != 6 + additional_len {
        return Err(ZkpError::SerializationError("metadata size mismatch".to_string()));
    }
    
    let additional_data = data[6..].to_vec();
    
    Ok((version, scheme_id, additional_data))
}

/// Create a standardized data payload for backend processing
pub fn create_backend_payload(operation: &str, params: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let op_bytes = operation.as_bytes();
    
    payload.extend_from_slice(&(op_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(op_bytes);
    payload.extend_from_slice(&(params.len() as u32).to_le_bytes());
    payload.extend_from_slice(params);
    
    payload
}

/// Parse a backend payload
pub fn parse_backend_payload(data: &[u8]) -> ZkpResult<(String, Vec<u8>)> {
    if data.len() < 8 {
        return Err(ZkpError::SerializationError("payload too short".to_string()));
    }
    
    let op_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let params_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    
    if data.len() != 8 + op_len + params_len {
        return Err(ZkpError::SerializationError("payload size mismatch".to_string()));
    }
    
    let operation = String::from_utf8(data[8..8+op_len].to_vec())
        .map_err(|_| ZkpError::SerializationError("invalid operation string".to_string()))?;
    
    let params = data[8+op_len..].to_vec();
    
    Ok((operation, params))
}

/// Serialize range parameters
pub fn serialize_range_params(value: u64, min: u64, max: u64) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&value.to_le_bytes());
    result.extend_from_slice(&min.to_le_bytes());
    result.extend_from_slice(&max.to_le_bytes());
    result
}

/// Deserialize range parameters
pub fn deserialize_range_params(data: &[u8]) -> ZkpResult<(u64, u64, u64)> {
    if data.len() != 24 {
        return Err(ZkpError::SerializationError("invalid range params size".to_string()));
    }
    
    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let min = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let max = u64::from_le_bytes(data[16..24].try_into().unwrap());
    
    Ok((value, min, max))
}

/// Serialize threshold parameters
pub fn serialize_threshold_params(values: &[u64], threshold: u64) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&threshold.to_le_bytes());
    result.extend_from_slice(&serialize_u64_vec(values));
    result
}

/// Deserialize threshold parameters
pub fn deserialize_threshold_params(data: &[u8]) -> ZkpResult<(Vec<u64>, u64)> {
    if data.len() < 8 {
        return Err(ZkpError::SerializationError("threshold params too short".to_string()));
    }
    
    let threshold = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let values = deserialize_u64_vec(&data[8..])?;
    
    Ok((values, threshold))
}

/// Serialize improvement parameters
pub fn serialize_improvement_params(old: u64, new: u64) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&old.to_le_bytes());
    result.extend_from_slice(&new.to_le_bytes());
    result
}

/// Deserialize improvement parameters
pub fn deserialize_improvement_params(data: &[u8]) -> ZkpResult<(u64, u64)> {
    if data.len() != 16 {
        return Err(ZkpError::SerializationError("invalid improvement params size".to_string()));
    }
    
    let old = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let new = u64::from_le_bytes(data[8..16].try_into().unwrap());
    
    Ok((old, new))
}

/// Serialize membership parameters
pub fn serialize_membership_params(value: u64, set: &[u64]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(&value.to_le_bytes());
    result.extend_from_slice(&serialize_u64_vec(set));
    result
}

/// Deserialize membership parameters
pub fn deserialize_membership_params(data: &[u8]) -> ZkpResult<(u64, Vec<u64>)> {
    if data.len() < 8 {
        return Err(ZkpError::SerializationError("membership params too short".to_string()));
    }
    
    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let set = deserialize_u64_vec(&data[8..])?;
    
    Ok((value, set))
}