use crate::utils::error_handling::{ZkpError, ZkpResult};

/// Validate range parameters
pub fn validate_range_params(value: u64, min: u64, max: u64) -> ZkpResult<()> {
    if min > max {
        return Err(ZkpError::InvalidInput(
            "min cannot be greater than max".to_string(),
        ));
    }
    if value < min || value > max {
        return Err(ZkpError::InvalidInput(format!(
            "value {} is not in range [{}, {}]",
            value, min, max
        )));
    }
    Ok(())
}

/// Validate equality parameters
pub fn validate_equality_params(val1: u64, val2: u64) -> ZkpResult<()> {
    if val1 != val2 {
        return Err(ZkpError::InvalidInput("values are not equal".to_string()));
    }
    Ok(())
}

/// Validate threshold parameters
pub fn validate_threshold_params(values: &[u64], threshold: u64) -> ZkpResult<u64> {
    if values.is_empty() {
        return Err(ZkpError::InvalidInput("values cannot be empty".to_string()));
    }

    let sum = values.iter().try_fold(0u64, |acc, &val| {
        acc.checked_add(val).ok_or_else(|| {
            ZkpError::InvalidInput("integer overflow in sum calculation".to_string())
        })
    })?;

    if sum < threshold {
        return Err(ZkpError::InvalidInput(format!(
            "sum {} is less than threshold {}",
            sum, threshold
        )));
    }

    Ok(sum)
}

/// Validate set membership parameters
pub fn validate_membership_params(value: u64, set: &[u64]) -> ZkpResult<()> {
    if set.is_empty() {
        return Err(ZkpError::InvalidInput("set cannot be empty".to_string()));
    }

    if !set.contains(&value) {
        return Err(ZkpError::InvalidInput(format!(
            "value {} is not in the provided set",
            value
        )));
    }

    Ok(())
}

/// Validate improvement parameters
pub fn validate_improvement_params(old: u64, new: u64) -> ZkpResult<u64> {
    if new <= old {
        return Err(ZkpError::InvalidInput(
            "new value must be greater than old value".to_string(),
        ));
    }

    Ok(new - old)
}

/// Validate consistency parameters (ascending order)
pub fn validate_consistency_params(data: &[u64]) -> ZkpResult<()> {
    if data.is_empty() {
        return Err(ZkpError::InvalidInput("data cannot be empty".to_string()));
    }

    if data.len() == 1 {
        return Ok(()); // Single element is always consistent
    }

    for window in data.windows(2) {
        if window[0] > window[1] {
            return Err(ZkpError::InvalidInput(format!(
                "data is not in ascending order: {} > {}",
                window[0], window[1]
            )));
        }
    }

    Ok(())
}

/// Validate proof data format
pub fn validate_proof_data(data: &[u8], min_size: usize) -> ZkpResult<()> {
    if data.len() < min_size {
        return Err(ZkpError::InvalidProofFormat(format!(
            "proof data too short: expected at least {} bytes, got {}",
            min_size,
            data.len()
        )));
    }
    Ok(())
}

/// Validate commitment format
pub fn validate_commitment_format(commitment: &[u8], expected_size: usize) -> ZkpResult<()> {
    if commitment.len() != expected_size {
        return Err(ZkpError::InvalidProofFormat(format!(
            "invalid commitment size: expected {} bytes, got {}",
            expected_size,
            commitment.len()
        )));
    }
    Ok(())
}

/// Validate that a set has no duplicates
pub fn validate_unique_set(set: &[u64]) -> ZkpResult<()> {
    let mut sorted_set = set.to_vec();
    sorted_set.sort_unstable();

    for window in sorted_set.windows(2) {
        if window[0] == window[1] {
            return Err(ZkpError::InvalidInput(format!(
                "duplicate value {} found in set",
                window[0]
            )));
        }
    }

    Ok(())
}

/// Validate maximum set size
pub fn validate_set_size(set: &[u64], max_size: usize) -> ZkpResult<()> {
    if set.len() > max_size {
        return Err(ZkpError::InvalidInput(format!(
            "set size {} exceeds maximum allowed size {}",
            set.len(),
            max_size
        )));
    }
    Ok(())
}

/// Validate value bounds
pub fn validate_value_bounds(value: u64, max_value: u64) -> ZkpResult<()> {
    if value > max_value {
        return Err(ZkpError::InvalidInput(format!(
            "value {} exceeds maximum allowed value {}",
            value, max_value
        )));
    }
    Ok(())
}
