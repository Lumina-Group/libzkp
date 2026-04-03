use crate::utils::error_handling::{ZkpError, ZkpResult};
use crate::utils::proof_helpers::{is_ascending_order, safe_sum};

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

    let sum = safe_sum(values)?;

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

    if !is_ascending_order(data) {
        return Err(ZkpError::InvalidInput(
            "data is not in ascending order".to_string(),
        ));
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
