//! Little-endian byte helpers shared by backends and proof parsing.

/// Read a `u64` from `data` at `offset` if at least 8 bytes are available.
#[inline]
pub fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let slice = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Read a length-prefixed slice: consumes `[u32 len][payload...]` from the front of `reader`.
pub fn read_length_prefixed_u32<'a>(reader: &mut &'a [u8]) -> Option<&'a [u8]> {
    if reader.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(reader[0..4].try_into().ok()?) as usize;
    *reader = &reader[4..];
    if reader.len() < len {
        return None;
    }
    let out = &reader[..len];
    *reader = &reader[len..];
    Some(out)
}
