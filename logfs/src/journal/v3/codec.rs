//! Postcard serialization for the v3 wire format.

use crate::LogFsError;

pub(super) fn serialize<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, LogFsError> {
    postcard::to_allocvec(value).map_err(postcard_error)
}

pub(super) fn serialized_size<T: serde::Serialize + ?Sized>(value: &T) -> Result<u64, LogFsError> {
    let size = postcard::experimental::serialized_size(value).map_err(postcard_error)?;
    u64::try_from(size).map_err(|_| LogFsError::new_internal("Serialized v3 value is too large"))
}

pub(super) fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, LogFsError> {
    deserialize_bounded(bytes, bytes.len())
}

pub(super) fn deserialize_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, LogFsError> {
    if bytes.len() > limit {
        return Err(LogFsError::new_internal(
            "Serialized v3 value exceeds resource limit",
        ));
    }
    let (value, remaining) = postcard::take_from_bytes(bytes).map_err(postcard_error)?;
    if !remaining.is_empty() {
        return Err(LogFsError::new_internal(
            "Serialized v3 value contains trailing bytes",
        ));
    }
    Ok(value)
}

fn postcard_error(error: postcard::Error) -> LogFsError {
    LogFsError::new_internal(format!("Invalid v3 Postcard payload: {error}"))
}
