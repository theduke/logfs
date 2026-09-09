//! Version-neutral bounded decoding and reserved chunk identifiers.
use super::data;
use crate::LogFsError;

pub(super) const MAX_CHECKPOINT_DECODED_BYTES: usize = 512 * 1024 * 1024;
pub(super) const MAX_ACTION_BYTES: usize = 512 * 1024 * 1024;

pub(super) fn deserialize_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, LogFsError> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(limit as u64)
        .deserialize(bytes)?)
}

pub(super) const ENTRY_HEADER_CHUNK: data::ChunkIndex = 0;
pub(super) const ENTRY_ACTION_CHUNK: data::ChunkIndex = 1;
pub(super) const ENTRY_FIRST_DATA_CHUNK: data::ChunkIndex = 2;
