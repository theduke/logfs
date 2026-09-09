//! Legacy checkpoint schema; field order is frozen.
use crate::journal::data::{ByteCountU32, ByteCountU64, EntryPointer, KeyPath};
use crate::{DataOffset, journal::SequenceId};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyIndexEntry {
    pub key: KeyPath,
    pub sequence_id: SequenceId,
    pub file_offset: DataOffset,
    pub size: ByteCountU64,
    pub chunk_size: Option<ByteCountU32>,
}

/// An index that contains all keys and associated metadata.
///
/// An index can be written to the log to speed up re-opening.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyIndex {
    /// Pointer to a previous index location.
    /// If present, this index is only partial and does not contain a full
    /// snapshot. To build a full index, the parent must be read first.
    /// This index will contain all updates since the previous one.
    pub parent_entry: Option<EntryPointer>,

    /// The available keys. If [`Self::parent_entry`] is [`None`], this is a
    /// full snapshot, otherwise it's a partial snapshot since the last entry.
    pub keys: Vec<KeyIndexEntry>,
}

use crate::journal::{
    codec::deserialize_bounded,
    v3::{index::validate_restored_pointer, read},
};
use crate::{LogFsError, state::KeyPointer};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

pub(in crate::journal) fn restore_snapshot<R: io::Read + io::Seek>(
    reader: &read::LogReader<R>,
    pointer: EntryPointer,
    data: &[u8],
    max_decoded_len: usize,
    tree: &mut BTreeMap<String, KeyPointer>,
) -> Result<Option<EntryPointer>, LogFsError> {
    let data: KeyIndex = deserialize_bounded(data, max_decoded_len)?;
    if let Some(parent) = data.parent_entry
        && (parent.offset >= pointer.offset || parent.sequence >= pointer.sequence)
    {
        return Err(LogFsError::new_internal(
            "Checkpoint parent pointer is not strictly backward",
        ));
    }
    let parent = data.parent_entry;

    let mut snapshot_keys = BTreeSet::new();
    for item in data.keys {
        if !snapshot_keys.insert(item.key.clone()) {
            return Err(LogFsError::new_internal(
                "Checkpoint contains duplicate keys",
            ));
        }
        validate_restored_pointer(
            reader,
            pointer,
            item.sequence_id,
            item.file_offset,
            item.size,
            item.chunk_size,
            None,
        )?;
        // Note: ignore already existing keys, since they would
        // already contain newer data from a previous entry.
        tree.entry(item.key).or_insert_with(|| KeyPointer {
            sequence_id: item.sequence_id.as_u64(),
            file_offset: item.file_offset,
            size: item.size,
            chunk_size: item.chunk_size,
            hash: None,
            entry_nonce: None,
            log_identity: None,
        });
    }
    Ok(parent)
}
