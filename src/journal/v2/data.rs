//! Types representing the data written to the log.

use crate::journal::SequenceId;

// /// A magic marker used to
// #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone, Debug)]
// pub struct MagicMarker([u8; 24]);

// pub const MAGIC_MARKER: [u8; 24] = *b"$logfs_super_v000000002$";

/// Offset.
pub type Offset = u64;

pub type ByteCountU64 = u64;
pub type ByteCountU32 = u32;

pub type ChunkIndex = u32;

// ATTENTION: the types here may not be changed!
// Doing so would break backwards compatibility.
// The ONLY PERMISSIBLE CHANGE is adding new variants to enums, AS LONG AS the
// order of existing variants is not changed.
//
// These limitations result from the bincode serializer.

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Sha256Hash(pub [u8; 32]);

impl Sha256Hash {
    pub fn from_array(data: [u8; 32]) -> Self {
        Self(data)
    }
}

pub type KeyPath = String;

impl std::fmt::Debug for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sha256Hash")
            .field(&format_args!(
                "{:x}",
                generic_array::GenericArray::from(self.0)
            ))
            .finish()
    }
}

/// Metadata for a stored key.
/// This is written to the log.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyMeta {
    /// The full length of the data in bytes.
    pub size: ByteCountU64,
    /// Size of the individual chunks in bytes.
    /// If None, the key is stored in a single chunk.
    /// This is present to allow for adaptive chunk sizes so that large keys can
    /// be stored in large chunks.
    pub chunk_size: Option<ByteCountU32>,
    /// The hash of the full data.
    pub hash: Sha256Hash,
    /// The path of the key.
    pub path: KeyPath,
}

impl KeyMeta {
    /// Calculate the number of chunks based on total length and chunk size.
    pub fn chunk_count(&self) -> ChunkIndex {
        // TODO: use .div_ceil() once stabilized
        // https://github.com/rust-lang/rust/issues/88581
        if let Some(chunk_size) = self.chunk_size {
            compute_chunk_count(self.size, chunk_size)
        } else {
            1
        }
    }
}

pub fn compute_chunk_count(data_size: ByteCountU64, chunk_size: ByteCountU32) -> ChunkIndex {
    // TODO: use .div_ceil() once stabilized
    // https://github.com/rust-lang/rust/issues/88581
    ((data_size + chunk_size as u64 - 1) / chunk_size as u64) as ChunkIndex
}

/// Describes the rename of a key.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyRename {
    pub old_key: KeyPath,
    pub new_key: KeyPath,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ActionKeyInsert {
    pub meta: KeyMeta,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ActionKeyRename {
    pub renames: Vec<KeyRename>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ActionKeyDelete {
    pub deleted_keys: Vec<KeyPath>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyIndexEntry {
    pub entry: JournalEntryHeader,
    pub key: KeyMeta,
}

/// An index that contains all keys and associated metadata.
///
/// An index can be written to the log to speed up re-opening.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyIndex {
    pub keys: Vec<KeyIndexEntry>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ActionIndexWrite {
    pub size: ByteCountU64,
}

/// A file action in the log/journal.
///
/// Actions are written to files in a (de)serialized encoding.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum JournalAction {
    /// Insertion of a new key + value.
    KeyInsert(ActionKeyInsert),
    /// Rename of one ore multiple keys.
    KeyRename(ActionKeyRename),
    /// Deletion of one or multiple keys.
    KeyDelete(ActionKeyDelete),
    /// Persist a new full keyspace index.
    IndexWrite(ActionIndexWrite),
}

bitflags::bitflags! {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[repr(transparent)]
    pub struct JournalEntryHeaderFlags: u32 {
        const INCOMPLETE = 0b00000001;
    }
}

/// Metadata for an entry in the journal.
///
/// This is serialized separately from the JournalAction.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct JournalEntryHeader {
    /// The global file offset.
    /// Included for consistency checks.
    pub offset: Offset,

    /// Unique sequence number of the entry.
    /// Included for consistency checks.
    pub sequence_id: SequenceId,

    /// The byte size of the serialiazed [`JournalAction`] that follows the
    /// header.
    ///
    /// NOTE: this only includes the action, not any key data.
    /// Hence [`u32`] is more than large enough.
    pub action_size: ByteCountU32,

    pub flags: JournalEntryHeaderFlags,
}

impl JournalEntryHeader {
    pub const SERIALIZED_LEN: usize = 24;
}

/// A single entry in the log/journal.
///
/// An entry describes the changes to the log, and is optionally followed by
/// data (only for inserts).
#[derive(Debug)]
pub struct JournalEntry {
    pub header: JournalEntryHeader,
    pub action: JournalAction,
}

/// A "pointer" to a log entry.
///
/// Contains the information required for reading the entry.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EntryPointer {
    pub sequence: SequenceId,
    pub offset: Offset,
}

bitflags::bitflags! {
#[derive(serde::Serialize, serde::Deserialize)]
    pub struct SuperblockFlags : u32 {

    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum LogFormatVersion {
    V1 = 1,
    V2 = 2,
}

/// A superblock contains metadata about the log.
///
/// Superblocks are written to the header of a log file to enable both
/// consistency validations and quicker re-opening.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Superblock {
    pub format_version: LogFormatVersion,
    pub flags: SuperblockFlags,

    /// The maximum sequence id written to the log.
    pub active_sequence: u64,
    /// The offset specifying the tail of the log.
    /// This must be equal to the file size (if not used in raw mode).
    pub tail_offset: Offset,
    /// Metadata for the newest keyspace index in the log.
    /// Can be used for opening the log without doing a full scan.
    pub last_index_entry: Option<EntryPointer>,
}

impl Superblock {
    pub const SERIALIZED_LEN: u64 = 256;
    pub const HEADER_COUNT: u64 = 10;
    pub const HEADER_SIZE: u64 = Self::SERIALIZED_LEN * Self::HEADER_COUNT;
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_superblock_size() {
    //     let block = Superblock{
    //         format_version: LogFormatVersion::V2,
    //         flags: SuperblockFlags::empty(),
    //         active_sequence: 0,
    //         tail_offset: 0,
    //         last_index_entry: None,
    //     };
    //     let code = block.serialize().unwrap();
    //     assert_eq!(code.len() as u64, Superblock::SERIALIZED_LEN);
    // }

    #[test]
    fn test_entry_header_size() {
        let header = JournalEntryHeader {
            offset: 0,
            sequence_id: SequenceId::first(),
            action_size: 0,
            flags: JournalEntryHeaderFlags::empty(),
        };
        let code = bincode::serialize(&header).unwrap();
        assert_eq!(code.len(), JournalEntryHeader::SERIALIZED_LEN);
    }
}
