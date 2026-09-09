//! Full v3 snapshots. The borrowed encoder avoids cloning the entire keyspace.
use super::data::{ByteCountU32, ByteCountU64, EntryPointer, KeyPath, Sha256Hash};
use super::{codec, data, limits, read, root::v3_entry_start};
use crate::Path;
use crate::journal::codec::{ENTRY_FIRST_DATA_CHUNK, MAX_CHECKPOINT_DECODED_BYTES};
use crate::{DataOffset, journal::SequenceId};
use crate::{LogFsError, state::KeyPointer};
use serde::{Serialize, ser::SerializeSeq};
use sha2::Digest;
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    io,
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) struct KeyIndexEntryV3 {
    pub key: KeyPath,
    pub sequence_id: SequenceId,
    pub entry_nonce: Option<[u8; 24]>,
    pub file_offset: DataOffset,
    pub size: ByteCountU64,
    pub chunk_size: Option<ByteCountU32>,
    pub hash: Option<Sha256Hash>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) struct KeyIndexV3 {
    pub keys: Vec<KeyIndexEntryV3>,
}

struct Snapshot<'a>(&'a BTreeMap<String, KeyPointer>);

impl Serialize for Snapshot<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Postcard structs have no envelope: the single Vec field in KeyIndexV3
        // is encoded identically to this sequence. Field order below is frozen.
        #[derive(Serialize)]
        struct Entry<'a> {
            key: &'a str,
            sequence_id: u64,
            entry_nonce: Option<[u8; 24]>,
            file_offset: u64,
            size: u64,
            chunk_size: Option<u32>,
            hash: Option<[u8; 32]>,
        }
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (key, ptr) in self.0 {
            seq.serialize_element(&Entry {
                key,
                sequence_id: ptr.sequence_id,
                entry_nonce: ptr.entry_nonce,
                file_offset: ptr.file_offset,
                size: ptr.size,
                chunk_size: ptr.chunk_size,
                hash: ptr.hash,
            })?;
        }
        seq.end()
    }
}

pub(super) fn serialize_snapshot(
    tree: &BTreeMap<String, KeyPointer>,
    encrypted: bool,
) -> Result<Vec<u8>, LogFsError> {
    let snapshot = Snapshot(tree);
    let size = codec::serialized_size(&snapshot)?;
    super::limits::checkpoint().encoded_len(
        size,
        if encrypted {
            crate::Crypto::EXTRA_PAYLOAD_LEN as u64
        } else {
            0
        },
    )?;
    codec::serialize(&snapshot)
}

pub(in crate::journal) fn validate_restored_pointer<R: io::Read + io::Seek>(
    reader: &read::LogReader<R>,
    checkpoint: EntryPointer,
    sequence: SequenceId,
    file_offset: u64,
    size: u64,
    chunk_size: Option<u32>,
    entry_nonce: Option<[u8; 24]>,
) -> Result<(), LogFsError> {
    if sequence >= checkpoint.sequence {
        return Err(LogFsError::new_internal(
            "Checkpoint key sequence is not older than its checkpoint",
        ));
    }
    if chunk_size == Some(0) {
        return Err(LogFsError::new_internal(
            "Checkpoint contains a zero chunk size",
        ));
    }
    let chunks = if size == 0 && entry_nonce.is_none() {
        0
    } else if let Some(chunk) = chunk_size {
        let count = size.div_ceil(chunk as u64);
        count.max(1)
    } else {
        1
    };
    if chunks > (u32::MAX - ENTRY_FIRST_DATA_CHUNK + 1) as u64 {
        return Err(LogFsError::new_internal(
            "Checkpoint chunk count exceeds format limits",
        ));
    }
    let padding = reader.crypto_padding();
    let occupied = size
        .checked_add(
            padding
                .checked_mul(chunks)
                .ok_or_else(|| LogFsError::new_internal("Checkpoint payload size overflow"))?,
        )
        .ok_or_else(|| LogFsError::new_internal("Checkpoint payload size overflow"))?;
    let payload_end = file_offset
        .checked_add(occupied)
        .ok_or_else(|| LogFsError::new_internal("Checkpoint payload offset overflow"))?;
    let first_data = reader
        .base_offset()
        .checked_add(if reader.v3_identity().is_some() {
            v3_entry_start(reader.base_offset())?
        } else {
            data::Superblock::HEADER_SIZE
        })
        .ok_or_else(|| LogFsError::new_internal("Checkpoint region offset overflow"))?;
    let checkpoint_absolute = reader
        .base_offset()
        .checked_add(checkpoint.offset)
        .ok_or_else(|| LogFsError::new_internal("Checkpoint entry offset overflow"))?;
    if file_offset < first_data
        || file_offset >= checkpoint_absolute
        || payload_end > reader.committed_end()?
    {
        return Err(LogFsError::new_internal(
            "Checkpoint value pointer is outside committed history",
        ));
    }
    Ok(())
}

pub(super) fn restore_index<R: io::Read + io::Seek>(
    reader: &mut read::LogReader<R>,
    pointer: EntryPointer,
) -> Result<BTreeMap<Path, KeyPointer>, LogFsError> {
    struct BoundedVecWriter {
        bytes: Vec<u8>,
        max_len: usize,
    }
    impl io::Write for BoundedVecWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) > self.max_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "checkpoint expands beyond committed log bounds",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut tree = BTreeMap::<Path, KeyPointer>::new();
    let max_decoded_len = usize::try_from(reader.committed_region_len())
        .unwrap_or(usize::MAX)
        .min(if reader.v3_identity().is_some() {
            limits::checkpoint().plaintext as usize
        } else {
            MAX_CHECKPOINT_DECODED_BYTES
        });

    tracing::trace!(
        sequence=%pointer.sequence.as_u64(),
        offset=%pointer.offset,
        "restoring index"
    );

    let mut prev_pointer = Some(pointer);
    let mut buffer = Vec::new();
    let mut visited = BTreeSet::new();

    while let Some(pointer) = prev_pointer {
        if !visited.insert((pointer.sequence.as_u64(), pointer.offset)) {
            return Err(LogFsError::new_internal("Checkpoint parent cycle detected"));
        }
        reader.seek_to_pointer(pointer)?;

        let (entry, data) = reader.next_entry(Some(&mut buffer))?;
        match entry.entry.action {
            data::JournalAction::IndexWrite(header) => {
                let actual_hash: [u8; 32] = sha2::Sha256::digest(data).into();
                if actual_hash != header.hash.0 {
                    return Err(LogFsError::new_internal("Checkpoint payload hash mismatch"));
                }
                let data = if let Some(compression) = header.compression {
                    match compression {
                        data::CompressionFormat::Brotli => {
                            let mut data: &[u8] = data;
                            let mut buffer = BoundedVecWriter {
                                bytes: Vec::new(),
                                max_len: max_decoded_len,
                            };
                            brotli::BrotliDecompress(&mut data, &mut buffer)?;
                            Cow::Owned(buffer.bytes)
                        }
                    }
                } else {
                    Cow::Borrowed(data)
                };

                prev_pointer = crate::journal::v2::index::restore_snapshot(
                    reader,
                    pointer,
                    &data,
                    max_decoded_len,
                    &mut tree,
                )?;
            }
            data::JournalAction::IndexWriteV3(header) => {
                let actual_hash: [u8; 32] = sha2::Sha256::digest(data).into();
                if actual_hash != header.hash.0 {
                    return Err(LogFsError::new_internal("Checkpoint payload hash mismatch"));
                }
                let decoded = if let Some(data::CompressionFormat::Brotli) = header.compression {
                    let mut input: &[u8] = data;
                    let mut output = BoundedVecWriter {
                        bytes: Vec::new(),
                        max_len: max_decoded_len,
                    };
                    brotli::BrotliDecompress(&mut input, &mut output)?;
                    Cow::Owned(output.bytes)
                } else {
                    Cow::Borrowed(data)
                };
                let index: KeyIndexV3 = codec::deserialize_bounded(&decoded, max_decoded_len)?;
                prev_pointer = None;
                for item in index.keys {
                    validate_restored_pointer(
                        reader,
                        pointer,
                        item.sequence_id,
                        item.file_offset,
                        item.size,
                        item.chunk_size,
                        item.entry_nonce,
                    )?;
                    if item.entry_nonce.is_none() {
                        return Err(LogFsError::new_internal(
                            "V3 checkpoint key is missing its entry nonce",
                        ));
                    }
                    if tree
                        .insert(
                            item.key,
                            KeyPointer {
                                sequence_id: item.sequence_id.as_u64(),
                                file_offset: item.file_offset,
                                size: item.size,
                                chunk_size: item.chunk_size,
                                hash: item.hash.map(|hash| hash.0),
                                entry_nonce: item.entry_nonce,
                                log_identity: reader.v3_identity(),
                            },
                        )
                        .is_some()
                    {
                        return Err(LogFsError::new_internal(
                            "V3 checkpoint contains duplicate keys",
                        ));
                    }
                }
            }
            _ => {
                return Err(LogFsError::new_internal(
                    "Invalid index pointer: log entry is not an index",
                ));
            }
        }
    }

    tracing::debug!(key_count=%tree.len(), "index restored");

    Ok(tree)
}
