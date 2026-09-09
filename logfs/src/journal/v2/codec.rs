//! Frozen legacy root and entry decoding used by open, export, and migration.
use super::data::{self, Offset};
use crate::journal::codec::{
    ENTRY_ACTION_CHUNK, ENTRY_HEADER_CHUNK, MAX_ACTION_BYTES, deserialize_legacy_bounded,
};
use crate::journal::v3::{IndexedSuperBlock, RootFormat};
use crate::{LogFsError, crypto::Crypto, journal::SequenceId};
use std::io::{self, Read, Seek, SeekFrom};

/// Try to find a valid entry header at an arbitrary position in a buffer.
/// Useful for recovery of corrupted logs.
pub(in crate::journal) fn find_entry_header_in_slice(
    crypto: Option<&Crypto>,
    sequence: SequenceId,
    data: &[u8],
    buffer_file_offset: u64,
    base_offset: u64,
) -> Option<(data::JournalEntryHeader, Offset)> {
    let header_len = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto.map(|c| c.extra_payload_len() as usize).unwrap_or(0);
    if data.len() < header_len {
        return None;
    }
    if let Some(crypto) = crypto {
        for index in 0..=(data.len() - header_len) {
            if index % 100_000 == 0 {
                tracing::trace!(chunk_index=%index, "trying to find entry");
            }
            let mut slice = data[index..index + header_len].to_vec();
            let decrypted =
                match crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, &mut slice) {
                    Ok(d) => d,
                    Err(_) => {
                        continue;
                    }
                };

            match crate::encoding::deserialize::<data::JournalEntryHeader>(decrypted) {
                Ok(header)
                    if header.sequence_id == sequence
                        && !header
                            .flags
                            .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
                        && header.offset
                            == buffer_file_offset
                                .checked_add(index as u64)?
                                .checked_sub(base_offset)? =>
                {
                    return Some((header, index as u64));
                }
                Err(_) => continue,
                _ => continue,
            }
        }
        None
    } else {
        for index in 0..=(data.len() - header_len) {
            let slice = &data[index..index + header_len];
            if let Ok(header) = crate::encoding::deserialize::<data::JournalEntryHeader>(slice)
                && header.sequence_id == sequence
                && !header
                    .flags
                    .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
                && header.offset
                    == buffer_file_offset
                        .checked_add(index as u64)?
                        .checked_sub(base_offset)?
            {
                return Some((header, index as u64));
            }
        }
        None
    }
}

pub(in crate::journal) fn read_entry_header(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    sequence: SequenceId,
) -> Result<data::JournalEntryHeader, LogFsError> {
    let size = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto.map(|c| c.extra_payload_len() as usize).unwrap_or(0);
    buffer.resize(size, 0);

    // Read into buffer.
    reader.read_exact(buffer)?;

    // Decrypt.
    let data = if let Some(crypto) = &crypto {
        crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, buffer)?
    } else {
        buffer
    };

    let header: data::JournalEntryHeader = crate::encoding::deserialize(data)?;
    Ok(header)
}

pub(in crate::journal) fn read_entry_action(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    header: &data::JournalEntryHeader,
) -> Result<data::JournalAction, LogFsError> {
    let action_size = header.action_size as usize;
    if action_size > MAX_ACTION_BYTES {
        return Err(LogFsError::new_internal(
            "Journal action exceeds resource limit",
        ));
    }
    buffer.resize(action_size, 0);

    // Read into buffer.
    reader.read_exact(buffer)?;

    // Decrypt.

    let action_data = if let Some(crypto) = &crypto {
        crypto.decrypt_data_ref(header.sequence_id.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
    } else {
        buffer
    };

    let action: data::JournalAction = deserialize_legacy_bounded(action_data, MAX_ACTION_BYTES)?;
    Ok(action)
}

pub(in crate::journal) fn read_entry(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    sequence: SequenceId,
) -> Result<data::JournalEntry, LogFsError> {
    let header = read_entry_header(reader, buffer, crypto, sequence)?;
    let action = read_entry_action(reader, buffer, crypto, &header)?;

    Ok(data::JournalEntry { header, action })
}

pub(in crate::journal) fn read_roots<R: Read + Seek>(
    reader: &mut R,
    base_offset: u64,
    file_end: u64,
    crypto: Option<&Crypto>,
) -> Result<Option<IndexedSuperBlock>, LogFsError> {
    // A v2 value may occupy offsets used by the opaque v3 roots. Prefer a
    // fully validated legacy root set before probing v3; arbitrary payload
    // bytes must never decide the format.
    reader.seek(SeekFrom::Start(base_offset))?;
    let mut legacy_best = None;
    for index in 0..data::Superblock::HEADER_COUNT as usize {
        let root_end = base_offset
            .checked_add((index as u64 + 1) * data::Superblock::SERIALIZED_LEN)
            .ok_or_else(|| LogFsError::new_internal("Legacy root offset overflow"))?;
        if root_end > file_end {
            break;
        }
        let mut raw = vec![0; data::Superblock::SERIALIZED_LEN as usize];
        reader.read_exact(&mut raw)?;
        if let Some(crypto) = crypto {
            raw = match crypto.decrypt_data(0, index as u32, raw) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
        }
        let Ok(candidate) = crate::encoding::deserialize::<data::Superblock>(&raw) else {
            continue;
        };
        if candidate.format_version != data::LogFormatVersion::V2 {
            continue;
        }
        let format = RootFormat::LegacyV2;
        if crate::journal::v3::read::validate_root(&candidate, &format, base_offset, file_end)
            .is_err()
        {
            continue;
        }
        if legacy_best.as_ref().is_none_or(|old: &IndexedSuperBlock| {
            candidate.active_sequence > old.block.active_sequence
        }) {
            legacy_best = Some(IndexedSuperBlock {
                block: candidate,
                index,
                format,
            });
        }
    }
    Ok(legacy_best)
}
