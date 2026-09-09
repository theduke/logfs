//! V3 byte framing, authentication domains, and recovery decoding.
use super::{
    ENTRY_ACTION_CHUNK, ENTRY_HEADER_CHUNK, codec,
    data::{self, Offset},
};
use crate::{LogFsError, crypto::Crypto, journal::SequenceId};
use sha2::Digest;
use std::io;

pub(super) const V3_INNER_MAGIC: [u8; 16] = *b"LOGFS-OPAQUE-V3\0";
pub(super) const V3_ROOT_SLOT_SIZE: u64 = 4096;
pub(super) const V3_ROOT_COUNT: u64 = 2;
pub(crate) const V3_HEADER_SIZE: u64 = V3_ROOT_SLOT_SIZE * V3_ROOT_COUNT;
pub(super) const V3_ROOT_RECORD_LEN: usize = V3_ROOT_SLOT_SIZE as usize;
pub(super) const V3_ROOT_SALT_LEN: usize = 16;
pub(super) const V3_NONCE_LEN: usize = 24;
pub(super) const V3_ROOT_OUTER_LEN: usize = V3_ROOT_SALT_LEN + V3_NONCE_LEN;
pub(super) const V3_ROOT_CLEAR_LEN: usize =
    V3_ROOT_RECORD_LEN - V3_ROOT_OUTER_LEN - Crypto::EXTRA_PAYLOAD_LEN;
pub(super) const V3_PLAIN_METADATA_CHECKSUM_LEN: usize = 32;
pub(super) const V3_FRAME_HEADER_CLEAR_LEN: usize = 256;

pub(super) const fn metadata_padding(encrypted: bool) -> usize {
    if encrypted {
        Crypto::EXTRA_PAYLOAD_LEN
    } else {
        V3_PLAIN_METADATA_CHECKSUM_LEN
    }
}

/// Complete searchable header, including the seed and authentication bytes.
pub(super) const fn frame_header_len(encrypted: bool) -> usize {
    V3_NONCE_LEN + V3_FRAME_HEADER_CLEAR_LEN + metadata_padding(encrypted)
}

pub(super) fn frame_len(
    action_plain: u64,
    payload_encoded: u64,
    encrypted: bool,
) -> Result<u64, LogFsError> {
    let action_encoded =
        super::limits::action().encoded_len(action_plain, metadata_padding(encrypted) as u64)?;
    u32::try_from(action_encoded)
        .map_err(|_| LogFsError::new_internal("V3 action exceeds u32 format limit"))?;
    (frame_header_len(encrypted) as u64)
        .checked_add(action_encoded)
        .and_then(|size| size.checked_add(payload_encoded))
        .ok_or_else(|| LogFsError::new_internal("V3 frame size overflow"))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct V3FrameHeader {
    pub(super) header: data::JournalEntryHeader,
    pub(super) previous_history: [u8; 32],
    pub(super) history: [u8; 32],
}

pub(super) fn decode_v3_frame_header(bytes: &[u8]) -> Result<V3FrameHeader, LogFsError> {
    let encoded_len = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| LogFsError::new_internal("Truncated v3 frame header"))?
            .try_into()
            .map_err(|_| LogFsError::new_internal("Truncated v3 frame header"))?,
    ) as usize;
    if encoded_len == 0 || encoded_len > bytes.len().saturating_sub(4) {
        return Err(LogFsError::new_internal("Invalid v3 frame header length"));
    }
    codec::deserialize(&bytes[4..4 + encoded_len])
}

pub(super) fn v3_history_commit(
    crypto: Option<&crate::crypto::V3Crypto>,
    previous: [u8; 32],
    identity: [u8; 16],
    entry_nonce: [u8; 24],
    action: &[u8],
) -> [u8; 32] {
    if let Some(crypto) = crypto {
        crypto.commit_history(&[&previous, &identity, &entry_nonce, action])
    } else {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"logfs/v3/plain-history");
        hasher.update(previous);
        hasher.update(identity);
        hasher.update(entry_nonce);
        hasher.update(action);
        hasher.finalize().into()
    }
}

pub(super) fn v3_nonce(mut entry_nonce: [u8; 24], chunk: data::ChunkIndex) -> [u8; 24] {
    let random_suffix = u32::from_le_bytes(
        entry_nonce[20..]
            .try_into()
            .expect("v3 nonce suffix is four bytes"),
    );
    entry_nonce[20..].copy_from_slice(&(random_suffix ^ chunk).to_le_bytes());
    entry_nonce
}

pub(super) fn v3_aad(
    identity: [u8; 16],
    entry_nonce: [u8; 24],
    chunk: data::ChunkIndex,
) -> [u8; 44] {
    let mut aad = [0u8; 44];
    aad[..16].copy_from_slice(&identity);
    aad[16..40].copy_from_slice(&entry_nonce);
    aad[40..].copy_from_slice(&chunk.to_le_bytes());
    aad
}

pub(super) fn append_plain_metadata_checksum(bytes: &mut Vec<u8>, aad: &[u8]) {
    let mut hasher = sha2::Sha256::new();
    hasher.update(aad);
    hasher.update(&*bytes);
    bytes.extend_from_slice(&hasher.finalize());
}

pub(super) fn verify_plain_metadata_checksum<'a>(
    bytes: &'a [u8],
    aad: &[u8],
) -> Result<&'a [u8], LogFsError> {
    let data_len = bytes
        .len()
        .checked_sub(V3_PLAIN_METADATA_CHECKSUM_LEN)
        .ok_or_else(|| LogFsError::new_internal("Truncated v3 metadata checksum"))?;
    let (data, expected) = bytes.split_at(data_len);
    let mut hasher = sha2::Sha256::new();
    hasher.update(aad);
    hasher.update(data);
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(LogFsError::new_internal("V3 metadata checksum mismatch"));
    }
    Ok(data)
}

pub(super) fn find_v3_entry_header_in_slice(
    crypto: Option<&Crypto>,
    v3_crypto: Option<&crate::crypto::V3Crypto>,
    identity: [u8; 16],
    sequence: SequenceId,
    bytes: &[u8],
    buffer_file_offset: u64,
    base_offset: u64,
) -> Option<(data::JournalEntryHeader, Offset, [u8; 24])> {
    let candidate_len = frame_header_len(crypto.is_some());
    if bytes.len() < candidate_len {
        return None;
    }
    for index in 0..=bytes.len() - candidate_len {
        let entry_nonce: [u8; 24] = bytes[index..index + 24].try_into().ok()?;
        let mut header_bytes = bytes[index + 24..index + candidate_len].to_vec();
        let aad = v3_aad(identity, entry_nonce, ENTRY_HEADER_CHUNK);
        let clear = if let Some(crypto) = v3_crypto {
            if crypto.authenticate_entry_candidate(
                v3_nonce(entry_nonce, ENTRY_HEADER_CHUNK),
                &aad,
                &mut header_bytes,
            ) {
                header_bytes.as_slice()
            } else {
                continue;
            }
        } else {
            let clear_len = header_bytes.len() - V3_PLAIN_METADATA_CHECKSUM_LEN;
            let (clear, expected) = header_bytes.split_at(clear_len);
            let mut hasher = sha2::Sha256::new();
            hasher.update(aad);
            hasher.update(clear);
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected {
                continue;
            }
            clear
        };
        if let Ok(frame) = decode_v3_frame_header(clear)
            && let header = frame.header
            && header.sequence_id == sequence
            && !header
                .flags
                .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
            && header.offset
                == buffer_file_offset
                    .checked_add(index as u64)?
                    .checked_sub(base_offset)?
        {
            return Some((header, index as u64, entry_nonce));
        }
    }
    None
}

pub(super) fn read_v3_entry(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    v3_crypto: Option<&crate::crypto::V3Crypto>,
    identity: [u8; 16],
    sequence: SequenceId,
) -> Result<(data::JournalEntry, [u8; 24]), LogFsError> {
    let mut entry_nonce = [0u8; 24];
    reader.read_exact(&mut entry_nonce)?;
    let header_size = frame_header_len(crypto.is_some()) - V3_NONCE_LEN;
    buffer.resize(header_size, 0);
    reader.read_exact(buffer)?;
    let header_aad = v3_aad(identity, entry_nonce, ENTRY_HEADER_CHUNK);
    let header_bytes = if let Some(crypto) = v3_crypto {
        crypto.decrypt_entry(
            v3_nonce(entry_nonce, ENTRY_HEADER_CHUNK),
            &header_aad,
            buffer,
        )?
    } else {
        verify_plain_metadata_checksum(buffer, &header_aad)?
    };
    let header = decode_v3_frame_header(header_bytes)?.header;
    if header.sequence_id != sequence {
        return Err(LogFsError::new_internal(
            "Recovered v3 entry has an unexpected sequence",
        ));
    }
    let action = read_entry_action_with_domain(
        reader,
        buffer,
        crypto,
        v3_crypto,
        &header,
        entry_nonce,
        identity,
    )?;
    Ok((data::JournalEntry { header, action }, entry_nonce))
}

pub(super) fn read_entry_action_with_domain(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    _crypto: Option<&Crypto>,
    v3_crypto: Option<&crate::crypto::V3Crypto>,
    header: &data::JournalEntryHeader,
    entry_nonce: [u8; 24],
    identity: [u8; 16],
) -> Result<data::JournalAction, LogFsError> {
    let action_size = header.action_size as usize;
    super::limits::action().check_encoded(
        action_size as u64,
        metadata_padding(v3_crypto.is_some()) as u64,
    )?;
    buffer.resize(action_size, 0);
    reader.read_exact(buffer)?;
    let aad = v3_aad(identity, entry_nonce, ENTRY_ACTION_CHUNK);
    let bytes = if let Some(crypto) = v3_crypto {
        crypto.decrypt_entry(v3_nonce(entry_nonce, ENTRY_ACTION_CHUNK), &aad, buffer)?
    } else {
        verify_plain_metadata_checksum(buffer, &aad)?
    };
    codec::deserialize_bounded(bytes, super::limits::action().plaintext as usize)
}
