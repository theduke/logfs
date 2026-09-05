use std::{
    io::{BufWriter, Cursor, Seek, SeekFrom, Write},
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use ring::rand::SecureRandom;
use sha2::Digest;

use crate::{
    KeyLock, LogFsError,
    crypto::Crypto,
    journal::{
        SequenceId,
        v2::{ENTRY_ACTION_CHUNK, ENTRY_HEADER_CHUNK, data::EntryPointer},
    },
    state::KeyPointer,
};

use super::{
    ENTRY_FIRST_DATA_CHUNK, IndexedSuperBlock, PersistedEntry, State,
    data::{self, ByteCountU64},
};

pub(crate) const FAIL_METADATA_WRITE: u8 = 1;
pub(crate) const FAIL_DATA_WRITE: u8 = 2;
pub(crate) const FAIL_DATA_FLUSH: u8 = 3;
pub(crate) const FAIL_DATA_SYNC: u8 = 4;
pub(crate) const FAIL_ROOT_WRITE: u8 = 5;
pub(crate) const FAIL_ROOT_SYNC: u8 = 6;

#[cfg(test)]
thread_local! {
    static TEST_FAIL_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn inject_next_io_failure(point: u8) {
    TEST_FAIL_POINT.with(|value| value.set(point));
}

fn maybe_fail_io(point: u8) -> std::io::Result<()> {
    #[cfg(test)]
    if TEST_FAIL_POINT.with(|value| {
        if value.get() == point {
            value.set(0);
            true
        } else {
            false
        }
    }) {
        return Err(std::io::Error::other("injected persistence I/O failure"));
    }
    let _ = point;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct TaintedFlag(Arc<AtomicBool>);

impl TaintedFlag {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn set_tainted(&self) {
        self.0.swap(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_tainted(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub(crate) struct LogWriter {
    /// Offset inside the file.
    /// Needed when the config specifies that the db should start at an offset.
    base_offset: u64,

    crypto: Option<Arc<Crypto>>,
    next_sequence: SequenceId,
    offset: data::Offset,
    writer: BufWriter<std::fs::File>,
    active_superblock: IndexedSuperBlock,
    tainted: TaintedFlag,

    incomplete_entry_in_progress: bool,
    // TODO: implement index recording!
    #[allow(dead_code)]
    actions_since_last_index_write: u64,

    last_written_index: Option<data::EntryPointer>,
    current_crypto_domain: Option<u64>,
    durable: Arc<AtomicBool>,
    region_len: Option<u64>,
}

impl std::fmt::Debug for LogWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogWriter")
            .field("base_offset", &self.base_offset)
            .field("next_sequence", &self.next_sequence)
            .field("offset", &self.offset)
            .field("writer", &self.writer)
            .field("active_superblock", &self.active_superblock)
            .field(
                "incomplete_entry_in_progress",
                &self.incomplete_entry_in_progress,
            )
            .field(
                "actions_since_last_index_write",
                &self.actions_since_last_index_write,
            )
            .field("last_written_index", &self.last_written_index)
            .field("current_crypto_domain", &self.current_crypto_domain)
            .finish()
    }
}

impl LogWriter {
    pub(crate) fn offset(&self) -> data::Offset {
        self.offset
    }

    pub(crate) fn flush(&mut self) -> Result<(), LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        self.writer.flush().map_err(|error| {
            self.tainted.set_tainted();
            LogFsError::from(error)
        })
    }

    pub(crate) fn sync(&mut self) -> Result<(), LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        let result = self
            .writer
            .flush()
            .and_then(|()| self.writer.get_ref().sync_all());
        result.map_err(|error| {
            self.tainted.set_tainted();
            LogFsError::from(error)
        })
    }

    pub(crate) fn backing_clone(&self) -> Result<std::fs::File, LogFsError> {
        Ok(self.writer.get_ref().try_clone()?)
    }

    pub(super) fn active_superblock(&self) -> &IndexedSuperBlock {
        &self.active_superblock
    }

    pub(crate) fn create_new(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        file: std::fs::File,
        base_offset: u64,
        durable: Arc<AtomicBool>,
        region_len: Option<u64>,
    ) -> Result<Self, LogFsError> {
        let v3_entry_start = super::v3_entry_start(base_offset)?;
        if region_len.is_some_and(|limit| limit < v3_entry_start) {
            return Err(LogFsError::new_internal(
                "Configured region is smaller than the v3 root area",
            ));
        }
        let random = ring::rand::SystemRandom::new();
        let mut identity = [0u8; 16];
        random
            .fill(&mut identity)
            .map_err(|_| LogFsError::new_internal("Could not generate v3 log identity"))?;
        let first_entry_offset = base_offset
            .checked_add(v3_entry_start)
            .ok_or_else(|| LogFsError::new_internal("Base offset overflow"))?;
        let mut s = Self {
            base_offset,
            crypto,
            next_sequence: SequenceId::first(),
            offset: first_entry_offset,
            writer: BufWriter::new(file),
            incomplete_entry_in_progress: false,
            active_superblock: IndexedSuperBlock {
                block: data::Superblock {
                    format_version: data::LogFormatVersion::V3,
                    flags: data::SuperblockFlags::empty(),
                    active_sequence: 0,
                    tail_offset: v3_entry_start,
                    last_index_entry: None,
                },
                index: 0,
                format: super::RootFormat::V3 {
                    identity,
                    generation: 0,
                    last_nonce_domain: u64::from_le_bytes(identity[..8].try_into().unwrap()),
                },
            },
            actions_since_last_index_write: 0,
            tainted,
            last_written_index: None,
            current_crypto_domain: None,
            durable,
            region_len,
        };

        s.create_superblocks()?;
        s.writer.seek(SeekFrom::Start(s.offset))?;

        Ok(s)
    }

    pub(super) fn open(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        mut file: std::fs::File,
        base_offset: u64,
        block: IndexedSuperBlock,
        durable: Arc<AtomicBool>,
        region_len: Option<u64>,
    ) -> Result<Self, LogFsError> {
        let root_count = match block.format {
            super::RootFormat::LegacyV2 => data::Superblock::HEADER_COUNT,
            super::RootFormat::V3 { .. } => super::V3_ROOT_COUNT,
        };
        if block.index >= root_count as usize {
            return Err(LogFsError::new_internal("Invalid active root slot"));
        }

        let offset = base_offset
            .checked_add(block.block.tail_offset)
            .ok_or_else(|| LogFsError::new_internal("Committed tail offset overflow"))?;
        file.seek(SeekFrom::Start(offset))?;

        let s = Self {
            base_offset,
            crypto,
            next_sequence: SequenceId::from_u64(block.block.active_sequence + 1),
            offset,
            incomplete_entry_in_progress: false,
            writer: BufWriter::new(file),
            actions_since_last_index_write: block
                .block
                .last_index_entry
                .map(|entry| block.block.active_sequence - entry.sequence.as_u64())
                .unwrap_or(block.block.active_sequence),
            active_superblock: block,
            tainted,
            last_written_index: None,
            current_crypto_domain: None,
            durable,
            region_len,
        };

        Ok(s)
    }

    fn crypto(&self) -> Option<&Crypto> {
        self.crypto.as_deref()
    }

    fn data_padding(&self) -> u64 {
        self.crypto()
            .map(|c| c.extra_payload_len())
            .unwrap_or_default()
    }

    fn v3_identity(&self) -> Option<[u8; 16]> {
        match self.active_superblock.format {
            super::RootFormat::V3 { identity, .. } => Some(identity),
            super::RootFormat::LegacyV2 => None,
        }
    }

    fn metadata_padding(&self) -> u64 {
        if self.v3_identity().is_some() {
            self.crypto()
                .map(|crypto| crypto.extra_payload_len())
                .unwrap_or(super::V3_PLAIN_METADATA_CHECKSUM_LEN as u64)
        } else {
            self.data_padding()
        }
    }

    fn ensure_capacity(&self, additional: u64) -> Result<(), LogFsError> {
        let relative = self
            .offset
            .checked_sub(self.base_offset)
            .ok_or_else(|| LogFsError::new_internal("Writer offset precedes region"))?;
        let end = relative
            .checked_add(additional)
            .ok_or_else(|| LogFsError::new_internal("Backing region offset overflow"))?;
        if self.region_len.is_some_and(|limit| end > limit) {
            return Err(LogFsError::new_internal(
                "Write would exceed configured backing region",
            ));
        }
        Ok(())
    }

    fn create_superblocks(&mut self) -> Result<(), LogFsError> {
        assert_eq!(self.next_sequence, SequenceId::first());
        assert_eq!(self.writer.stream_position()?, self.base_offset);

        for _ in 0..super::V3_ROOT_COUNT {
            self.write_next_superblock()?;
        }
        self.offset = self
            .base_offset
            .checked_add(super::v3_entry_start(self.base_offset)?)
            .ok_or_else(|| LogFsError::new_internal("Root area offset overflow"))?;
        debug_assert_eq!(self.offset, self.writer.stream_position().unwrap());

        Ok(())
    }

    fn write_next_superblock(&mut self) -> Result<(), LogFsError> {
        let root_count = match self.active_superblock.format {
            super::RootFormat::LegacyV2 => data::Superblock::HEADER_COUNT,
            super::RootFormat::V3 { .. } => super::V3_ROOT_COUNT,
        };
        let index = if (self.active_superblock.index as u64) < root_count - 1 {
            self.active_superblock.index + 1
        } else {
            0
        };

        let format = match self.active_superblock.format {
            super::RootFormat::LegacyV2 => super::RootFormat::LegacyV2,
            super::RootFormat::V3 {
                identity,
                generation,
                last_nonce_domain,
            } => super::RootFormat::V3 {
                identity,
                generation: generation
                    .checked_add(1)
                    .ok_or_else(|| LogFsError::new_internal("V3 root generation exhausted"))?,
                last_nonce_domain,
            },
        };
        let block = IndexedSuperBlock {
            index,
            block: data::Superblock {
                format_version: self.active_superblock.block.format_version,
                flags: self.active_superblock.block.flags,
                active_sequence: self.next_sequence.as_u64() - 1,
                tail_offset: self.offset - self.base_offset,
                last_index_entry: self
                    .last_written_index
                    .or(self.active_superblock.block.last_index_entry),
            },
            format,
        };
        self.apply_superblock(block)
    }

    fn apply_superblock(&mut self, block: IndexedSuperBlock) -> Result<(), LogFsError> {
        match self.try_apply_superblock(block) {
            Err(err) => {
                self.tainted.set_tainted();
                Err(err)
            }
            other => other,
        }
    }

    fn try_apply_superblock(&mut self, block: IndexedSuperBlock) -> Result<(), LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }

        debug_assert!(!self.incomplete_entry_in_progress);
        debug_assert_eq!(block.block.active_sequence, self.next_sequence.as_u64() - 1);
        debug_assert_eq!(block.block.tail_offset, self.offset - self.base_offset);
        if let Some(ptr) = &block.block.last_index_entry {
            debug_assert!(ptr.sequence < self.next_sequence);
        }

        let buffer = match block.format {
            super::RootFormat::LegacyV2 => {
                let block_size = data::Superblock::SERIALIZED_LEN - self.data_padding();
                let mut buffer = bincode::serialize(&block.block)?;
                if buffer.len() as u64 >= block_size {
                    return Err(LogFsError::new_internal("Legacy superblock is too large"));
                }
                buffer.resize(block_size as usize, 0);
                if let Some(crypto) = self.crypto() {
                    crypto.encrypt_data(0, block.index as u32, &mut buffer)?;
                }
                buffer
            }
            super::RootFormat::V3 {
                identity,
                generation,
                last_nonce_domain,
            } => {
                let mut payload = bincode::serialize(&super::V3RootPayload {
                    block: block.block.clone(),
                    last_nonce_domain,
                })?;
                let encrypted = self.crypto.is_some();
                // Root nonces are random 96-bit values. Limiting one identity
                // to 2^32 publications bounds the birthday-collision
                // probability to approximately 2^-33.
                if encrypted && generation > u32::MAX as u64 {
                    return Err(LogFsError::new_internal(
                        "Encrypted v3 root nonce budget exhausted",
                    ));
                }
                let final_payload_len = payload.len()
                    + if encrypted {
                        Crypto::EXTRA_PAYLOAD_LEN
                    } else {
                        0
                    };
                let mut buffer = vec![0u8; super::V3_ROOT_RECORD_LEN];
                buffer[..8].copy_from_slice(&super::V3_ROOT_MAGIC);
                buffer[8..16].copy_from_slice(&super::V3_ROOT_MAGIC);
                buffer[16] = if encrypted {
                    super::V3_ROOT_FLAG_ENCRYPTED
                } else {
                    0
                };
                buffer[20..28].copy_from_slice(&generation.to_le_bytes());
                buffer[28..44].copy_from_slice(&identity);
                let mut nonce = [0u8; 12];
                if encrypted {
                    ring::rand::SystemRandom::new()
                        .fill(&mut nonce)
                        .map_err(|_| {
                            LogFsError::new_internal("Could not generate v3 root nonce")
                        })?;
                }
                buffer[44..56].copy_from_slice(&nonce);
                let final_payload_len = u32::try_from(final_payload_len)
                    .map_err(|_| LogFsError::new_internal("V3 root payload length overflow"))?;
                buffer[56..60].copy_from_slice(&final_payload_len.to_le_bytes());
                if encrypted {
                    self.crypto()
                        .ok_or_else(|| LogFsError::new_internal("Missing v3 encryption key"))?
                        .encrypt_with_nonce(
                            nonce,
                            &buffer[..super::V3_ROOT_PREFIX_LEN],
                            &mut payload,
                        )?;
                }
                let payload_end = super::V3_ROOT_PREFIX_LEN + payload.len();
                let required = payload_end + if encrypted { 0 } else { 32 };
                if required > buffer.len() {
                    return Err(LogFsError::new_internal("V3 root payload is too large"));
                }
                buffer[super::V3_ROOT_PREFIX_LEN..payload_end].copy_from_slice(&payload);
                if !encrypted {
                    let hash: [u8; 32] = sha2::Sha256::digest(&buffer[..payload_end]).into();
                    buffer[payload_end..payload_end + 32].copy_from_slice(&hash);
                }
                buffer[super::V3_ROOT_MAGIC_COPY_OFFSET..].copy_from_slice(&super::V3_ROOT_MAGIC);
                buffer
            }
        };

        let offset = self
            .base_offset
            .checked_add(block.format.root_offset(self.base_offset, block.index)?)
            .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow"))?;

        self.writer.seek(SeekFrom::Start(offset))?;
        maybe_fail_io(FAIL_ROOT_WRITE)?;
        self.writer.write_all(&buffer)?;
        self.writer.flush()?;

        self.writer.seek(SeekFrom::Start(self.offset))?;

        self.active_superblock = block;

        Ok(())
    }

    fn prepare_entry_domain(&mut self) -> Result<Option<u64>, LogFsError> {
        let super::RootFormat::V3 {
            identity,
            generation,
            last_nonce_domain,
        } = self.active_superblock.format
        else {
            self.current_crypto_domain = None;
            return Ok(None);
        };
        let domain = last_nonce_domain
            .checked_add(1)
            .ok_or_else(|| LogFsError::new_internal("V3 nonce domain exhausted"))?;
        self.active_superblock.format = super::RootFormat::V3 {
            identity,
            generation,
            last_nonce_domain: domain,
        };
        self.write_next_superblock()?;
        // An encrypted nonce domain must reach stable storage before any
        // ciphertext using it is emitted. This is part of the v3 format, not a
        // change to the legacy flush contract.
        if self.crypto.is_some() {
            self.sync()?;
        }
        self.current_crypto_domain = Some(domain);
        Ok(Some(domain))
    }

    pub(super) fn begin_write_session(&mut self) -> Result<(), LogFsError> {
        let super::RootFormat::V3 {
            identity,
            generation,
            ..
        } = self.active_superblock.format
        else {
            return Ok(());
        };
        let mut bytes = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| LogFsError::new_internal("Could not generate v3 nonce domain"))?;
        self.active_superblock.format = super::RootFormat::V3 {
            identity,
            generation,
            last_nonce_domain: u64::from_le_bytes(bytes),
        };
        self.write_next_superblock()?;
        if self.crypto.is_some() {
            self.sync()?;
        }
        Ok(())
    }

    fn publish_committed_root(&mut self) -> Result<(), LogFsError> {
        if self.durable.load(std::sync::atomic::Ordering::SeqCst) {
            maybe_fail_io(FAIL_DATA_FLUSH)?;
            self.writer.flush()?;
            maybe_fail_io(FAIL_DATA_SYNC)?;
            self.writer.get_ref().sync_data()?;
        }
        self.write_next_superblock()?;
        if self.durable.load(std::sync::atomic::Ordering::SeqCst) {
            maybe_fail_io(FAIL_ROOT_SYNC)?;
            self.writer.get_ref().sync_all()?;
        }
        Ok(())
    }

    pub(super) fn write_journal_entry(
        &mut self,
        chunk_size: u32,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        incomplete: bool,
    ) -> Result<PersistedEntry, LogFsError> {
        if chunk_size == 0 && data.as_ref().is_some_and(|value| !value.is_empty()) {
            return Err(LogFsError::new_internal(
                "Chunk size must be greater than zero",
            ));
        }
        let action_plain_len = bincode::serialized_size(&action)?;
        let metadata_padding = self.metadata_padding();
        let domain_len = if matches!(self.active_superblock.format, super::RootFormat::V3 { .. }) {
            8
        } else {
            0
        };
        let total_len = [
            domain_len,
            data::JournalEntryHeader::SERIALIZED_LEN as u64,
            metadata_padding,
            action_plain_len,
            metadata_padding,
            action.payload_len(self.crypto()),
        ]
        .into_iter()
        .try_fold(0u64, |total, length| total.checked_add(length))
        .ok_or_else(|| LogFsError::new_internal("Journal entry size overflow"))?;
        self.ensure_capacity(total_len)?;
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        match self.try_write_journal_entry(chunk_size, action, data, incomplete) {
            Err(err) => {
                self.tainted.set_tainted();
                Err(err)
            }
            Ok(e) => {
                tracing::trace!(entry=?e, "wrote journal entry");
                Ok(e)
            }
        }
    }

    fn try_write_journal_entry(
        &mut self,
        chunk_size: u32,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        incomplete: bool,
    ) -> Result<PersistedEntry, LogFsError> {
        let sequence = self.next_sequence;

        self.prepare_entry_domain()?;

        debug_assert_eq!(self.writer.stream_position().unwrap(), self.offset);
        let header = self.write_action(&action, incomplete)?;

        let data_offset = self.offset;
        if let Some(data) = data {
            self.write_data(chunk_size, data)?
        } else {
            0
        };

        self.writer.flush()?;

        self.next_sequence = sequence.try_increment()?;
        self.incomplete_entry_in_progress = incomplete;

        debug_assert_eq!(self.offset, self.writer.stream_position().unwrap());

        if !incomplete {
            if action.is_index_write() {
                self.last_written_index = Some(EntryPointer {
                    sequence,
                    offset: header.offset,
                });
            }

            self.publish_committed_root()?;
        }

        let entry = PersistedEntry {
            entry: data::JournalEntry { header, action },
            file_data_offset: data_offset,
            crypto_domain: self.current_crypto_domain,
            log_identity: self.v3_identity(),
        };
        self.current_crypto_domain = None;

        Ok(entry)
    }

    pub fn write_action(
        &mut self,
        action: &data::JournalAction,
        incomplete: bool,
    ) -> Result<data::JournalEntryHeader, LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        debug_assert!(!self.incomplete_entry_in_progress);
        debug_assert_eq!(self.offset, self.writer.stream_position()?);

        let sequence = self.next_sequence;
        let entry_offset = self.offset - self.base_offset;

        let mut action_data = bincode::serialize(&action)?;
        let domain = self
            .current_crypto_domain
            .unwrap_or_else(|| sequence.as_u64());
        if let Some(identity) = self.v3_identity() {
            let aad = super::v3_aad(identity, domain, ENTRY_ACTION_CHUNK);
            if let Some(crypto) = self.crypto.as_ref() {
                crypto.encrypt_data_with_aad(domain, ENTRY_ACTION_CHUNK, &aad, &mut action_data)?;
            } else {
                super::append_plain_metadata_checksum(&mut action_data, &aad);
            }
        } else if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(domain, ENTRY_ACTION_CHUNK, &mut action_data)?;
        }
        let action_data_len = action_data.len();

        let flags = if incomplete {
            data::JournalEntryHeaderFlags::INCOMPLETE
        } else {
            data::JournalEntryHeaderFlags::empty()
        };
        let header = data::JournalEntryHeader {
            offset: entry_offset,
            sequence_id: sequence,
            action_size: u32::try_from(action_data_len)
                .map_err(|_| LogFsError::new_internal("Journal action exceeds format limit"))?,
            flags,
        };
        let mut header_data = bincode::serialize(&header)?;
        debug_assert_eq!(header_data.len(), data::JournalEntryHeader::SERIALIZED_LEN);
        if let Some(identity) = self.v3_identity() {
            let aad = super::v3_aad(identity, domain, ENTRY_HEADER_CHUNK);
            if let Some(crypto) = self.crypto.as_ref() {
                crypto.encrypt_data_with_aad(domain, ENTRY_HEADER_CHUNK, &aad, &mut header_data)?;
            } else {
                super::append_plain_metadata_checksum(&mut header_data, &aad);
            }
        } else if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(domain, ENTRY_HEADER_CHUNK, &mut header_data)?;
        }

        let domain_len = if self.current_crypto_domain.is_some() {
            8
        } else {
            0
        };
        self.ensure_capacity((domain_len + header_data.len() + action_data.len()) as u64)?;
        if let Some(domain) = self.current_crypto_domain {
            maybe_fail_io(FAIL_METADATA_WRITE)?;
            self.writer.write_all(&domain.to_le_bytes())?;
        } else {
            maybe_fail_io(FAIL_METADATA_WRITE)?;
        }
        self.writer.write_all(&header_data)?;
        self.writer.write_all(&action_data)?;

        self.offset += (domain_len + header_data.len() + action_data.len()) as u64;
        debug_assert_eq!(self.writer.stream_position().unwrap(), self.offset);
        self.incomplete_entry_in_progress = true;

        Ok(header)
    }

    fn reserve_stream_action(
        &mut self,
        action: &data::JournalAction,
    ) -> Result<data::JournalEntryHeader, LogFsError> {
        self.prepare_entry_domain()?;
        if self.current_crypto_domain.is_none() {
            return self.write_action(action, true);
        }

        let action_plain = bincode::serialize(action)?;
        let action_size = action_plain
            .len()
            .checked_add(self.metadata_padding() as usize)
            .ok_or_else(|| LogFsError::new_internal("Streaming action size overflow"))?;
        let header = data::JournalEntryHeader {
            offset: self.offset - self.base_offset,
            sequence_id: self.next_sequence,
            action_size: u32::try_from(action_size)
                .map_err(|_| LogFsError::new_internal("Streaming action is too large"))?,
            flags: data::JournalEntryHeaderFlags::empty(),
        };
        let header_size =
            data::JournalEntryHeader::SERIALIZED_LEN + self.metadata_padding() as usize;
        let reserved = 8usize
            .checked_add(header_size)
            .and_then(|size| size.checked_add(action_size))
            .ok_or_else(|| LogFsError::new_internal("Streaming reservation overflow"))?;
        let zeros = vec![0u8; reserved];
        self.ensure_capacity(reserved as u64)?;
        self.writer.write_all(&zeros)?;
        self.offset += reserved as u64;
        self.incomplete_entry_in_progress = true;
        Ok(header)
    }

    fn write_data(&mut self, chunk_size: u32, data: Vec<u8>) -> Result<u64, LogFsError> {
        if chunk_size == 0 {
            if data.is_empty() {
                let mut empty = Vec::new();
                return self.write_data_chunk(ENTRY_FIRST_DATA_CHUNK, &mut empty);
            }
            return Err(LogFsError::new_internal(
                "Chunk size must be greater than zero",
            ));
        }
        let chunks = data::compute_chunk_count(data.len() as u64, chunk_size);
        let chunk_size = chunk_size as usize;
        let mut full_len = 0u64;
        let mut scratch = Vec::with_capacity(chunk_size.saturating_add(Crypto::EXTRA_PAYLOAD_LEN));
        if data.is_empty() {
            full_len += self.write_data_chunk(ENTRY_FIRST_DATA_CHUNK, &mut scratch)?;
            return Ok(full_len);
        }
        for (index, source) in data.chunks(chunk_size).enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| LogFsError::new_internal("Exceeded maximum chunk count"))?;
            let chunk = ENTRY_FIRST_DATA_CHUNK
                .checked_add(index)
                .ok_or_else(|| LogFsError::new_internal("Exceeded maximum chunk count"))?;
            scratch.clear();
            scratch.extend_from_slice(source);
            full_len += self.write_data_chunk(chunk, &mut scratch)?;
        }
        debug_assert_eq!(chunks as usize, data.chunks(chunk_size).count());

        Ok(full_len)
    }

    pub(super) fn write_full_index(
        &mut self,
        tree: &std::collections::BTreeMap<String, KeyPointer>,
    ) -> Result<(), LogFsError> {
        let started = std::time::Instant::now();
        let v3 = matches!(self.active_superblock.format, super::RootFormat::V3 { .. });
        let serialized = if v3 {
            bincode::serialize(&data::KeyIndexV3 {
                keys: tree
                    .iter()
                    .map(|(key, ptr)| data::KeyIndexEntryV3 {
                        key: key.clone(),
                        sequence_id: SequenceId::from_u64(ptr.sequence_id),
                        crypto_domain: ptr.crypto_domain,
                        file_offset: ptr.file_offset,
                        size: ptr.size,
                        chunk_size: ptr.chunk_size,
                        hash: ptr.hash.map(data::Sha256Hash),
                    })
                    .collect(),
            })?
        } else {
            bincode::serialize(&data::KeyIndex {
                parent_entry: None,
                keys: tree
                    .iter()
                    .map(|(key, ptr)| data::KeyIndexEntry {
                        key: key.clone(),
                        sequence_id: SequenceId::from_u64(ptr.sequence_id),
                        file_offset: ptr.file_offset,
                        size: ptr.size,
                        chunk_size: ptr.chunk_size,
                    })
                    .collect(),
            })?
        };
        if serialized.len() > super::MAX_CHECKPOINT_DECODED_BYTES {
            return Err(LogFsError::new_internal(
                "Checkpoint exceeds the 512 MiB resource limit",
            ));
        }
        let serialized_size = serialized.len();
        let serialization_elapsed = started.elapsed();
        let compression_started = std::time::Instant::now();
        let (payload, compression) = if v3 {
            // V3 snapshots are bounded directly by their committed payload
            // length and avoid an attacker-controlled decompression expansion.
            (serialized, None)
        } else {
            let mut input = serialized.as_slice();
            let mut output = Cursor::new(Vec::new());
            brotli::BrotliCompress(
                &mut input,
                &mut output,
                &brotli::enc::BrotliEncoderParams {
                    quality: 4,
                    ..brotli::enc::BrotliEncoderInitParams()
                },
            )?;
            (output.into_inner(), Some(data::CompressionFormat::Brotli))
        };
        let compression_elapsed = compression_started.elapsed();
        let payload_size = payload.len();
        let hash = data::Sha256Hash(sha2::Sha256::digest(&payload).into());
        let index_action = data::ActionIndexWrite {
            size: payload.len() as u64,
            hash,
            compression,
        };
        let action = if v3 {
            data::JournalAction::IndexWriteV3(index_action)
        } else {
            data::JournalAction::IndexWrite(index_action)
        };
        let chunk_size = u32::try_from(payload.len().max(1))
            .map_err(|_| LogFsError::new_internal("Checkpoint payload exceeds v2 limit"))?;
        self.write_journal_entry(chunk_size, action, Some(payload), false)?;
        tracing::debug!(
            key_count = tree.len(),
            serialized_bytes = serialized_size,
            snapshot_bytes = payload_size,
            serialization_ms = serialization_elapsed.as_millis(),
            compression_ms = compression_elapsed.as_millis(),
            total_ms = started.elapsed().as_millis(),
            v3,
            "full checkpoint written"
        );
        Ok(())
    }

    fn write_data_chunk(
        &mut self,
        chunk: data::ChunkIndex,
        data: &mut Vec<u8>,
    ) -> Result<data::ByteCountU64, LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        match self.try_write_data_chunk(chunk, data) {
            Ok(x) => Ok(x),
            Err(err) => {
                self.tainted.set_tainted();
                Err(err)
            }
        }
    }

    fn try_write_data_chunk(
        &mut self,
        chunk: data::ChunkIndex,
        data: &mut Vec<u8>,
    ) -> Result<ByteCountU64, LogFsError> {
        debug_assert!(self.incomplete_entry_in_progress);
        debug_assert!(chunk >= ENTRY_FIRST_DATA_CHUNK);

        let domain = self
            .current_crypto_domain
            .unwrap_or_else(|| self.next_sequence.as_u64());
        if let (Some(crypto), Some(identity)) = (self.crypto.as_ref(), self.v3_identity()) {
            let aad = super::v3_aad(identity, domain, chunk);
            crypto.encrypt_data_with_aad(domain, chunk, &aad, data)?;
        } else if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(domain, chunk, data)?;
        }
        let len = data.len() as u64;

        self.ensure_capacity(len)?;
        maybe_fail_io(FAIL_DATA_WRITE)?;
        self.writer.write_all(data)?;
        self.offset += len;

        Ok(len)
    }
}

pub struct LogChunkWriter {
    chunk_size: u32,
    state: Arc<State>,
    writer: LogWriter,
    tree: Arc<RwLock<crate::state::State>>,

    path: data::KeyPath,
    header: data::JournalEntryHeader,

    current_chunk: data::ChunkIndex,
    data_size: u64,
    hasher: sha2::Sha256,
    data_offset: u64,
    checkpoint_interval: u64,
}

impl LogChunkWriter {
    pub(super) fn new(
        tree: Arc<RwLock<crate::state::State>>,
        state: Arc<State>,
        mut writer: LogWriter,
        chunk_size: u32,
        path: data::KeyPath,
        checkpoint_interval: u64,
    ) -> Result<Self, Box<(LogFsError, LogWriter)>> {
        let action = data::JournalAction::KeyInsert(data::ActionKeyInsert {
            meta: data::KeyMeta {
                size: 0,
                chunk_size: Some(chunk_size),
                hash: data::Sha256Hash::from_array([0u8; 32]),
                path: path.clone(),
            },
        });

        let header = match writer.reserve_stream_action(&action) {
            Ok(header) => header,
            Err(error) => {
                writer.tainted.set_tainted();
                return Err(Box::new((error, writer)));
            }
        };
        let data_offset = writer.offset;

        Ok(Self {
            tree,
            state,
            chunk_size,
            writer,
            path,
            header,
            hasher: sha2::Sha256::new(),
            data_size: 0,
            current_chunk: ENTRY_FIRST_DATA_CHUNK,
            data_offset,
            checkpoint_interval,
        })
    }

    fn write_chunk(&mut self, data: &mut Vec<u8>, is_last: bool) -> Result<(), LogFsError> {
        if !is_last && data.len() != self.chunk_size as usize {
            return Err(LogFsError::new_internal(
                "Non-final streaming chunk has an invalid length",
            ));
        }

        let len = data.len();
        let next_chunk = self
            .current_chunk
            .checked_add(1)
            .ok_or_else(|| LogFsError::new_internal("Exceeded maximum chunk count"))?;

        self.hasher.update(&data);
        self.writer.write_data_chunk(self.current_chunk, data)?;
        self.current_chunk = next_chunk;
        self.data_size += len as u64;

        Ok(())
    }

    fn try_finalize(&mut self, final_data: Option<&mut Vec<u8>>) -> Result<(), LogFsError> {
        if let Some(data) = final_data {
            if data.len() >= self.chunk_size as usize {
                return Err(LogFsError::new_internal(
                    "Final streaming chunk exceeds configured chunk size",
                ));
            }
            self.write_chunk(data, true)?;
        } else if self.data_size == 0 {
            let mut empty = Vec::new();
            self.write_chunk(&mut empty, true)?;
        }

        let meta = data::KeyMeta {
            size: self.data_size,
            chunk_size: Some(self.chunk_size),
            hash: data::Sha256Hash(std::mem::take(&mut self.hasher).finalize().into()),
            path: self.path.clone(),
        };

        let action = data::JournalAction::KeyInsert(data::ActionKeyInsert { meta: meta.clone() });

        let writer = &mut self.writer;
        let end_offset = writer.offset;
        writer
            .writer
            .seek(SeekFrom::Start(writer.base_offset + self.header.offset))?;
        writer.offset = writer.base_offset + self.header.offset;
        writer.incomplete_entry_in_progress = false;
        let header = writer.write_action(&action, false)?;

        if header.action_size != self.header.action_size
            || header.offset != self.header.offset
            || header.sequence_id != self.header.sequence_id
        {
            return Err(LogFsError::new_internal(
                "Streaming finalization changed reserved framing",
            ));
        }

        writer.writer.flush()?;

        let pointer = KeyPointer {
            sequence_id: writer.next_sequence.as_u64(),
            file_offset: self.data_offset,
            size: self.data_size,
            chunk_size: Some(self.chunk_size),
            hash: Some(meta.hash.0),
            crypto_domain: writer.current_crypto_domain,
            log_identity: writer.v3_identity(),
        };

        writer.offset = end_offset;
        writer.incomplete_entry_in_progress = false;
        writer.next_sequence = writer.next_sequence.try_increment()?;

        writer.publish_committed_root()?;
        writer.current_crypto_domain = None;

        let mut tree = self
            .tree
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tree.add_key(meta.path, pointer);
        tree.record_mutation();
        if self.checkpoint_interval != 0 && tree.write_counter >= self.checkpoint_interval {
            match writer.write_full_index(&tree.tree) {
                Ok(()) => tree.write_counter = 0,
                Err(error) => {
                    tracing::error!(
                        ?error,
                        "automatic checkpoint failed after committed streaming insert"
                    );
                }
            }
        }

        Ok(())
    }

    fn finalize(mut self, final_data: Option<&mut Vec<u8>>) -> Result<(), LogFsError> {
        let result = self.try_finalize(final_data);
        if result.is_err() {
            self.writer.tainted.set_tainted();
        }
        self.state.return_writer(self.writer);
        result
    }

    fn abort(mut self) -> Result<(), LogFsError> {
        let entry_offset = self
            .writer
            .base_offset
            .checked_add(self.header.offset)
            .ok_or_else(|| LogFsError::new_internal("Streaming abort offset overflow"))?;
        let result = self
            .writer
            .writer
            .seek(SeekFrom::Start(entry_offset))
            .map(|_| {
                self.writer.offset = entry_offset;
                self.writer.incomplete_entry_in_progress = false;
                self.writer.current_crypto_domain = None;
            })
            .map_err(LogFsError::from);
        if result.is_err() {
            self.writer.tainted.set_tainted();
        }
        self.state.return_writer(self.writer);
        result
    }
}

pub struct KeyWriter {
    writer: Option<LogChunkWriter>,
    buffer: Vec<u8>,
    buffer_offset: usize,
    _lock: Option<KeyLock>,
}

impl KeyWriter {
    pub fn new(writer: LogChunkWriter, lock: Option<KeyLock>) -> Self {
        let buffer = vec![0; writer.chunk_size as usize];
        Self {
            buffer,
            writer: Some(writer),
            buffer_offset: 0,
            _lock: lock,
        }
    }

    pub fn finish(mut self) -> Result<(), LogFsError> {
        self.finish_mut()
    }

    /// Discard an unfinished streaming insert. Already-written tail bytes are
    /// left outside the committed root and will be overwritten by the next
    /// mutation.
    pub fn abort(mut self) -> Result<(), LogFsError> {
        self.writer
            .take()
            .ok_or_else(|| LogFsError::new_internal("KeyWriter already finished"))?
            .abort()
    }

    // Only called in Self::drop as a workaround.
    fn finish_mut(&mut self) -> Result<(), LogFsError> {
        let final_data = if self.buffer_offset > 0 {
            self.buffer.truncate(self.buffer_offset);
            Some(&mut self.buffer)
        } else {
            None
        };
        self.writer
            .take()
            .ok_or_else(|| LogFsError::new_internal("KeyWriter already finished"))?
            .finalize(final_data)
    }
}

impl std::io::Write for KeyWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let size = input.len();
        let mut input = input;

        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| LogFsError::new_internal("KeyWriter already finished").into_io())?;

        while !input.is_empty() {
            let available = writer.chunk_size as usize - self.buffer_offset;
            debug_assert!(available > 0);
            let to_copy = std::cmp::min(available, input.len());
            self.buffer[self.buffer_offset..self.buffer_offset + to_copy]
                .copy_from_slice(&input[..to_copy]);

            if available - to_copy == 0 {
                writer
                    .write_chunk(&mut self.buffer, false)
                    .map_err(|e| e.into_io())?;
                self.buffer.resize(writer.chunk_size as usize, 0);
                self.buffer_offset = 0;
            } else {
                self.buffer_offset += to_copy;
                break;
            }

            input = &input[to_copy..];
        }

        Ok(size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| LogFsError::new_internal("KeyWriter already finished").into_io())?;
        writer.writer.flush().map_err(LogFsError::into_io)
    }
}

impl Drop for KeyWriter {
    fn drop(&mut self) {
        if self.writer.is_some()
            && let Err(error) = self.finish_mut()
        {
            // Drop must never trigger a second panic during unwinding. The
            // underlying writer is returned in a tainted state so waiters
            // wake and receive a deterministic error.
            tracing::error!(?error, "commit-on-drop streaming writer failed");
        }
    }
}
