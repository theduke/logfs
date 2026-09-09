use std::{
    io::{BufWriter, Seek, SeekFrom, Write},
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use ring::rand::SecureRandom;
use sha2::Digest;

use crate::{
    KeyLock, LogFsError,
    crypto::{Crypto, V3Crypto, V3RootCrypto},
    journal::{
        SequenceId,
        v3::{ENTRY_ACTION_CHUNK, ENTRY_HEADER_CHUNK, data::EntryPointer},
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
    v3_crypto: Option<V3Crypto>,
    v3_root_crypto: Option<V3RootCrypto>,
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
    current_entry_nonce: Option<[u8; 24]>,
    current_entry_is_checkpoint: bool,
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
            .field("current_entry_nonce", &self.current_entry_nonce)
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

    pub(super) fn v3_crypto(&self) -> Option<V3Crypto> {
        self.v3_crypto.clone()
    }

    pub(super) fn is_legacy_v2(&self) -> bool {
        matches!(self.active_superblock.format, super::RootFormat::LegacyV2)
    }

    pub(crate) fn create_new(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        file: std::fs::File,
        base_offset: u64,
        durable: Arc<AtomicBool>,
        region_len: Option<u64>,
        randomize_region: bool,
    ) -> Result<Self, LogFsError> {
        let v3_entry_start = super::v3_entry_start(base_offset)?;
        if region_len.is_some_and(|limit| limit < v3_entry_start) {
            return Err(LogFsError::new_internal(
                "Configured region is smaller than the v3 root area",
            ));
        }
        if randomize_region && region_len.is_none() {
            return Err(LogFsError::new_internal(
                "Randomized preallocation requires a bounded region length",
            ));
        }
        let random = ring::rand::SystemRandom::new();
        let mut identity = [0u8; 16];
        let mut log_secret = zeroize::Zeroizing::new([0u8; 32]);
        let mut root_salts = [[0u8; 16]; 2];
        random
            .fill(&mut identity)
            .map_err(|_| LogFsError::new_internal("Could not generate v3 log identity"))?;
        random
            .fill(log_secret.as_mut())
            .map_err(|_| LogFsError::new_internal("Could not generate v3 log secret"))?;
        for salt in &mut root_salts {
            random
                .fill(salt)
                .map_err(|_| LogFsError::new_internal("Could not generate v3 root salt"))?;
        }
        let v3_crypto = crypto.as_ref().map(|_| V3Crypto::new(&log_secret));
        let v3_root_crypto = crypto
            .as_ref()
            .map(|crypto| crypto.v3_root_crypto(&root_salts))
            .transpose()?;
        let first_entry_offset = base_offset
            .checked_add(v3_entry_start)
            .ok_or_else(|| LogFsError::new_internal("Base offset overflow"))?;
        let mut s = Self {
            base_offset,
            v3_crypto,
            v3_root_crypto,
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
                    log_secret,
                    root_salts,
                    history: [0; 32],
                    checkpoint_history: [0; 32],
                },
            },
            actions_since_last_index_write: 0,
            tainted,
            last_written_index: None,
            current_entry_nonce: None,
            current_entry_is_checkpoint: false,
            durable,
            region_len,
        };

        s.create_superblocks()?;
        if randomize_region {
            let region_len = region_len.expect("validated bounded randomized region");
            let remaining = region_len
                .checked_sub(v3_entry_start)
                .ok_or_else(|| LogFsError::new_internal("Invalid randomized region bounds"))?;
            let random = ring::rand::SystemRandom::new();
            let mut chunk = vec![0u8; 1024 * 1024];
            let mut written = 0u64;
            while written < remaining {
                let len = usize::try_from((remaining - written).min(chunk.len() as u64))
                    .map_err(|_| LogFsError::new_internal("Randomized region chunk overflow"))?;
                random.fill(&mut chunk[..len]).map_err(|_| {
                    LogFsError::new_internal("Could not randomize unused log region")
                })?;
                s.writer.write_all(&chunk[..len])?;
                written += len as u64;
            }
            s.writer.flush()?;
        }
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

        let (v3_crypto, v3_root_crypto) = match (&crypto, &block.format) {
            (
                Some(crypto),
                super::RootFormat::V3 {
                    log_secret,
                    root_salts,
                    ..
                },
            ) => (
                Some(V3Crypto::new(log_secret)),
                Some(crypto.v3_root_crypto(root_salts)?),
            ),
            (None, super::RootFormat::V3 { .. }) => (None, None),
            (_, super::RootFormat::LegacyV2) => (None, None),
        };
        let s = Self {
            base_offset,
            v3_crypto,
            v3_root_crypto,
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
            current_entry_nonce: None,
            current_entry_is_checkpoint: false,
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
            super::metadata_padding(self.crypto.is_some()) as u64
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
            super::RootFormat::LegacyV2 => return Err(LogFsError::ReadOnly),
            super::RootFormat::V3 {
                identity,
                generation,
                ref log_secret,
                root_salts,
                history,
                checkpoint_history,
            } => super::RootFormat::V3 {
                identity,
                generation: generation
                    .checked_add(1)
                    .ok_or_else(|| LogFsError::new_internal("V3 root generation exhausted"))?,
                log_secret: log_secret.clone(),
                root_salts,
                history,
                checkpoint_history,
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

        let buffer = super::root::encode_root(
            &block,
            self.crypto(),
            self.v3_crypto.as_ref(),
            self.v3_root_crypto.as_ref(),
        )?;

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

    fn prepare_entry_nonce(&mut self) -> Result<Option<[u8; 24]>, LogFsError> {
        if !matches!(self.active_superblock.format, super::RootFormat::V3 { .. }) {
            return Err(LogFsError::ReadOnly);
        }
        let mut nonce = [0u8; 24];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| LogFsError::new_internal("Could not generate v3 entry nonce"))?;
        self.current_entry_nonce = Some(nonce);
        Ok(Some(nonce))
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
        if self.is_legacy_v2() {
            return Err(LogFsError::ReadOnly);
        }
        let total_len = super::frame_len(
            action_plain_len,
            action.payload_len(self.crypto()),
            self.crypto.is_some(),
        )?;
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

        self.prepare_entry_nonce()?;

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
            entry_nonce: self.current_entry_nonce,
            log_identity: self.v3_identity(),
        };
        self.current_entry_nonce = None;
        self.current_entry_is_checkpoint = false;

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

        super::frame_len(bincode::serialized_size(action)?, 0, self.crypto.is_some())?;
        let action_plain = bincode::serialize(&action)?;
        let mut action_data = action_plain.clone();
        if let Some(identity) = self.v3_identity() {
            let entry_nonce = self
                .current_entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, ENTRY_ACTION_CHUNK);
            if let Some(crypto) = self.v3_crypto.as_ref() {
                crypto.encrypt_entry(
                    super::v3_nonce(entry_nonce, ENTRY_ACTION_CHUNK),
                    &aad,
                    &mut action_data,
                )?;
            } else {
                super::append_plain_metadata_checksum(&mut action_data, &aad);
            }
        } else {
            return Err(LogFsError::ReadOnly);
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
        let next_history;
        let mut header_data = if let Some(identity) = self.v3_identity() {
            let entry_nonce = self
                .current_entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let previous_history = match &self.active_superblock.format {
                super::RootFormat::V3 { history, .. } => *history,
                super::RootFormat::LegacyV2 => unreachable!(),
            };
            let history = super::v3_history_commit(
                self.v3_crypto.as_ref(),
                previous_history,
                identity,
                entry_nonce,
                &action_plain,
            );
            next_history = Some((previous_history, history));
            let encoded = bincode::serialize(&super::V3FrameHeader {
                header: header.clone(),
                previous_history,
                history,
            })?;
            if encoded.len() + 4 > super::V3_FRAME_HEADER_CLEAR_LEN {
                return Err(LogFsError::new_internal("V3 frame header is too large"));
            }
            let mut clear = vec![0u8; super::V3_FRAME_HEADER_CLEAR_LEN];
            if self.v3_crypto.is_none() {
                ring::rand::SystemRandom::new()
                    .fill(&mut clear)
                    .map_err(|_| {
                        LogFsError::new_internal("Could not randomize v3 frame padding")
                    })?;
            }
            clear[..4].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
            clear[4..4 + encoded.len()].copy_from_slice(&encoded);
            clear
        } else {
            return Err(LogFsError::ReadOnly);
        };
        if let Some(identity) = self.v3_identity() {
            let entry_nonce = self
                .current_entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, ENTRY_HEADER_CHUNK);
            if let Some(crypto) = self.v3_crypto.as_ref() {
                crypto.encrypt_entry(
                    super::v3_nonce(entry_nonce, ENTRY_HEADER_CHUNK),
                    &aad,
                    &mut header_data,
                )?;
            } else {
                super::append_plain_metadata_checksum(&mut header_data, &aad);
            }
        } else {
            return Err(LogFsError::ReadOnly);
        }

        let domain_len = if self.current_entry_nonce.is_some() {
            24
        } else {
            0
        };
        self.ensure_capacity((domain_len + header_data.len() + action_data.len()) as u64)?;
        if let Some(domain) = self.current_entry_nonce {
            maybe_fail_io(FAIL_METADATA_WRITE)?;
            self.writer.write_all(&domain)?;
        } else {
            maybe_fail_io(FAIL_METADATA_WRITE)?;
        }
        self.writer.write_all(&header_data)?;
        self.writer.write_all(&action_data)?;

        self.offset += (domain_len + header_data.len() + action_data.len()) as u64;
        debug_assert_eq!(self.writer.stream_position().unwrap(), self.offset);
        self.incomplete_entry_in_progress = true;
        self.current_entry_is_checkpoint = action.is_index_write();
        if let Some((previous_history, history)) = next_history {
            let super::RootFormat::V3 {
                history: root_history,
                checkpoint_history,
                ..
            } = &mut self.active_superblock.format
            else {
                unreachable!();
            };
            if action.is_index_write() {
                *checkpoint_history = previous_history;
            }
            *root_history = history;
        }

        Ok(header)
    }

    fn reserve_stream_action(
        &mut self,
        action: &data::JournalAction,
    ) -> Result<data::JournalEntryHeader, LogFsError> {
        let reserved = self.preflight_stream_action(action)?;
        self.prepare_entry_nonce()?;

        let action_size = bincode::serialized_size(action)? + self.metadata_padding();
        let header = data::JournalEntryHeader {
            offset: self.offset - self.base_offset,
            sequence_id: self.next_sequence,
            action_size: u32::try_from(action_size)
                .map_err(|_| LogFsError::new_internal("Streaming action is too large"))?,
            flags: data::JournalEntryHeaderFlags::empty(),
        };
        let mut random_bytes = vec![0u8; reserved as usize];
        ring::rand::SystemRandom::new()
            .fill(&mut random_bytes)
            .map_err(|_| LogFsError::new_internal("Could not randomize streaming reservation"))?;
        self.ensure_capacity(reserved)?;
        self.writer.write_all(&random_bytes)?;
        self.offset += reserved;
        self.incomplete_entry_in_progress = true;
        Ok(header)
    }

    fn preflight_stream_action(&self, action: &data::JournalAction) -> Result<u64, LogFsError> {
        if self.is_legacy_v2() {
            return Err(LogFsError::ReadOnly);
        }
        let reserved =
            super::frame_len(bincode::serialized_size(action)?, 0, self.crypto.is_some())?;
        // Even an empty encrypted value needs one authentication tag.
        self.ensure_capacity(reserved + self.data_padding())?;
        Ok(reserved)
    }

    fn write_data(&mut self, chunk_size: u32, data: Vec<u8>) -> Result<u64, LogFsError> {
        if chunk_size == 0 {
            if data.is_empty() {
                return if self.v3_identity().is_some() {
                    let mut empty = Vec::new();
                    self.write_data_chunk(ENTRY_FIRST_DATA_CHUNK, &mut empty)
                } else {
                    Ok(0)
                };
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
            if self.v3_identity().is_some() {
                full_len += self.write_data_chunk(ENTRY_FIRST_DATA_CHUNK, &mut scratch)?;
            }
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
        if self.is_legacy_v2() {
            return Err(LogFsError::ReadOnly);
        }
        let serialized = super::index::serialize_snapshot(tree, self.crypto.is_some())?;
        let serialized_size = serialized.len();
        let serialization_elapsed = started.elapsed();
        let compression_started = std::time::Instant::now();
        let (payload, compression) = (serialized, None);
        let compression_elapsed = compression_started.elapsed();
        let payload_size = payload.len();
        let hash = data::Sha256Hash(sha2::Sha256::digest(&payload).into());
        let index_action = data::ActionIndexWrite {
            size: payload.len() as u64,
            hash,
            compression,
        };
        let action = data::JournalAction::IndexWriteV3(index_action);
        let chunk_size = u32::try_from(payload.len().max(1)).map_err(|_| {
            LogFsError::new_internal("Checkpoint payload exceeds chunk-size format limit")
        })?;
        self.write_journal_entry(chunk_size, action, Some(payload), false)?;
        tracing::debug!(
            key_count = tree.len(),
            serialized_bytes = serialized_size,
            snapshot_bytes = payload_size,
            serialization_ms = serialization_elapsed.as_millis(),
            compression_ms = compression_elapsed.as_millis(),
            total_ms = started.elapsed().as_millis(),
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

        if let (Some(crypto), Some(identity)) = (self.v3_crypto.as_ref(), self.v3_identity()) {
            let entry_nonce = self
                .current_entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, chunk);
            if self.current_entry_is_checkpoint {
                crypto.encrypt_checkpoint(super::v3_nonce(entry_nonce, chunk), &aad, data)?;
            } else {
                crypto.encrypt_entry(super::v3_nonce(entry_nonce, chunk), &aad, data)?;
            }
        } else if self.is_legacy_v2() {
            return Err(LogFsError::ReadOnly);
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

        // Predictable rejection must not taint the writer; no bytes or nonce state
        // have been touched at this point. I/O errors below still taint it.
        if let Err(error) = writer.preflight_stream_action(&action) {
            return Err(Box::new((error, writer)));
        }
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
        } else if self.data_size == 0 && self.writer.v3_identity().is_some() {
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
            entry_nonce: writer.current_entry_nonce,
            log_identity: writer.v3_identity(),
        };

        writer.offset = end_offset;
        writer.incomplete_entry_in_progress = false;
        writer.next_sequence = writer.next_sequence.try_increment()?;

        writer.publish_committed_root()?;
        writer.current_entry_nonce = None;

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
                self.writer.current_entry_nonce = None;
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
