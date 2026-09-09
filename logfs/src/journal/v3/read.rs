use sha2::Digest;
use std::{
    io::{self, BufReader, Read, Seek, SeekFrom},
    sync::Arc,
};

use crate::{LogFsError, crypto::Crypto, journal::SequenceId, state::KeyPointer};

use super::{
    ENTRY_ACTION_CHUNK, ENTRY_FIRST_DATA_CHUNK, ENTRY_HEADER_CHUNK, IndexedSuperBlock,
    PersistedEntry,
    data::{self, EntryPointer},
};

pub struct LogReader<'a, R> {
    base_offset: u64,
    offset: u64,
    // TODO: should be private!
    pub next_sequence: SequenceId,
    crypto: Option<&'a Crypto>,
    v3_crypto: Option<crate::crypto::V3Crypto>,
    buffer: Vec<u8>,
    // TODO: should be private!
    pub reader: BufReader<R>,
    committed_end: Option<u64>,
    v3_entries: bool,
    v3_identity: Option<[u8; 16]>,
    expected_history: [u8; 32],
    committed_history: [u8; 32],
    checkpoint_history: [u8; 32],
    checkpoint_pointer: Option<EntryPointer>,
}

pub(in crate::journal) fn validate_root(
    block: &data::Superblock,
    format: &super::RootFormat,
    base_offset: u64,
    file_end: u64,
) -> Result<(), LogFsError> {
    let entry_start = format.entry_start(base_offset)?;
    if !block.flags.is_empty()
        || block.tail_offset < entry_start
        || block.active_sequence == u64::MAX
    {
        return Err(LogFsError::new_internal("Invalid committed root boundary"));
    }
    let absolute_tail = base_offset
        .checked_add(block.tail_offset)
        .ok_or_else(|| LogFsError::new_internal("Committed tail offset overflow"))?;
    if absolute_tail > file_end {
        return Err(LogFsError::new_internal(
            "Committed tail extends beyond EOF",
        ));
    }
    if let Some(pointer) = block.last_index_entry
        && (pointer.offset < entry_start
            || pointer.offset >= block.tail_offset
            || pointer.sequence.as_u64() == 0
            || pointer.sequence.as_u64() > block.active_sequence)
    {
        return Err(LogFsError::new_internal(
            "Invalid checkpoint pointer in root",
        ));
    }
    Ok(())
}

impl<'a, R: std::io::Read + std::io::Seek> LogReader<'a, R> {
    pub fn new_start(reader: R, base_offset: u64, crypto: Option<&'a Crypto>) -> Self {
        Self {
            base_offset,
            offset: base_offset,
            next_sequence: SequenceId::first(),
            crypto,
            v3_crypto: None,
            buffer: Vec::new(),
            reader: BufReader::new(reader),
            committed_end: None,
            v3_entries: false,
            v3_identity: None,
            expected_history: [0; 32],
            committed_history: [0; 32],
            checkpoint_history: [0; 32],
            checkpoint_pointer: None,
        }
    }

    pub(super) fn read_superblocks(&mut self) -> Result<IndexedSuperBlock, LogFsError> {
        self.read_superblocks_with_policy(false)
    }

    /// Explicit recovery may use one authenticated root and a truncated tail.
    pub(super) fn read_repair_superblocks(&mut self) -> Result<IndexedSuperBlock, LogFsError> {
        self.read_superblocks_with_policy(true)
    }

    fn read_superblocks_with_policy(
        &mut self,
        salvage: bool,
    ) -> Result<IndexedSuperBlock, LogFsError> {
        let file_end = self.reader.seek(SeekFrom::End(0))?;
        let block = match crate::journal::v2::read_roots(
            &mut self.reader,
            self.base_offset,
            file_end,
            self.crypto,
        )? {
            Some(block) => block,
            None => super::root::read_roots(
                &mut self.reader,
                self.base_offset,
                file_end,
                self.crypto,
                salvage,
            )?,
        };
        self.reader.seek(SeekFrom::Start(
            self.base_offset
                .checked_add(block.format.entry_start(self.base_offset)?)
                .ok_or_else(|| LogFsError::new_internal("Root area offset overflow"))?,
        ))?;
        self.offset = self.reader.stream_position()?;
        debug_assert_eq!(
            self.offset,
            block.format.entry_start(self.base_offset)? + self.base_offset
        );

        self.committed_end = Some(
            self.base_offset
                .checked_add(block.block.tail_offset)
                .ok_or_else(|| LogFsError::new_internal("Superblock tail offset overflow"))?,
        );
        self.v3_entries = matches!(block.format, super::RootFormat::V3 { .. });
        self.v3_identity = match &block.format {
            super::RootFormat::V3 { identity, .. } => Some(*identity),
            super::RootFormat::LegacyV2 => None,
        };
        self.v3_crypto = match &block.format {
            super::RootFormat::V3 { log_secret, .. } if self.crypto.is_some() => {
                Some(crate::crypto::V3Crypto::new(log_secret))
            }
            _ => None,
        };
        if let super::RootFormat::V3 {
            history,
            checkpoint_history,
            ..
        } = &block.format
        {
            self.committed_history = *history;
            self.checkpoint_history = *checkpoint_history;
            self.checkpoint_pointer = block.block.last_index_entry;
        }
        Ok(block)
    }

    pub(in crate::journal) fn v3_identity(&self) -> Option<[u8; 16]> {
        self.v3_identity
    }

    pub(in crate::journal) fn crypto_padding(&self) -> u64 {
        self.crypto
            .map(|crypto| crypto.extra_payload_len())
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub(super) fn rewind_to_first_entry(&mut self) -> Result<(), LogFsError> {
        let target = self
            .base_offset
            .checked_add(if self.v3_entries {
                super::v3_entry_start(self.base_offset)?
            } else {
                data::Superblock::HEADER_SIZE
            })
            .ok_or_else(|| LogFsError::new_internal("Root area offset overflow"))?;
        self.reader.seek(io::SeekFrom::Start(target))?;
        self.offset = target;
        self.next_sequence = SequenceId::first();
        self.expected_history = [0; 32];
        self.buffer.clear();
        Ok(())
    }

    pub(super) fn seek_to_pointer(&mut self, entry: EntryPointer) -> Result<(), LogFsError> {
        let start = self.offset;
        debug_assert_eq!(start, self.reader.stream_position()?);

        let entry_start = if self.v3_entries {
            super::v3_entry_start(self.base_offset)?
        } else {
            data::Superblock::HEADER_SIZE
        };
        if entry.offset < entry_start
            || self
                .committed_end
                .is_some_and(|end| entry.offset >= end.saturating_sub(self.base_offset))
        {
            return Err(LogFsError::new_internal(
                "Entry pointer is outside committed history",
            ));
        }
        let offset = self
            .base_offset
            .checked_add(entry.offset)
            .ok_or_else(|| LogFsError::new_internal("Entry pointer offset overflow"))?;
        match self.reader.seek(SeekFrom::Start(offset)) {
            Ok(_) => {
                self.offset = offset;
                self.next_sequence = entry.sequence;
                if self.v3_entries {
                    self.expected_history = if self.checkpoint_pointer == Some(entry) {
                        self.checkpoint_history
                    } else {
                        return Err(LogFsError::new_internal(
                            "V3 random seeks require the authenticated checkpoint pointer",
                        ));
                    };
                }
                Ok(())
            }
            Err(err) => {
                let _ = self.reader.seek(SeekFrom::Start(start));
                Err(err.into())
            }
        }
    }

    pub(super) fn is_at_committed_end(&self) -> bool {
        self.committed_end == Some(self.offset)
            && (!self.v3_entries || self.expected_history == self.committed_history)
    }

    pub(super) fn committed_region_len(&self) -> u64 {
        self.committed_end
            .unwrap_or(self.offset)
            .saturating_sub(self.base_offset)
    }

    pub(in crate::journal) fn base_offset(&self) -> u64 {
        self.base_offset
    }

    pub(in crate::journal) fn committed_end(&self) -> Result<u64, LogFsError> {
        self.committed_end
            .ok_or_else(|| LogFsError::new_internal("Committed boundary is unavailable"))
    }

    /* fn skip_superblocks(&mut self) -> Result<(), LogFsError> {
        self.reader.seek_relative(
            data::Superblock::HEADER_COUNT as i64 * data::Superblock::SERIALIZED_LEN as i64,
        )?;
        Ok(())
    } */

    /// Read the next journal entry.
    ///
    /// If data_buffer is provided, the entry data will be written to the buffer
    /// in its entirety. Otherwise the data is skipped.
    pub(super) fn next_entry<'b>(
        &mut self,
        data_buffer: Option<&'b mut Vec<u8>>,
    ) -> Result<(PersistedEntry, &'b [u8]), LogFsError> {
        let metadata_padding = if self.v3_entries {
            super::metadata_padding(self.crypto.is_some())
        } else {
            self.crypto.map(|c| c.extra_payload_len()).unwrap_or(0) as usize
        };
        let start_offset = self.offset;
        let buffer = &mut self.buffer;
        let sequence = self.next_sequence;

        debug_assert_eq!(self.reader.stream_position()?, start_offset);

        let domain_prefix = if self.v3_entries {
            super::V3_NONCE_LEN
        } else {
            0
        };
        let header_size = if self.v3_entries {
            super::frame_header_len(self.crypto.is_some())
        } else {
            data::JournalEntryHeader::SERIALIZED_LEN + metadata_padding
        };

        let committed_end = self.committed_end.unwrap_or(u64::MAX);
        let header_end = start_offset
            .checked_add(header_size as u64)
            .ok_or_else(|| LogFsError::new_internal("Entry header offset overflow"))?;
        if header_end > committed_end {
            return Err(LogFsError::new_internal(
                "Incomplete entry header inside committed history",
            ));
        }

        // Read journal entry header.
        let entry_nonce = if self.v3_entries {
            let mut bytes = [0u8; 24];
            self.reader.read_exact(&mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        buffer.resize(header_size - domain_prefix, 0);

        self.reader.read_exact(&mut *buffer)?;

        let header_data = if let Some(identity) = self.v3_identity {
            let entry_nonce = entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, ENTRY_HEADER_CHUNK);
            if let Some(crypto) = &self.v3_crypto {
                crypto.decrypt_entry(
                    super::v3_nonce(entry_nonce, ENTRY_HEADER_CHUNK),
                    &aad,
                    buffer,
                )?
            } else {
                super::verify_plain_metadata_checksum(buffer, &aad)?
            }
        } else if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, buffer)?
        } else {
            buffer.as_slice()
        };
        let (header, frame_history) = if self.v3_entries {
            let frame = super::decode_v3_frame_header(header_data)?;
            if frame.previous_history != self.expected_history {
                return Err(LogFsError::new_internal("V3 history predecessor mismatch"));
            }
            (frame.header.clone(), Some(frame))
        } else {
            (crate::encoding::deserialize(header_data)?, None)
        };
        tracing::trace!(?header, "read entry header");

        if sequence != header.sequence_id {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry sequence number for sequence {:?}",
                sequence,
            )));
        }
        if start_offset - self.base_offset != header.offset {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry offset does not match actual offset for sequence {:?}",
                self.next_sequence
            )));
        }
        if header
            .flags
            .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
        {
            return Err(LogFsError::new_internal(
                "Incomplete entry is referenced by the committed superblock",
            ));
        }

        // Read the journal action.

        // Make sure the buffer can hold the data.
        let action_size = header.action_size as usize;
        if self.v3_entries {
            super::limits::action().check_encoded(action_size as u64, metadata_padding as u64)?;
        } else if action_size > super::MAX_ACTION_BYTES {
            return Err(LogFsError::new_internal(
                "Journal action exceeds resource limit",
            ));
        }
        let action_end = header_end
            .checked_add(action_size as u64)
            .ok_or_else(|| LogFsError::new_internal("Entry action offset overflow"))?;
        if action_end > committed_end {
            return Err(LogFsError::new_internal(
                "Incomplete entry action inside committed history",
            ));
        }
        buffer.resize(action_size, 0);
        // Read into buffer.
        self.reader.read_exact(buffer)?;

        // Decrypt.

        let action_data = if let Some(identity) = self.v3_identity {
            let entry_nonce = entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 entry is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, ENTRY_ACTION_CHUNK);
            if let Some(crypto) = &self.v3_crypto {
                crypto.decrypt_entry(
                    super::v3_nonce(entry_nonce, ENTRY_ACTION_CHUNK),
                    &aad,
                    buffer,
                )?
            } else {
                super::verify_plain_metadata_checksum(buffer, &aad)?
            }
        } else if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
        } else {
            buffer.as_slice()
        };

        let action_limit = if self.v3_entries {
            super::limits::action().plaintext as usize
        } else {
            super::MAX_ACTION_BYTES
        };
        let action: data::JournalAction = super::deserialize_bounded(action_data, action_limit)?;
        if let Some(frame) = &frame_history {
            let actual = super::v3_history_commit(
                self.v3_crypto.as_ref(),
                frame.previous_history,
                self.v3_identity.expect("v3 identity was validated"),
                entry_nonce.expect("v3 nonce was read"),
                action_data,
            );
            if actual != frame.history {
                return Err(LogFsError::new_internal("V3 history commitment mismatch"));
            }
        }
        if data_buffer.is_some() && !action.is_index_write() {
            return Err(LogFsError::new_internal(
                "Checkpoint pointer does not reference an index entry",
            ));
        }
        let data_len = if !self.v3_entries
            && matches!(
                &action,
                data::JournalAction::KeyInsert(insert) if insert.meta.size == 0
            ) {
            0
        } else {
            action.payload_len(self.crypto)
        };

        let data_offset = action_end;
        let next_entry_offset = data_offset
            .checked_add(data_len)
            .ok_or_else(|| LogFsError::new_internal("Entry payload offset overflow"))?;
        if next_entry_offset > committed_end {
            return Err(LogFsError::new_internal(
                "Incomplete entry payload inside committed history",
            ));
        }
        if data_buffer.is_some() && self.v3_entries {
            super::limits::checkpoint().check_encoded(data_len, self.crypto_padding())?;
        } else if data_buffer.is_some() && data_len > super::MAX_CHECKPOINT_DECODED_BYTES as u64 {
            return Err(LogFsError::new_internal(
                "Checkpoint payload exceeds the 512 MiB resource limit",
            ));
        }
        let data_len_usize = usize::try_from(data_len)
            .map_err(|_| LogFsError::new_internal("Entry payload does not fit in memory"))?;

        let decrypted_data: &'b [u8] = if let Some(buffer_ref) = data_buffer {
            debug_assert_eq!(data_offset, self.reader.stream_position().unwrap());

            buffer_ref.resize(data_len_usize, 0);
            self.reader.read_exact(buffer_ref)?;

            if let Some(crypto) = &self.v3_crypto {
                let identity = self.v3_identity.ok_or_else(|| {
                    LogFsError::new_internal("Encrypted v3 entry is missing its log identity")
                })?;
                let entry_nonce = entry_nonce.ok_or_else(|| {
                    LogFsError::new_internal("V3 entry is missing its random nonce")
                })?;
                let aad = super::v3_aad(identity, entry_nonce, ENTRY_FIRST_DATA_CHUNK);
                if action.is_index_write() {
                    crypto.decrypt_checkpoint(
                        super::v3_nonce(entry_nonce, ENTRY_FIRST_DATA_CHUNK),
                        &aad,
                        buffer_ref,
                    )?
                } else {
                    crypto.decrypt_entry(
                        super::v3_nonce(entry_nonce, ENTRY_FIRST_DATA_CHUNK),
                        &aad,
                        buffer_ref,
                    )?
                }
            } else if let Some(crypto) = &self.crypto {
                crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_FIRST_DATA_CHUNK, buffer_ref)?
            } else {
                buffer_ref.as_slice()
            }
        } else {
            self.reader.seek(SeekFrom::Start(next_entry_offset))?;
            &[]
        };

        self.offset = next_entry_offset;
        self.next_sequence = self.next_sequence.try_increment()?;
        if let Some(frame) = frame_history {
            self.expected_history = frame.history;
        }

        debug_assert_eq!(self.offset, self.reader.stream_position()?);

        let entry = PersistedEntry {
            entry: data::JournalEntry { header, action },
            file_data_offset: data_offset,
            entry_nonce,
            log_identity: self.v3_identity,
        };
        Ok((entry, decrypted_data))
    }
}

pub(crate) struct BackingFile {
    file: std::fs::File,
    fallback_lock: std::sync::Mutex<()>,
}

impl BackingFile {
    pub(crate) fn new(file: std::fs::File) -> Self {
        Self {
            file,
            fallback_lock: std::sync::Mutex::new(()),
        }
    }

    fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt;
            return self.file.read_at(buffer, offset);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            return self.file.seek_read(buffer, offset);
        }
        #[allow(unreachable_code)]
        {
            let _guard = self
                .fallback_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut file = &self.file;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buffer)
        }
    }
}

struct PositionedReader {
    backing: Arc<BackingFile>,
    position: u64,
}

impl Read for PositionedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.backing.read_at(buffer, self.position)?;
        self.position = self.position.saturating_add(read as u64);
        Ok(read)
    }
}

impl Seek for PositionedReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(position) => position as i128,
            SeekFrom::Current(delta) => self.position as i128 + delta as i128,
            SeekFrom::End(delta) => self.backing.file.metadata()?.len() as i128 + delta as i128,
        };
        if !(0..=u64::MAX as i128).contains(&next) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

pub struct KeyDataReader {
    crypto: Option<Arc<Crypto>>,
    reader: BufReader<PositionedReader>,
    sequence: SequenceId,
    chunk_size: usize,
    total_size: u64,
    last_chunk_index: data::ChunkIndex,
    last_chunk_size: usize,

    next_chunk: data::ChunkIndex,
    finished: bool,
    expected_hash: Option<[u8; 32]>,
    consumed_size: u64,
    entry_nonce: Option<[u8; 24]>,
    log_identity: Option<[u8; 16]>,
    v3_crypto: Option<Arc<crate::crypto::V3Crypto>>,
    value_hasher: Option<sha2::Sha256>,
}

impl KeyDataReader {
    pub fn new(
        crypto: Option<Arc<Crypto>>,
        pointer: &KeyPointer,
        file: std::fs::File,
    ) -> Result<Self, LogFsError> {
        Self::new_shared(
            crypto,
            None,
            pointer,
            Arc::new(BackingFile::new(file)),
            false,
        )
    }

    pub(crate) fn new_verified(
        crypto: Option<Arc<Crypto>>,
        v3_crypto: Option<Arc<crate::crypto::V3Crypto>>,
        pointer: &KeyPointer,
        file: std::fs::File,
    ) -> Result<Self, LogFsError> {
        Self::new_shared(
            crypto,
            v3_crypto,
            pointer,
            Arc::new(BackingFile::new(file)),
            true,
        )
    }

    pub(crate) fn new_shared(
        crypto: Option<Arc<Crypto>>,
        v3_crypto: Option<Arc<crate::crypto::V3Crypto>>,
        pointer: &KeyPointer,
        backing: Arc<BackingFile>,
        verify_hash: bool,
    ) -> Result<Self, LogFsError> {
        let reader = BufReader::new(PositionedReader {
            backing,
            position: pointer.file_offset,
        });
        if pointer.entry_nonce.is_some() && crypto.is_some() && v3_crypto.is_none() {
            return Err(LogFsError::new_internal(
                "Encrypted v3 value requires the authenticated log secret",
            ));
        }
        if pointer.chunk_size == Some(0) {
            return Err(LogFsError::new_internal("Stored chunk size is zero"));
        }
        // Historical v2 writers stored an empty value as zero chunks. V3 uses
        // one explicit empty chunk (and therefore one AEAD tag when encrypted).
        let legacy_empty = pointer.size == 0 && pointer.entry_nonce.is_none();
        let chunk_count = if legacy_empty {
            0
        } else {
            pointer
                .chunk_size
                .map(|chunk_size| data::compute_chunk_count(pointer.size, chunk_size))
                .unwrap_or(1)
        };
        let last_chunk_index = if chunk_count == 0 {
            ENTRY_FIRST_DATA_CHUNK - 1
        } else {
            ENTRY_FIRST_DATA_CHUNK
                .checked_add(chunk_count - 1)
                .ok_or_else(|| LogFsError::new_internal("Stored chunk count overflow"))?
        };
        let last_chunk_size = if chunk_count == 0 {
            0
        } else if let Some(size) = pointer.chunk_size {
            let preceding = (size as u64)
                .checked_mul(chunk_count as u64 - 1)
                .ok_or_else(|| LogFsError::new_internal("Stored chunk layout overflow"))?;
            pointer
                .size
                .checked_sub(preceding)
                .ok_or_else(|| LogFsError::new_internal("Stored chunk layout underflow"))?
        } else {
            pointer.size
        };
        let last_chunk_size = usize::try_from(last_chunk_size)
            .map_err(|_| LogFsError::new_internal("Stored chunk is too large for this platform"))?;

        Ok(Self {
            crypto,
            reader,
            sequence: SequenceId::from_u64(pointer.sequence_id),
            chunk_size: pointer
                .chunk_size
                .map(|x| x as usize)
                .unwrap_or_else(|| usize::try_from(pointer.size).unwrap_or(usize::MAX).max(1)),
            total_size: pointer.size,
            last_chunk_index,
            last_chunk_size,
            next_chunk: ENTRY_FIRST_DATA_CHUNK,
            finished: chunk_count == 0,
            expected_hash: pointer.hash,
            consumed_size: 0,
            entry_nonce: pointer.entry_nonce,
            log_identity: pointer.log_identity,
            v3_crypto,
            value_hasher: verify_hash.then(sha2::Sha256::new),
        })
    }

    pub fn read_all(mut self) -> Result<Vec<u8>, LogFsError> {
        let capacity = usize::try_from(self.total_size)
            .map_err(|_| LogFsError::new_internal("Stored value is too large for this platform"))?;
        let mut data = Vec::with_capacity(capacity);

        while self.next_chunk < self.last_chunk_index {
            data.extend(self.read_next_chunk(Vec::with_capacity(self.chunk_size))?);
        }
        if !self.is_finished() {
            data.extend(self.read_next_chunk(Vec::with_capacity(self.last_chunk_size))?);
        }
        self.verify_complete()?;

        Ok(data)
    }

    pub(crate) fn verify_to_end(mut self) -> Result<(), LogFsError> {
        let mut buffer = Vec::with_capacity(self.chunk_size.min(1024 * 1024));
        while !self.is_finished() {
            buffer = self.read_next_chunk(buffer)?;
            buffer.clear();
        }
        self.verify_complete()
    }

    fn read_next_chunk(&mut self, mut buffer: Vec<u8>) -> Result<Vec<u8>, LogFsError> {
        debug_assert!(self.next_chunk >= ENTRY_FIRST_DATA_CHUNK);
        if self.finished || self.next_chunk > self.last_chunk_index {
            return Err(LogFsError::new_internal("Chunk index out of range"));
        }

        let chunk = self.next_chunk;
        let is_last = chunk == self.last_chunk_index;

        let size = if is_last {
            self.last_chunk_size
        } else {
            self.chunk_size
        };

        let padding = self
            .crypto
            .as_ref()
            .map(|c| c.extra_payload_len() as usize)
            .unwrap_or_default();

        let size = size
            .checked_add(padding)
            .ok_or_else(|| LogFsError::new_internal("Stored chunk allocation overflow"))?;
        buffer.resize(size, 0);
        self.reader.read_exact(&mut buffer)?;

        let data = if let Some(crypto) = self.v3_crypto.as_ref() {
            let identity = self.log_identity.ok_or_else(|| {
                LogFsError::new_internal("Encrypted v3 value is missing its log identity")
            })?;
            let entry_nonce = self
                .entry_nonce
                .ok_or_else(|| LogFsError::new_internal("V3 value is missing its random nonce"))?;
            let aad = super::v3_aad(identity, entry_nonce, chunk);
            crypto
                .decrypt_entry(super::v3_nonce(entry_nonce, chunk), &aad, &mut buffer)?
                .to_vec()
        } else if let Some(crypto) = self.crypto.as_ref() {
            crypto.decrypt_data(self.sequence.as_u64(), chunk, buffer)?
        } else {
            buffer
        };

        if is_last {
            self.finished = true;
        } else {
            self.next_chunk = self
                .next_chunk
                .checked_add(1)
                .ok_or_else(|| LogFsError::new_internal("Stored chunk index overflow"))?;
        }
        self.consumed_size = self
            .consumed_size
            .checked_add(data.len() as u64)
            .filter(|consumed| *consumed <= self.total_size)
            .ok_or_else(|| LogFsError::new_internal("Stored value length exceeds metadata"))?;
        if let Some(hasher) = self.value_hasher.as_mut() {
            hasher.update(&data);
        }
        if self.is_finished() {
            self.verify_complete()?;
        }

        Ok(data)
    }

    fn verify_complete(&self) -> Result<(), LogFsError> {
        if self.consumed_size != self.total_size {
            return Ok(());
        }
        if let (Some(hasher), Some(expected)) = (&self.value_hasher, self.expected_hash) {
            let actual: [u8; 32] = hasher.clone().finalize().into();
            if actual != expected {
                return Err(LogFsError::new_internal("Stored value hash mismatch"));
            }
        }
        Ok(())
    }

    fn skip_chunks(&mut self, count: u32) -> Result<(), LogFsError> {
        let target_chunk = self
            .next_chunk
            .checked_add(count)
            .ok_or_else(|| LogFsError::new_internal("Chunk index overflow"))?;
        if target_chunk > self.last_chunk_index {
            return Err(LogFsError::new_internal("Chunk index out of range"));
        }

        let padding = self
            .crypto
            .as_ref()
            .map(|c| c.extra_payload_len() as usize)
            .unwrap_or_default();

        let encoded_chunk_size = (self.chunk_size as u64)
            .checked_add(padding as u64)
            .ok_or_else(|| LogFsError::new_internal("Chunk skip size overflow"))?;
        let bytes_to_skip = (count as u64)
            .checked_mul(encoded_chunk_size)
            .ok_or_else(|| LogFsError::new_internal("Chunk skip offset overflow"))?;
        let bytes_to_skip = i64::try_from(bytes_to_skip)
            .map_err(|_| LogFsError::new_internal("Chunk skip offset is too large"))?;
        self.reader
            .seek(std::io::SeekFrom::Current(bytes_to_skip))?;
        self.next_chunk = target_chunk;
        self.consumed_size = self
            .consumed_size
            .checked_add(
                (count as u64)
                    .checked_mul(self.chunk_size as u64)
                    .ok_or_else(|| LogFsError::new_internal("Chunk skip length overflow"))?,
            )
            .filter(|consumed| *consumed <= self.total_size)
            .ok_or_else(|| LogFsError::new_internal("Chunk skip exceeds stored value"))?;
        // Seeking means this reader no longer observes the whole value.
        self.value_hasher = None;

        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.finished
    }

    /* fn close(self) -> std::fs::File {
        self.reader.into_inner()
    } */
}

pub struct StdKeyReader {
    reader: Option<KeyDataReader>,
    buffer: Vec<u8>,
    buffer_offset: usize,
}

impl StdKeyReader {
    pub fn new(reader: KeyDataReader) -> Self {
        Self {
            reader: Some(reader),
            buffer: Vec::new(),
            buffer_offset: 0,
        }
    }
}

impl std::io::Read for StdKeyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.buffer.is_empty() {
            let remaining_in_buffer = self.buffer.len() - self.buffer_offset;

            let to_write = std::cmp::min(buf.len(), remaining_in_buffer);
            buf[0..to_write]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + to_write]);

            if to_write >= remaining_in_buffer {
                self.buffer.clear();
            } else {
                self.buffer_offset += to_write;
            }
            return Ok(to_write);
        }

        let mut reader = if let Some(reader) = self.reader.take() {
            reader
        } else {
            return Ok(0);
        };

        if reader.is_finished() {
            reader.verify_complete().map_err(LogFsError::into_io)?;
            return Ok(0);
        }

        let res = reader.read_next_chunk(std::mem::take(&mut self.buffer));

        match res {
            Ok(new_buffer) => {
                self.buffer = new_buffer;
                self.buffer_offset = 0;
                self.reader = if !reader.is_finished() {
                    Some(reader)
                } else {
                    None
                };

                self.read(buf)
            }
            Err(err) => {
                self.reader = Some(reader);
                Err(err.into_io())
            }
        }
        // FIXME: write tests!
    }
}

pub struct KeyChunkIter {
    reader: KeyDataReader,
    /// Buffer for partial chunks.
    /// Required when Self::seek targets a partial chunk.
    partial_buffer: Option<Vec<u8>>,
}

impl KeyChunkIter {
    pub fn new(reader: KeyDataReader) -> Self {
        Self {
            reader,
            partial_buffer: None,
        }
    }

    pub fn skip_bytes(&mut self, offset: u64) -> Result<(), LogFsError> {
        if offset == 0 {
            return Ok(());
        }
        if let Some(partial) = self.partial_buffer.as_mut() {
            let take = usize::try_from(offset.min(partial.len() as u64))
                .map_err(|_| LogFsError::new_internal("Partial chunk offset overflow"))?;
            partial.drain(..take);
            if partial.is_empty() {
                self.partial_buffer = None;
            }
            if take as u64 == offset {
                return Ok(());
            }
            return self.skip_bytes(offset - take as u64);
        }
        let remaining = self
            .reader
            .total_size
            .saturating_sub(self.reader.consumed_size);
        if offset > remaining {
            return Err(LogFsError::new_internal("Seek out of bounds"));
        }
        if offset == remaining {
            self.reader.finished = true;
            self.reader.consumed_size = self.reader.total_size;
            return Ok(());
        }
        let to_skip = u32::try_from(offset / self.reader.chunk_size as u64)
            .map_err(|_| LogFsError::new_internal("Seek out of bounds"))?;
        self.reader.skip_chunks(to_skip)?;

        let partial = (offset % self.reader.chunk_size as u64) as usize;
        if partial > 0 {
            // Partial chunk read.
            // Need to read and buffer the next chunk.
            let mut data = self.reader.read_next_chunk(Vec::new())?;
            data.drain(..partial);
            debug_assert!(!data.is_empty());
            self.partial_buffer = Some(data);
        }
        Ok(())
    }
}

impl Iterator for KeyChunkIter {
    type Item = Result<Vec<u8>, LogFsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(partial) = self.partial_buffer.take() {
            Some(Ok(partial))
        } else if self.reader.is_finished() {
            None
        } else {
            Some(self.reader.read_next_chunk(Vec::new()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Journal2, LogConfig, LogFs};

    #[test]
    fn checkpoint_probe_rejects_non_index_before_payload_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed-checkpoint.log");
        let config = LogConfig {
            path: path.clone(),
            raw_mode: false,
            offset: None,
            allow_create: true,
            crypto: None,
            default_chunk_size: 1024 * 1024,
            partial_index_write_interval: 0,
            full_index_write_interval: 0,
            readonly: false,
        };
        let log = LogFs::<Journal2>::open(config).unwrap();
        log.insert("not-an-index", vec![0x5a; 8 * 1024 * 1024])
            .unwrap();
        drop(log);

        let file = std::fs::File::open(path).unwrap();
        let mut reader = LogReader::new_start(file, 0, None);
        reader.read_superblocks().unwrap();
        let mut payload = Vec::new();
        let error = reader.next_entry(Some(&mut payload)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not reference an index entry")
        );
        assert_eq!(payload.capacity(), 0);
    }
}
