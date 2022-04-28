use std::{
    io::{BufWriter, Seek, SeekFrom, Write},
    sync::{atomic::AtomicBool, Arc, RwLock},
};

use sha2::Digest;

use crate::{
    crypto::Crypto,
    journal::{
        v2::{ENTRY_ACTION_CHUNK, ENTRY_HEADER_CHUNK},
        SequenceId,
    },
    state::KeyPointer,
    LogFsError,
};

use super::{
    data::{self, ByteCountU64},
    IndexedSuperBlock, PersistedEntry, State, ENTRY_FIRST_DATA_CHUNK,
};

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
}

impl LogWriter {
    pub(crate) fn offset(&self) -> data::Offset {
        self.offset
    }

    pub(crate) fn create_new(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        file: std::fs::File,
        base_offset: u64,
    ) -> Result<Self, LogFsError> {
        let mut s = Self {
            base_offset,
            crypto,
            next_sequence: SequenceId::first(),
            offset: base_offset + data::Superblock::HEADER_SIZE,
            writer: BufWriter::new(file),
            incomplete_entry_in_progress: false,
            active_superblock: IndexedSuperBlock {
                block: data::Superblock {
                    format_version: data::LogFormatVersion::V2,
                    flags: data::SuperblockFlags::empty(),
                    active_sequence: 0,
                    tail_offset: data::Superblock::HEADER_SIZE as u64,
                    last_index_entry: None,
                },
                index: 0,
            },
            actions_since_last_index_write: 0,
            tainted,
        };

        s.create_superblocks()?;
        s.writer.seek(SeekFrom::Start(
            base_offset + s.active_superblock.block.tail_offset,
        ))?;

        Ok(s)
    }

    pub(super) fn open(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        mut file: std::fs::File,
        base_offset: u64,
        block: IndexedSuperBlock,
    ) -> Result<Self, LogFsError> {
        assert!(block.index < data::Superblock::HEADER_COUNT as usize);

        file.seek(SeekFrom::Start(base_offset + block.block.tail_offset))?;

        let s = Self {
            base_offset,
            crypto,
            next_sequence: SequenceId::from_u64(block.block.active_sequence + 1),
            offset: base_offset + block.block.tail_offset,
            incomplete_entry_in_progress: false,
            writer: BufWriter::new(file),
            actions_since_last_index_write: block
                .block
                .last_index_entry
                .clone()
                .map(|entry| block.block.active_sequence - entry.sequence.as_u64())
                .unwrap_or(block.block.active_sequence),
            active_superblock: block,
            tainted,
        };

        Ok(s)
    }

    fn crypto(&self) -> Option<&Crypto> {
        self.crypto.as_ref().map(|x| &**x)
    }

    fn data_padding(&self) -> u64 {
        self.crypto()
            .map(|c| c.extra_payload_len())
            .unwrap_or_default()
    }

    fn create_superblocks(&mut self) -> Result<(), LogFsError> {
        assert_eq!(self.next_sequence, SequenceId::first());
        assert_eq!(self.writer.stream_position()?, self.base_offset);

        for _ in 0..data::Superblock::HEADER_COUNT {
            self.write_next_superblock()?;
        }
        self.offset = self.base_offset + data::Superblock::HEADER_SIZE;
        debug_assert_eq!(self.offset, self.writer.stream_position().unwrap());

        Ok(())
    }

    fn write_next_superblock(&mut self) -> Result<(), LogFsError> {
        let index = if (self.active_superblock.index as u64) < data::Superblock::HEADER_COUNT - 1 {
            self.active_superblock.index + 1
        } else {
            0
        };

        let block = IndexedSuperBlock {
            index,
            block: data::Superblock {
                format_version: self.active_superblock.block.format_version,
                flags: self.active_superblock.block.flags,
                active_sequence: self.next_sequence.as_u64() - 1,
                tail_offset: self.offset - self.base_offset,
                last_index_entry: self.active_superblock.block.last_index_entry.clone(),
            },
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
        assert_eq!(self.tainted.is_tainted(), false);

        debug_assert_eq!(self.incomplete_entry_in_progress, false);
        debug_assert_eq!(block.block.active_sequence, self.next_sequence.as_u64() - 1);
        debug_assert_eq!(block.block.tail_offset, self.offset - self.base_offset);
        if let Some(ptr) = &block.block.last_index_entry {
            debug_assert!(ptr.sequence < self.next_sequence);
        }

        let block_size = data::Superblock::SERIALIZED_LEN - self.data_padding();
        let mut buffer = bincode::serialize(&block.block)?;
        assert!((buffer.len() as u64) < block_size);
        buffer.resize(block_size as usize, 0);
        if let Some(crypto) = self.crypto() {
            crypto.encrypt_data(0, block.index as u32, &mut buffer)?;
        }
        debug_assert_eq!(buffer.len(), data::Superblock::SERIALIZED_LEN as usize);

        let offset = self.base_offset + block.index as u64 * data::Superblock::SERIALIZED_LEN;

        self.writer.seek(SeekFrom::Start(offset))?;
        self.writer.write_all(&buffer)?;
        self.writer.flush()?;

        self.writer.seek(SeekFrom::Start(self.offset))?;

        self.active_superblock = block;

        Ok(())
    }

    pub(super) fn write_journal_entry(
        &mut self,
        chunk_size: u32,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        incomplete: bool,
    ) -> Result<PersistedEntry, LogFsError> {
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
            self.write_next_superblock()?;
        }

        let entry = PersistedEntry {
            entry: data::JournalEntry { header, action },
            file_data_offset: data_offset,
        };

        Ok(entry)
    }

    pub fn write_action(
        &mut self,
        action: &data::JournalAction,
        incomplete: bool,
    ) -> Result<data::JournalEntryHeader, LogFsError> {
        assert_eq!(self.tainted.is_tainted(), false);
        debug_assert_eq!(self.incomplete_entry_in_progress, false);
        debug_assert_eq!(self.offset, self.writer.stream_position()?);

        let sequence = self.next_sequence;

        let mut action_data = bincode::serialize(&action)?;
        if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(sequence.as_u64(), ENTRY_ACTION_CHUNK, &mut action_data)?;
        }
        let action_data_len = action_data.len();

        let flags = if incomplete {
            data::JournalEntryHeaderFlags::INCOMPLETE
        } else {
            data::JournalEntryHeaderFlags::empty()
        };
        let header = data::JournalEntryHeader {
            offset: self.offset - self.base_offset,
            sequence_id: sequence,
            action_size: action_data_len as u32,
            flags,
        };
        let mut header_data = bincode::serialize(&header)?;
        debug_assert_eq!(header_data.len(), data::JournalEntryHeader::SERIALIZED_LEN);
        if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(sequence.as_u64(), ENTRY_HEADER_CHUNK, &mut header_data)?;
        }

        self.writer.write_all(&header_data)?;
        self.writer.write_all(&action_data)?;

        self.offset += header_data.len() as u64 + action_data.len() as u64;
        debug_assert_eq!(self.writer.stream_position().unwrap(), self.offset);
        self.incomplete_entry_in_progress = true;

        Ok(header)
    }

    fn write_data(&mut self, chunk_size: u32, mut data: Vec<u8>) -> Result<u64, LogFsError> {
        let chunks = data::compute_chunk_count(data.len() as u64, chunk_size);
        let chunk_size = chunk_size as usize;

        let last_chunk_index = ENTRY_FIRST_DATA_CHUNK + chunks - 1;

        let mut full_len = 0u64;

        // Write all full chunks.
        for chunk in ENTRY_FIRST_DATA_CHUNK..last_chunk_index {
            let remaining_data = data.split_off(chunk_size);
            debug_assert_eq!(data.len(), chunk_size);

            full_len += self.write_data_chunk(chunk, &mut data)?;
            data = remaining_data;
        }

        // Write the last (partial) chunk.
        full_len += self.write_data_chunk(last_chunk_index, &mut data)?;

        Ok(full_len)
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
        debug_assert_eq!(self.incomplete_entry_in_progress, true);
        debug_assert!(chunk >= ENTRY_FIRST_DATA_CHUNK);

        if let Some(crypto) = self.crypto.as_ref() {
            crypto.encrypt_data(self.next_sequence.as_u64(), chunk, data)?;
        }
        let len = data.len() as u64;

        self.writer.write_all(&data)?;
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
}

impl LogChunkWriter {
    pub(super) fn new(
        tree: Arc<RwLock<crate::state::State>>,
        state: Arc<State>,
        mut writer: LogWriter,
        chunk_size: u32,
        path: data::KeyPath,
    ) -> Result<Self, LogFsError> {
        let action = data::JournalAction::KeyInsert(data::ActionKeyInsert {
            meta: data::KeyMeta {
                size: 0,
                chunk_size: Some(chunk_size),
                hash: data::Sha256Hash::from_array([0u8; 32]),
                path: path.clone(),
            },
        });

        let header = writer.write_action(&action, true)?;

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
        })
    }

    fn write_chunk(&mut self, data: &mut Vec<u8>, is_last: bool) -> Result<(), LogFsError> {
        if !is_last {
            assert_eq!(data.len(), self.chunk_size as usize);
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

    fn finalize(mut self, final_data: Option<&mut Vec<u8>>) -> Result<(), LogFsError> {
        if let Some(data) = final_data {
            assert!(data.len() < self.chunk_size as usize);
            self.write_chunk(data, true)?;
        }

        let meta = data::KeyMeta {
            size: self.data_size,
            chunk_size: Some(self.chunk_size),
            hash: data::Sha256Hash(self.hasher.finalize().into()),
            path: self.path,
        };

        let action = data::JournalAction::KeyInsert(data::ActionKeyInsert { meta: meta.clone() });

        let mut writer = self.writer;
        let end_offset = writer.offset;
        writer.writer.seek(SeekFrom::Start(self.header.offset))?;
        writer.offset = self.header.offset;
        writer.incomplete_entry_in_progress = false;
        let header = writer.write_action(&action, false)?;

        assert_eq!(header.action_size, self.header.action_size);
        assert_eq!(header.offset, self.header.offset);
        assert_eq!(header.sequence_id, self.header.sequence_id);

        writer.writer.flush()?;

        let pointer = KeyPointer {
            sequence_id: writer.next_sequence.as_u64(),
            file_offset: writer.offset,
            size: self.data_size,
            chunk_size: Some(self.chunk_size),
        };

        writer.offset = end_offset;
        writer.incomplete_entry_in_progress = false;
        writer.next_sequence = writer.next_sequence.try_increment().unwrap();

        writer.write_next_superblock()?;

        self.tree.write().unwrap().add_key(meta.path, pointer);
        self.state.return_writer(writer);

        Ok(())
    }
}

pub struct KeyWriter {
    writer: Option<LogChunkWriter>,
    buffer: Vec<u8>,
    buffer_offset: usize,
}

impl KeyWriter {
    pub fn new(writer: LogChunkWriter) -> Self {
        let mut buffer = Vec::new();
        buffer.resize(writer.chunk_size as usize, 0);
        Self {
            buffer,
            writer: Some(writer),
            buffer_offset: 0,
        }
    }

    pub fn finish(mut self) -> Result<(), LogFsError> {
        self.finish_mut()
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
            .expect("writer must be available")
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
        writer.writer.writer.flush()
    }
}

impl Drop for KeyWriter {
    fn drop(&mut self) {
        if self.writer.is_some() {
            self.finish_mut().expect(
                "Drop handler for KeyWriter failed - you should always call KeyWriter::finish()",
            );
        }
    }
}
