use std::{
    io::{BufReader, BufWriter, Read, Seek, Write},
    sync::{atomic::AtomicBool, Arc, Mutex, RwLock},
};

use sha2::Digest;

use crate::{
    crypto::Crypto,
    state::{KeyPointer, SharedTree},
    LogConfig, LogFsError,
};

use self::data::ByteCountU64;

use super::SequenceId;

mod data;

#[derive(Debug)]
struct PersistedEntry {
    entry: data::JournalEntry,
    /// The offset where the entry data starts.
    file_data_offset: data::Offset,
}

#[derive(Clone)]
struct TaintedFlag(Arc<AtomicBool>);

impl TaintedFlag {
    fn set_tainted(&self) {
        self.0.swap(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_tainted(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub struct Journal2 {
    path: std::path::PathBuf,
    _tainted: TaintedFlag,
    crypto: Option<Arc<Crypto>>,
    state: Arc<State>,
    default_chunk_size: u32,
}

enum WriterState {
    Closed,
    Available(Option<LogWriter>),
}

struct State {
    /// The file used for writes.
    /// Only a single file descriptor is used for writes, which means concurrent
    /// writes are not possible.
    ///
    /// Seperate file descriptors are used for reading.
    writer: Mutex<WriterState>,
    writer_condvar: std::sync::Condvar,
}

impl State {
    fn return_writer(&self, writer: LogWriter) {
        *self.writer.lock().unwrap() = WriterState::Available(Some(writer));
        self.writer_condvar.notify_one();
    }

    fn acquire_borrowed_writer(&self) -> Result<LogWriter, LogFsError> {
        loop {
            let mut lock = self
                .writer
                .lock()
                .map_err(|_| LogFsError::new_internal("Could not acquire writer"))?;

            match &mut *lock {
                WriterState::Available(w) => match w.take() {
                    Some(w) => {
                        return Ok(w);
                    }
                    None => {
                        let mut new_lock = self
                            .writer_condvar
                            .wait(lock)
                            .map_err(|_| LogFsError::Tainted)?;
                        match &mut *new_lock {
                            WriterState::Closed => {
                                return Err(LogFsError::WriterClosed);
                            }
                            WriterState::Available(writer_opt) => {
                                if let Some(w) = writer_opt.take() {
                                    return Ok(w);
                                } else {
                                    continue;
                                }
                            }
                        }
                    }
                },
                WriterState::Closed => {
                    return Err(LogFsError::new_internal("Log is closed"));
                }
            }
        }
    }
}

impl Journal2 {
    pub fn open(
        path: std::path::PathBuf,
        state: &mut crate::state::State,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError> {
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // TODO: use file locks on platforms that support it.
        let file = std::fs::OpenOptions::new()
            .create(config.allow_create)
            .read(true)
            .write(true)
            .open(&path)?;
        let meta = file.metadata()?;
        let file_size = meta.len();

        let tainted = TaintedFlag(Arc::new(AtomicBool::new(false)));

        let writer = if config.raw_mode {
            match Self::open_existing(file, state, &crypto, &tainted) {
                Ok(w) => w,
                Err(_err) => {
                    if config.allow_create {
                        let file = std::fs::OpenOptions::new()
                            .create(true)
                            .read(true)
                            .write(true)
                            .open(&path)?;
                        LogWriter::create_new(crypto.clone(), tainted.clone(), file)?
                    } else {
                        return Err(LogFsError::new_internal(
                            "Could not open database: file does not appear to be a log",
                        ));
                    }
                }
            }
        } else if file_size == 0 {
            LogWriter::create_new(crypto.clone(), tainted.clone(), file)?
        } else {
            Self::open_existing(file, state, &crypto, &tainted)?
        };

        let j = Self {
            state: Arc::new(State {
                writer: std::sync::Mutex::new(WriterState::Available(Some(writer))),
                writer_condvar: std::sync::Condvar::new(),
            }),
            _tainted: tainted,
            crypto,
            path,
            default_chunk_size: config.default_chunk_size,
        };

        Ok(j)
    }

    fn open_existing(
        file: std::fs::File,
        state: &mut crate::state::State,
        crypto: &Option<Arc<Crypto>>,
        tainted: &TaintedFlag,
    ) -> Result<LogWriter, LogFsError> {
        let meta = file.metadata()?;
        let file_size = meta.len();

        let mut reader = LogReader::new_start(file, crypto.as_ref().map(|x| &**x));
        let superblock = reader.read_superblocks()?;

        loop {
            // TODO: use sequence number instead to support raw files
            if reader.next_sequence.as_u64() > superblock.block.active_sequence {
                break;
            }
            let entry = reader.next_entry()?;
            apply_entry(state, entry)?;
        }

        let file = reader.reader.into_inner();

        // Make sure file wasn't modified in the meantime.
        if file.metadata()?.len() != file_size {
            return Err(LogFsError::new_internal(
                "File was modified during bootstrap",
            ));
        }
        let writer = LogWriter::open(crypto.clone(), tainted.clone(), file, superblock)?;
        Ok(writer)
    }

    fn open_and_truncate_file(
        path: &std::path::Path,
        new_length: u64,
    ) -> Result<std::fs::File, std::io::Error> {
        let f = std::fs::OpenOptions::new()
            .create(false)
            .read(true)
            .write(true)
            .open(path)?;
        f.set_len(new_length)?;
        Ok(f)
    }

    fn write_entry(
        &self,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        chunk_size: u32,
    ) -> Result<PersistedEntry, LogFsError> {
        loop {
            let mut writer = self
                .state
                .writer
                .lock()
                .map_err(|_| LogFsError::new_internal("Could not retrieve log writer"))?;
            match &mut *writer {
                WriterState::Closed => return Err(LogFsError::new_internal("Log is closed")),
                WriterState::Available(None) => {
                    let mut new_state = self
                        .state
                        .writer_condvar
                        .wait(writer)
                        .map_err(|_| LogFsError::Tainted)?;
                    match &mut *new_state {
                        WriterState::Available(Some(w)) => {
                            return w.write_journal_entry(chunk_size, action, data, false);
                        }
                        WriterState::Available(None) => {
                            continue;
                        }
                        WriterState::Closed => {
                            return Err(LogFsError::WriterClosed);
                        }
                    }
                }
                WriterState::Available(Some(w)) => {
                    return w.write_journal_entry(chunk_size, action, data, false);
                }
            }
        }
    }

    pub fn write_insert(
        &self,
        path: data::KeyPath,
        data: Vec<u8>,
        chunk_size: u32,
    ) -> Result<KeyPointer, LogFsError> {
        let chunk_size_opt = if data.len() > chunk_size as usize {
            Some(chunk_size)
        } else {
            None
        };

        let hash = sha2::Sha256::digest(&data);
        let action = data::JournalAction::KeyInsert(data::ActionKeyInsert {
            meta: data::KeyMeta {
                path: path.clone(),
                size: data.len() as u64,
                hash: data::Sha256Hash(hash.into()),
                chunk_size: chunk_size_opt,
            },
        });

        let size = data.len() as u64;
        let entry = self.write_entry(action, Some(data), chunk_size)?;

        Ok(KeyPointer {
            sequence_id: entry.entry.header.sequence_id.as_u64(),
            offset: entry.file_data_offset,
            size,
            chunk_size: chunk_size_opt,
        })
    }

    pub fn write_rename(
        &self,
        old_key: data::KeyPath,
        new_key: data::KeyPath,
    ) -> Result<(), LogFsError> {
        let action = data::JournalAction::KeyRename(data::ActionKeyRename {
            renames: vec![data::KeyRename { old_key, new_key }],
        });
        self.write_entry(action, None, 0)?;
        Ok(())
    }

    pub fn write_remove(&self, deleted_keys: Vec<data::KeyPath>) -> Result<(), LogFsError> {
        let action = data::JournalAction::KeyDelete(data::ActionKeyDelete { deleted_keys });
        self.write_entry(action, None, 0)?;
        Ok(())
    }

    pub fn read_data(&self, pointer: &KeyPointer) -> Result<Vec<u8>, LogFsError> {
        // TODO: use a pool of reused file descriptors
        let f = std::fs::File::open(&self.path)?;
        let reader = KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        let (data, _file) = reader.read_all()?;
        Ok(data)
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<StdKeyReader, LogFsError> {
        // TODO: use a pool of reused file descriptors
        let f = std::fs::File::open(&self.path)?;
        let reader = KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        Ok(StdKeyReader::new(reader))
    }

    fn chunk_iter(&self, pointer: &KeyPointer) -> Result<KeyChunkIter, LogFsError> {
        // TODO: use a pool of reused file descriptors
        let f = std::fs::File::open(&self.path)?;
        let reader = KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        Ok(KeyChunkIter::new(reader))
    }

    /// Get a reference to the journal's path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

fn apply_entry(state: &mut crate::state::State, entry: PersistedEntry) -> Result<(), LogFsError> {
    match entry.entry.action {
        data::JournalAction::KeyInsert(action) => {
            let key = action.meta;
            state.add_key(
                key.path,
                KeyPointer {
                    sequence_id: entry.entry.header.sequence_id.as_u64(),
                    offset: entry.file_data_offset,
                    size: key.size,
                    chunk_size: key.chunk_size,
                },
            )
        }
        data::JournalAction::KeyRename(action) => {
            for rename in action.renames {
                // TODO: raise error if old key does not exist?
                if let Err(_err) = state.rename_key(&rename.old_key, rename.new_key) {
                    tracing::trace!("Log entry tried to rename a key that does not exist");
                }
            }
        }
        data::JournalAction::KeyDelete(action) => {
            for key in action.deleted_keys {
                // TODO: raise error if old key does not exist?
                if state.remove_key(&key).is_none() {
                    tracing::trace!("Log entry tried to delete a key that does not exist");
                }
            }
        }
        data::JournalAction::IndexWrite(_) => {}
    }

    Ok(())
}

const ENTRY_HEADER_CHUNK: data::ChunkIndex = 0;
const ENTRY_ACTION_CHUNK: data::ChunkIndex = 1;
const ENTRY_FIRST_DATA_CHUNK: data::ChunkIndex = 2;

#[derive(Debug)]
struct IndexedSuperBlock {
    block: data::Superblock,
    index: usize,
}

struct LogReader<'a, R> {
    offset: u64,
    next_sequence: SequenceId,
    crypto: Option<&'a Crypto>,
    buffer: Vec<u8>,
    reader: BufReader<R>,
}

impl<'a, R: std::io::Read + std::io::Seek> LogReader<'a, R> {
    fn new_start(reader: R, crypto: Option<&'a Crypto>) -> Self {
        Self {
            offset: 0,
            next_sequence: SequenceId::first(),
            crypto,
            buffer: Vec::new(),
            reader: BufReader::new(reader),
        }
    }

    fn read_superblocks(&mut self) -> Result<IndexedSuperBlock, LogFsError> {
        let mut best_block: Option<IndexedSuperBlock> = None;

        let mut buf = Vec::new();
        for index in 0..data::Superblock::HEADER_COUNT {
            buf.resize(data::Superblock::SERIALIZED_LEN as usize, 0);
            self.reader.read_exact(&mut buf)?;

            if let Some(crypto) = self.crypto.as_ref() {
                buf = match crypto.decrypt_data(0, index as u32, std::mem::take(&mut buf)) {
                    Ok(b) => b,
                    Err(_err) => {
                        continue;
                    }
                };
            }

            match bincode::deserialize::<data::Superblock>(&buf) {
                Ok(block) => {
                    best_block = if let Some(old_block) = best_block {
                        if block.active_sequence > old_block.block.active_sequence {
                            Some(IndexedSuperBlock {
                                index: index as usize,
                                block,
                            })
                        } else {
                            Some(old_block)
                        }
                    } else {
                        Some(IndexedSuperBlock {
                            block,
                            index: index as usize,
                        })
                    };
                }
                Err(_err) => {}
            }
        }

        let block =
            best_block.ok_or_else(|| LogFsError::new_internal("Could not find a superblock"))?;
        self.offset = self.reader.stream_position()?;
        debug_assert_eq!(self.offset, data::Superblock::HEADER_SIZE);

        Ok(block)
    }

    fn next_entry(&mut self) -> Result<PersistedEntry, LogFsError> {
        let chunk_padding = self.crypto.map(|c| c.extra_payload_len()).unwrap_or(0) as usize;
        let start_offset = self.offset;
        let buffer = &mut self.buffer;
        let sequence = self.next_sequence;

        let header_size = data::JournalEntryHeader::SERIALIZED_LEN + chunk_padding;

        // Read journal entry header.
        buffer.resize(header_size, 0);

        self.reader.read_exact(buffer)?;

        let header_data = if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, buffer)?
        } else {
            &buffer
        };
        let header: data::JournalEntryHeader = bincode::deserialize(&header_data)?;

        if self.next_sequence != header.sequence_id {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry sequence number for sequence {:?}",
                self.next_sequence
            )));
        }
        if start_offset != header.offset {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry offset does not match actual offset for sequence {:?}",
                self.next_sequence
            )));
        }

        // Read the journal action.

        // Make sure the buffer can hold the data.
        let action_size = header.action_size as usize;
        buffer.resize(action_size, 0);
        // Read into buffer.
        self.reader.read_exact(buffer)?;

        // Decrypt.

        let action_data = if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
        } else {
            &buffer
        };

        let action: data::JournalAction = bincode::deserialize(action_data)?;

        let data_len = match &action {
            data::JournalAction::KeyInsert(key) => {
                key.meta.size + (chunk_padding as u64 * key.meta.chunk_count() as u64)
            }
            data::JournalAction::KeyRename(_) => 0,
            data::JournalAction::KeyDelete(_) => 0,
            data::JournalAction::IndexWrite(w) => w.size as u64 + chunk_padding as u64,
        };
        self.reader
            .seek(std::io::SeekFrom::Current(data_len as i64))?;

        let data_offset = start_offset + header_size as u64 + action_size as u64;
        let next_entry_offset = data_offset + data_len;
        self.offset = next_entry_offset;
        self.next_sequence = self.next_sequence.try_increment()?;

        assert_eq!(self.offset, self.reader.stream_position()?);

        Ok(PersistedEntry {
            entry: data::JournalEntry { header, action },
            file_data_offset: data_offset,
        })
    }
}

pub struct LogWriter {
    crypto: Option<Arc<Crypto>>,
    next_sequence: SequenceId,
    offset: data::Offset,
    writer: BufWriter<std::fs::File>,
    active_superblock: IndexedSuperBlock,
    tainted: TaintedFlag,

    incomplete_entry_in_progress: bool,
    actions_since_last_index_write: u64,
}

impl LogWriter {
    fn create_new(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        file: std::fs::File,
    ) -> Result<Self, LogFsError> {
        let mut s = Self {
            crypto,
            next_sequence: SequenceId::first(),
            offset: data::Superblock::HEADER_SIZE,
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
        s.writer.seek(std::io::SeekFrom::Start(
            s.active_superblock.block.tail_offset,
        ))?;

        Ok(s)
    }

    fn open(
        crypto: Option<Arc<Crypto>>,
        tainted: TaintedFlag,
        mut file: std::fs::File,
        block: IndexedSuperBlock,
    ) -> Result<Self, LogFsError> {
        assert!(block.index < data::Superblock::HEADER_COUNT as usize);

        file.seek(std::io::SeekFrom::Start(block.block.tail_offset))?;

        let s = Self {
            crypto,
            next_sequence: SequenceId::from_u64(block.block.active_sequence + 1),
            offset: block.block.tail_offset,
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
        assert_eq!(self.writer.stream_position()?, 0);

        for _ in 0..data::Superblock::HEADER_COUNT {
            self.write_next_superblock()?;
        }
        self.offset = data::Superblock::HEADER_SIZE;

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
                tail_offset: self.offset,
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
        debug_assert_eq!(block.block.tail_offset, self.offset);
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

        let offset = block.index as u64 * data::Superblock::SERIALIZED_LEN;

        self.writer.seek(std::io::SeekFrom::Start(offset))?;
        self.writer.write_all(&buffer)?;
        self.writer.flush()?;

        self.writer.seek(std::io::SeekFrom::Start(self.offset))?;

        self.active_superblock = block;

        Ok(())
    }

    fn write_journal_entry(
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
            other => other,
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

    fn write_action(
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
            offset: self.offset,
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
    ) -> Result<ByteCountU64, LogFsError> {
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

struct LogChunkWriter {
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
    fn new(
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
        writer
            .writer
            .seek(std::io::SeekFrom::Start(self.header.offset))?;
        writer.offset = self.header.offset;
        writer.incomplete_entry_in_progress = false;
        let header = writer.write_action(&action, false)?;

        assert_eq!(header.action_size, self.header.action_size);
        assert_eq!(header.offset, self.header.offset);
        assert_eq!(header.sequence_id, self.header.sequence_id);

        writer.writer.flush()?;

        let pointer = KeyPointer {
            sequence_id: writer.next_sequence.as_u64(),
            offset: writer.offset,
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
    fn new(writer: LogChunkWriter) -> Self {
        let mut buffer = Vec::new();
        buffer.resize(writer.chunk_size as usize, 0);
        Self {
            buffer,
            writer: Some(writer),
            buffer_offset: 0,
        }
    }

    pub fn finish(mut self) -> Result<(), LogFsError> {
        let final_data = if self.buffer_offset > 0 {
            self.buffer.truncate(self.buffer_offset);
            Some(&mut self.buffer)
        } else {
            None
        };
        self.writer.take().unwrap().finalize(final_data)
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
            panic!("Unfinished KeyWriter dropped. Must call KeyWriter::finish()");
        }
    }
}

pub struct KeyDataReader {
    crypto: Option<Arc<Crypto>>,
    reader: BufReader<std::fs::File>,
    sequence: SequenceId,
    chunk_size: usize,
    total_size: u64,
    last_chunk_index: data::ChunkIndex,
    last_chunk_size: usize,

    next_chunk: data::ChunkIndex,
}

impl KeyDataReader {
    fn new(
        crypto: Option<Arc<Crypto>>,
        pointer: &KeyPointer,
        mut file: std::fs::File,
    ) -> Result<Self, LogFsError> {
        file.seek(std::io::SeekFrom::Start(pointer.offset))?;
        let reader = BufReader::new(file);
        let chunk_count = pointer
            .chunk_size
            .map(|chunk_size| data::compute_chunk_count(pointer.size, chunk_size))
            .unwrap_or(1);

        let last_chunk_index = chunk_count - 1 + ENTRY_FIRST_DATA_CHUNK;
        let last_chunk_size = pointer
            .chunk_size
            .map(|s| pointer.size - (s as u64 * (chunk_count as u64 - 1)))
            .unwrap_or(pointer.size) as usize;

        Ok(Self {
            crypto,
            reader,
            sequence: SequenceId::from_u64(pointer.sequence_id),
            chunk_size: pointer
                .chunk_size
                .map(|x| x as usize)
                .unwrap_or(pointer.size as usize),
            total_size: pointer.size,
            last_chunk_index,
            last_chunk_size,
            next_chunk: ENTRY_FIRST_DATA_CHUNK,
        })
    }

    fn read_all(mut self) -> Result<(Vec<u8>, std::fs::File), LogFsError> {
        let mut data = Vec::with_capacity(self.total_size as usize);

        while self.next_chunk < self.last_chunk_index {
            data.extend(self.read_next_chunk(Vec::with_capacity(self.chunk_size))?);
        }

        data.extend(self.read_next_chunk(Vec::with_capacity(self.last_chunk_size))?);

        Ok((data, self.reader.into_inner()))
    }

    fn read_next_chunk(&mut self, mut buffer: Vec<u8>) -> Result<Vec<u8>, LogFsError> {
        debug_assert!(self.next_chunk >= ENTRY_FIRST_DATA_CHUNK);
        assert!(self.next_chunk <= self.last_chunk_index as u32);

        let chunk = self.next_chunk;
        let is_last = chunk == self.last_chunk_index;

        let size = if is_last {
            if self.last_chunk_index == ENTRY_FIRST_DATA_CHUNK {
                self.chunk_size
            } else {
                (self.total_size
                    - (self.last_chunk_index - ENTRY_FIRST_DATA_CHUNK) as u64
                        * self.chunk_size as u64) as usize
            }
        } else {
            self.chunk_size
        };

        let padding = self
            .crypto
            .as_ref()
            .map(|c| c.extra_payload_len() as usize)
            .unwrap_or_default();

        let size = size + padding;
        buffer.resize(size, 0);
        self.reader.read_exact(&mut buffer)?;

        let data = if let Some(crypto) = self.crypto.as_ref() {
            crypto.decrypt_data(self.sequence.as_u64(), chunk, buffer)?
        } else {
            buffer
        };

        self.next_chunk = self.next_chunk + 1;

        Ok(data)
    }

    fn is_finished(&self) -> bool {
        self.next_chunk > self.last_chunk_index
    }
}

pub struct StdKeyReader {
    reader: Option<KeyDataReader>,
    buffer: Vec<u8>,
    buffer_offset: usize,
}

impl StdKeyReader {
    fn new(reader: KeyDataReader) -> Self {
        Self {
            reader: Some(reader),
            buffer: Vec::new(),
            buffer_offset: 0,
        }
    }
}

impl std::io::Read for StdKeyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(mut reader) = self.reader.take() {
            if self.buffer.is_empty() {
                let res = reader.read_next_chunk(std::mem::take(&mut self.buffer));

                match res {
                    Ok(buf) => {
                        self.buffer = buf;
                        self.buffer_offset = 0;
                        self.reader = if reader.next_chunk <= reader.last_chunk_index {
                            Some(reader)
                        } else {
                            None
                        };
                    }
                    Err(err) => {
                        self.reader = Some(reader);
                        return Err(err.into_io());
                    }
                }
            } else {
                self.reader = Some(reader);
            }

            let remaining_in_buffer = self.buffer.len() - self.buffer_offset;

            let to_write = std::cmp::min(buf.len(), remaining_in_buffer);
            buf[0..to_write]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + to_write]);

            if self.buffer_offset + to_write >= self.buffer.len() {
                self.buffer.clear();
            } else {
                self.buffer_offset += to_write;
            }
            Ok(to_write)
        } else {
            Ok(0)
        }
    }
}

pub struct KeyChunkIter {
    reader: KeyDataReader,
}

impl KeyChunkIter {
    pub fn new(reader: KeyDataReader) -> Self {
        Self { reader }
    }
}

impl Iterator for KeyChunkIter {
    type Item = Result<Vec<u8>, LogFsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.reader.is_finished() {
            None
        } else {
            Some(self.reader.read_next_chunk(Vec::new()))
        }
    }
}

impl super::JournalStore for Journal2 {
    fn open(
        path: std::path::PathBuf,
        state: &mut crate::state::State,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError>
    where
        Self: Sized,
    {
        Journal2::open(path, state, crypto, config)
    }

    fn write_insert(&self, path: crate::Path, data: Vec<u8>) -> Result<KeyPointer, LogFsError> {
        self.write_insert(path, data, self.default_chunk_size)
    }

    fn write_rename(&self, old_path: crate::Path, new_path: crate::Path) -> Result<(), LogFsError> {
        self.write_rename(old_path, new_path)
    }

    fn write_remove(&self, paths: Vec<crate::Path>) -> Result<(), LogFsError> {
        self.write_remove(paths)
    }

    fn read_data(&self, pointer: &KeyPointer) -> Result<Vec<u8>, LogFsError> {
        self.read_data(pointer)
    }

    fn insert_writer(&self, path: crate::Path, tree: SharedTree) -> Result<KeyWriter, LogFsError> {
        let writer = self.state.acquire_borrowed_writer()?;
        Ok(KeyWriter::new(LogChunkWriter::new(
            tree,
            self.state.clone(),
            writer,
            self.default_chunk_size,
            path,
        )?))
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<StdKeyReader, LogFsError> {
        Journal2::reader(&self, pointer)
    }

    fn read_chunks(&self, pointer: &KeyPointer) -> Result<KeyChunkIter, LogFsError> {
        Journal2::chunk_iter(&self, pointer)
    }
}
