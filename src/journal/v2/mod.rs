pub mod read;
mod repair;
pub mod write;

use std::{
    collections::BTreeMap,
    io::{self, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use sha2::Digest;

use crate::{
    crypto::Crypto,
    state::{KeyPointer, SharedTree},
    KeyLock, LogConfig, LogFsError, Path,
};

use self::{
    data::{EntryPointer, Offset},
    write::LogWriter,
};

use super::{RepairConfig, SequenceId};

mod data;
pub use data::Superblock;

#[derive(Debug)]
struct PersistedEntry {
    entry: data::JournalEntry,
    /// The offset where the entry data starts.
    file_data_offset: data::Offset,
}

impl PersistedEntry {
    // fn to_key_pointer(&self, crypto: Option<&Crypto>) -> KeyPointer {
    //     KeyPointer {
    //         sequence_id: self.entry.header.sequence_id.as_u64(),
    //         file_offset: self.file_data_offset,
    //         size: self.entry.action.payload_len(crypto),
    //         chunk_size: match &self.entry.action {
    //             data::JournalAction::KeyInsert(ins) => ins.meta.chunk_size,
    //             data::JournalAction::KeyRename(_) => None,
    //             data::JournalAction::KeyDelete(_) => None,
    //             data::JournalAction::IndexWrite(_) => None,
    //         },
    //     }
    // }
}

pub struct Journal2 {
    path: std::path::PathBuf,
    _tainted: write::TaintedFlag,
    crypto: Option<Arc<Crypto>>,
    state: Arc<State>,
    default_chunk_size: u32,
}

#[derive(Debug)]
enum WriterState {
    // FIXME: clean up log writer tainting logic
    #[allow(dead_code)]
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
        eprintln!("borrowed writer returned");
    }

    fn acquire_borrowed_writer(&self) -> Result<LogWriter, LogFsError> {
        let mut lock = self
            .writer
            .lock()
            .map_err(|_| LogFsError::new_internal("Could not acquire writer"))?;

        loop {
            match &mut *lock {
                WriterState::Available(w) => match w.take() {
                    Some(w) => {
                        eprintln!("borrowed writer acquired");
                        return Ok(w);
                    }
                    None => {
                        lock = self
                            .writer_condvar
                            .wait(lock)
                            .map_err(|_| LogFsError::Tainted)?;
                    }
                },
                WriterState::Closed => {
                    return Err(LogFsError::new_internal("Log is closed"));
                }
            }
        }
    }
}

/// Try to find a valid entry header at an arbitrary position in a buffer.
/// Useful for recovery of corrupted logs.
fn find_entry_header_in_slice(
    crypto: Option<&Crypto>,
    sequence: SequenceId,
    data: &[u8],
) -> Option<(data::JournalEntryHeader, Offset)> {
    if let Some(crypto) = crypto {
        let header_len =
            data::JournalEntryHeader::SERIALIZED_LEN + crypto.extra_payload_len() as usize;

        for index in 0..=(data.len() - header_len) {
            if index % 100_000 == 0 {
                tracing::trace!(chunk_index=%index, "trying ty find entry");
            }
            let mut slice = data[index..index + header_len].to_vec();
            let decrypted =
                match crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, &mut slice) {
                    Ok(d) => d,
                    Err(_) => {
                        continue;
                    }
                };

            match bincode::deserialize::<data::JournalEntryHeader>(&decrypted) {
                Ok(header) => return Some((header, index as u64)),
                Err(_) => continue,
            }
        }
        None
    } else {
        todo!()
    }
}

fn determine_file_size(f: &mut std::fs::File) -> Result<u64, LogFsError> {
    let metadata = f.metadata()?;

    #[cfg(unix)]
    {
        use std::os::unix::prelude::FileTypeExt;

        if metadata.file_type().is_block_device() {
            let start_offset = f.stream_position()?;
            // The regular metadata len for block devices is 0.
            // Accurate size can be found by seeking to the end.
            f.seek(SeekFrom::End(0))?;
            let size = f.stream_position()?;
            f.seek(SeekFrom::Start(start_offset))?;
            return Ok(size);
        }
    }

    if metadata.is_file() {
        Ok(metadata.len())
    } else {
        Err(LogFsError::new_internal(
            "Invalid path: expected a file or a block device",
        ))
    }
}

fn read_entry_header(
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
        &buffer
    };

    let header: data::JournalEntryHeader = bincode::deserialize(data)?;
    Ok(header)
}

fn read_entry_action(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    header: &data::JournalEntryHeader,
) -> Result<data::JournalAction, LogFsError> {
    let action_size = header.action_size as usize;
    buffer.resize(action_size, 0);

    // Read into buffer.
    reader.read_exact(buffer)?;

    // Decrypt.

    let action_data = if let Some(crypto) = &crypto {
        crypto.decrypt_data_ref(header.sequence_id.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
    } else {
        &buffer
    };

    let action: data::JournalAction = bincode::deserialize(action_data)?;
    Ok(action)
}

fn read_entry(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    sequence: SequenceId,
) -> Result<data::JournalEntry, LogFsError> {
    let header = read_entry_header(reader, buffer, crypto, sequence)?;
    let action = read_entry_action(reader, buffer, crypto, &header)?;

    Ok(data::JournalEntry { header, action })
}

fn restore_index<R: io::Read + io::Seek>(
    reader: &mut read::LogReader<R>,
    pointer: EntryPointer,
) -> Result<BTreeMap<Path, KeyPointer>, LogFsError> {
    let mut tree = BTreeMap::<Path, KeyPointer>::new();

    tracing::trace!(
        sequence=%pointer.sequence.as_u64(),
        offset=%pointer.offset,
        "restoring index"
    );

    let mut prev_pointer = Some(pointer);
    let mut buffer = Vec::new();

    while let Some(pointer) = prev_pointer {
        reader.seek_to_pointer(pointer)?;

        let (entry, data) = reader.next_entry(Some(&mut buffer))?;
        match entry.entry.action {
            data::JournalAction::IndexWrite(header) => {
                if let Some(_compression) = header.compression {
                    todo!("implement decompression");
                }

                let data: data::KeyIndex = bincode::deserialize(&data)?;
                prev_pointer = data.parent_entry;

                for item in data.keys {
                    // Note: ignore already existing keys, since they would
                    // already contain newer data from a previous entry.
                    tree.entry(item.key).or_insert_with(|| KeyPointer {
                        sequence_id: item.sequence_id.as_u64(),
                        file_offset: item.file_offset,
                        size: item.size,
                        chunk_size: item.chunk_size,
                    });
                }
            }
            _ => {
                return Err(LogFsError::new_internal(
                    "Invalid index pointer: log entry is not an index",
                ))?;
            }
        }
    }

    tracing::debug!(key_count=%tree.len(), "index restored");

    Ok(tree)
}

impl Journal2 {
    pub fn open(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError> {
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
        }

        if path.is_dir() {
            return Err(LogFsError::new_internal("Database path is a directory"));
        }

        let is_new = !path.exists();

        // TODO: use file locks on platforms that support it.
        let mut file = std::fs::OpenOptions::new()
            .create(config.allow_create)
            .read(true)
            .write(true)
            .open(&path)?;

        let meta = file.metadata()?;

        if let Some(offset) = config.offset {
            if is_new {
                return Err(LogFsError::new_internal(
                    "config specified byte offset, but the specified file does not exist",
                ));
            }
            if (meta.len() as u64) < offset {
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if meta.file_type().is_block_device() {
                        // allow
                    } else {
                        return Err(LogFsError::new_internal(
                            "config specified byte offset, but the specified file is smaller  then the offset",
                        ));
                    }
                }

                #[cfg(not(target_os = "linux"))]
                return Err(LogFsError::new_internal(
                    "config specified byte offset, but the specified file is smaller  then the offset",
                ));
            }

            file.seek(io::SeekFrom::Start(offset))?;
        }

        let base_offset = config.offset.unwrap_or_default();
        let file_len = file.metadata()?.len();

        let tainted = write::TaintedFlag::new();

        tracing::trace!(?path, "opening logfs");

        let writer = if config.raw_mode {
            let mut state = tree.write().unwrap();

            match Self::open_existing(file, &mut state, &crypto, base_offset, &tainted) {
                Ok(w) => w,
                Err(_err) => {
                    if config.allow_create {
                        let mut file = std::fs::OpenOptions::new()
                            .create(true)
                            .read(true)
                            .write(true)
                            .open(&path)?;

                        file.seek(SeekFrom::Start(base_offset))?;

                        LogWriter::create_new(crypto.clone(), tainted.clone(), file, base_offset)?
                    } else {
                        return Err(LogFsError::new_internal(
                            "Could not open database: file does not appear to be a log",
                        ));
                    }
                }
            }
        } else if is_new || file_len == base_offset {
            if config.allow_create {
                tracing::trace!(?path, "creating new log");
                LogWriter::create_new(
                    crypto.clone(),
                    tainted.clone(),
                    file,
                    config.offset.unwrap_or_default(),
                )?
            } else {
                return Err(LogFsError::new_internal(format!(
                    "No log found at {}",
                    config.path.display()
                )));
            }
        } else {
            tracing::trace!(?path, "opening existing log");
            let mut state = tree.write().unwrap();
            Self::open_existing(file, &mut state, &crypto, base_offset, &tainted)?
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
        mut file: std::fs::File,
        state: &mut crate::state::State,
        crypto: &Option<Arc<Crypto>>,
        base_offset: u64,
        tainted: &write::TaintedFlag,
    ) -> Result<LogWriter, LogFsError> {
        let meta = file.metadata()?;
        let file_size = meta.len();

        debug_assert_eq!(file.stream_position().unwrap(), base_offset);

        let mut reader =
            read::LogReader::new_start(file, base_offset, crypto.as_ref().map(|x| &**x));
        let superblock = reader.read_superblocks()?;

        // If an index entry is present, use it to restore the index.
        if let Some(index_pointer) = superblock.block.last_index_entry {
            match restore_index(&mut reader, index_pointer) {
                Ok(tree) => {
                    state.set_tree(tree);
                }
                Err(error) => {
                    #[cfg(test)]
                    panic!("could not restore index: {error:?}");

                    #[cfg(not(test))]
                    {
                        tracing::warn!(?error, "could not restore index - attempting full scan");

                        reader.rewind_to_first_entry()?;
                    }
                }
            }
        };

        while reader.next_sequence.as_u64() <= superblock.block.active_sequence {
            let (entry, _) = reader.next_entry(None)?;
            apply_entry(state, entry)?;
        }

        let file = reader.reader.into_inner();

        // Make sure file wasn't modified in the meantime.
        if file.metadata()?.len() != file_size {
            return Err(LogFsError::new_internal(
                "File was modified during bootstrap",
            ));
        }
        let writer = LogWriter::open(
            crypto.clone(),
            tainted.clone(),
            file,
            base_offset,
            superblock,
        )?;
        Ok(writer)
    }

    /* fn open_and_truncate_file(
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
    } */

    fn write_entry(
        &self,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        chunk_size: u32,
    ) -> Result<PersistedEntry, LogFsError> {
        let mut guard = self.state.writer.lock().unwrap();

        let res = loop {
            match &mut *guard {
                WriterState::Closed => break Err(LogFsError::new_internal("Log is closed")),
                WriterState::Available(Some(w)) => {
                    let entry = w.write_journal_entry(chunk_size, action, data, false)?;

                    break Ok(entry);
                }
                WriterState::Available(None) => {
                    guard = self
                        .state
                        .writer_condvar
                        .wait(guard)
                        .map_err(|_| LogFsError::Tainted)?;
                    continue;
                }
            }
        };

        self.state.writer_condvar.notify_one();

        res
    }

    fn write_index(
        &self,
        tree: &BTreeMap<String, KeyPointer>,
        _full: bool,
    ) -> Result<(), LogFsError> {
        // TODO: implement partial writes.

        let index = data::KeyIndex {
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
        };
        let data = bincode::serialize(&index)?;

        // TODO: compression

        let hash = data::Sha256Hash(sha2::Sha256::digest(&data).into());

        let action = data::JournalAction::IndexWrite(data::ActionIndexWrite {
            size: data.len() as u64,
            hash,
            compression: None,
        });

        let chunk_size = data.len();

        self.write_entry(action, Some(data), chunk_size as u32)?;

        Ok(())
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
            file_offset: entry.file_data_offset,
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
        let reader = read::KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        let (data, _file) = reader.read_all()?;
        Ok(data)
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<read::StdKeyReader, LogFsError> {
        // TODO: use a pool of reused file descriptors
        let f = std::fs::File::open(&self.path)?;
        let reader = read::KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        Ok(read::StdKeyReader::new(reader))
    }

    fn chunk_iter(&self, pointer: &KeyPointer) -> Result<read::KeyChunkIter, LogFsError> {
        // TODO: use a pool of reused file descriptors
        let f = std::fs::File::open(&self.path)?;
        let reader = read::KeyDataReader::new(self.crypto.clone(), pointer, f)?;
        Ok(read::KeyChunkIter::new(reader))
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
                    file_offset: entry.file_data_offset,
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

impl super::JournalStore for Journal2 {
    fn open(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError>
    where
        Self: Sized,
    {
        Journal2::open(path, tree, crypto, config)
    }

    fn repair(
        log_config: &LogConfig,
        crypto: Option<Arc<Crypto>>,
        repair_config: RepairConfig,
    ) -> Result<(), LogFsError>
    where
        Self: Sized,
    {
        repair::repair(log_config, crypto, repair_config)
    }

    fn write_insert(&self, path: crate::Path, data: Vec<u8>) -> Result<KeyPointer, LogFsError> {
        self.write_insert(path, data, self.default_chunk_size)
    }

    fn insert_writer(
        &self,
        path: crate::Path,
        tree: SharedTree,
        writer_lock: KeyLock,
    ) -> Result<write::KeyWriter, LogFsError> {
        let writer = self.state.acquire_borrowed_writer()?;
        let chunk = write::LogChunkWriter::new(
            tree,
            self.state.clone(),
            writer,
            self.default_chunk_size,
            path,
        )?;
        Ok(write::KeyWriter::new(chunk, Some(writer_lock)))
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

    fn reader(&self, pointer: &KeyPointer) -> Result<read::StdKeyReader, LogFsError> {
        Journal2::reader(&self, pointer)
    }

    fn read_chunks(&self, pointer: &KeyPointer) -> Result<read::KeyChunkIter, LogFsError> {
        Journal2::chunk_iter(&self, pointer)
    }

    fn size_log(&self) -> Result<u64, LogFsError> {
        let writer = self
            .state
            .writer
            .lock()
            .map_err(|_| LogFsError::new_internal("Could not retrieve log writer"))?;
        match &*writer {
            WriterState::Closed | WriterState::Available(None) => {
                Err(LogFsError::new_internal("Writer not available"))
            }
            WriterState::Available(Some(w)) => Ok(w.offset()),
        }
    }

    fn supberlock(&self) -> Result<Superblock, LogFsError> {
        let writer = self.state.acquire_borrowed_writer()?;
        Ok(writer.active_superblock().block.clone())
    }

    fn write_index(
        &self,
        tree: &BTreeMap<String, KeyPointer>,
        full: bool,
    ) -> Result<(), LogFsError> {
        self.write_index(tree, full)
    }
}
