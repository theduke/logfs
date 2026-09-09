//! Current journal implementation. Legacy decoding is delegated to `v2`.
mod format;
pub(super) mod index;
mod limits;
mod root;
use super::codec::*;
#[cfg(test)]
pub(crate) use format::V3_HEADER_SIZE;
use format::*;
use index::restore_index;
#[cfg(test)]
mod tests;
use super::v2::{find_entry_header_in_slice, read_entry};
use root::v3_entry_start;
pub(super) use root::{IndexedSuperBlock, RootFormat};
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
    KeyLock, LogConfig, LogFsError, LogOpenOptions,
    crypto::Crypto,
    state::{KeyPointer, SharedTree},
};

use self::write::LogWriter;

use super::RepairConfig;

pub(crate) use super::data;
pub use data::Superblock;

fn require_creatable_format(
    format_version: Option<data::LogFormatVersion>,
) -> Result<(), LogFsError> {
    if let Some(version) = format_version
        && version != data::LogFormatVersion::V3
    {
        return Err(LogFsError::new_internal(format!(
            "Cannot create log format {version:?}; only V3 creation is supported"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct PersistedEntry {
    entry: data::JournalEntry,
    /// The offset where the entry data starts.
    file_data_offset: data::Offset,
    entry_nonce: Option<[u8; 24]>,
    log_identity: Option<[u8; 16]>,
}

pub struct Journal2 {
    path: std::path::PathBuf,
    _tainted: write::TaintedFlag,
    crypto: Option<Arc<Crypto>>,
    v3_crypto: Option<Arc<crate::crypto::V3Crypto>>,
    state: Arc<State>,
    default_chunk_size: u32,
    readonly: bool,
    checkpoint_interval: u64,
    backing: Arc<read::BackingFile>,
    durable: Arc<std::sync::atomic::AtomicBool>,
    verify_reads: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
enum WriterState {
    // FIXME: clean up log writer tainting logic
    #[allow(dead_code)]
    Closed,
    Available(Option<Box<LogWriter>>),
}

struct State {
    /// The file used for writes.
    /// Only a single file descriptor is used for writes, which means concurrent
    /// writes are not possible.
    ///
    /// Seperate file descriptors are used for reading.
    writer: Mutex<WriterState>,
    writer_condvar: std::sync::Condvar,
    tainted: write::TaintedFlag,
}

impl State {
    fn return_writer(&self, writer: LogWriter) {
        *self
            .writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            WriterState::Available(Some(Box::new(writer)));
        self.writer_condvar.notify_all();
    }

    fn acquire_borrowed_writer(&self) -> Result<LogWriter, LogFsError> {
        if self.tainted.is_tainted() {
            return Err(LogFsError::Tainted);
        }
        let mut lock = self
            .writer
            .lock()
            .map_err(|_| LogFsError::new_internal("Could not acquire writer"))?;

        loop {
            match &mut *lock {
                WriterState::Available(slot) => match slot.take() {
                    Some(writer) => {
                        if self.tainted.is_tainted() {
                            *slot = Some(writer);
                            return Err(LogFsError::Tainted);
                        }
                        return Ok(*writer);
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

impl Journal2 {
    pub fn open(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError> {
        Self::open_with_region(path, tree, crypto, config, LogOpenOptions::default())
    }

    pub(crate) fn create_new_exclusive(
        path: std::path::PathBuf,
        _tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
        options: LogOpenOptions,
    ) -> Result<Self, LogFsError> {
        require_creatable_format(options.format_version)?;
        if config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        if config.default_chunk_size == 0 {
            return Err(LogFsError::new_internal(
                "default_chunk_size must be greater than zero",
            ));
        }
        if let Some(parent) = path.parent()
            && !parent.is_dir()
        {
            if config.allow_create {
                std::fs::create_dir_all(parent)?;
            } else {
                return Err(LogFsError::new_internal("Parent directory does not exist"));
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            LogFsError::new_internal(format!("Could not acquire exclusive log lock: {error}"))
        })?;
        if let Some(offset) = config.offset {
            file.set_len(offset)?;
            file.seek(io::SeekFrom::Start(offset))?;
        }
        let tainted = write::TaintedFlag::new();
        let durable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = LogWriter::create_new(
            crypto.clone(),
            tainted.clone(),
            file,
            config.offset.unwrap_or_default(),
            durable.clone(),
            options.region_len,
            options.randomize_region,
        )?;
        let backing = Arc::new(read::BackingFile::new(writer.backing_clone()?));
        let v3_crypto = writer.v3_crypto().map(Arc::new);
        Ok(Self {
            state: Arc::new(State {
                writer: std::sync::Mutex::new(WriterState::Available(Some(Box::new(writer)))),
                writer_condvar: std::sync::Condvar::new(),
                tainted: tainted.clone(),
            }),
            _tainted: tainted,
            crypto,
            v3_crypto,
            path,
            default_chunk_size: config.default_chunk_size,
            readonly: false,
            checkpoint_interval: config.full_index_write_interval,
            backing,
            durable,
            verify_reads: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub(crate) fn open_with_region(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
        options: LogOpenOptions,
    ) -> Result<Self, LogFsError> {
        if config.default_chunk_size == 0 {
            return Err(LogFsError::new_internal(
                "default_chunk_size must be greater than zero",
            ));
        }
        if let Some(parent) = path.parent()
            && !parent.is_dir()
        {
            if config.allow_create {
                std::fs::create_dir_all(parent)?;
            } else {
                return Err(LogFsError::new_internal("Parent directory does not exist"));
            }
        }

        let mut existing_options = std::fs::OpenOptions::new();
        existing_options.read(true).write(!config.readonly);
        let existing_file = match existing_options.open(&path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };

        let tainted = write::TaintedFlag::new();
        let durable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = if let Some(mut file) = existing_file {
            if config.readonly {
                fs2::FileExt::try_lock_shared(&file).map_err(|error| {
                    LogFsError::new_internal(format!("Could not acquire shared log lock: {error}"))
                })?;
            } else {
                fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
                    LogFsError::new_internal(format!(
                        "Could not acquire exclusive log lock: {error}"
                    ))
                })?;
            }

            let meta = file.metadata()?;
            if meta.is_dir() {
                return Err(LogFsError::new_internal("Database path is a directory"));
            }
            let is_block_device = {
                #[cfg(target_family = "unix")]
                {
                    use std::os::unix::fs::FileTypeExt;
                    meta.file_type().is_block_device()
                }
                #[cfg(not(target_family = "unix"))]
                {
                    false
                }
            };

            // All creation/format decisions use metadata from the locked
            // descriptor, not a pathname lookup that can become stale.
            let locked_len = file.metadata()?.len();
            if let Some(offset) = config.offset {
                if locked_len < offset && !is_block_device {
                    return Err(LogFsError::new_internal(
                        "config specified byte offset, but the specified file is smaller  then the offset",
                    ));
                }

                file.seek(io::SeekFrom::Start(offset))?;
            }

            if locked_len == config.offset.unwrap_or_default() && !is_block_device {
                // File is exactly at the offset - treat as new file.
                if !config.allow_create {
                    return Err(LogFsError::new_internal(
                        "File is empty at the specified offset - but allow_create is false",
                    ));
                }
                require_creatable_format(options.format_version)?;

                LogWriter::create_new(
                    crypto.clone(),
                    tainted.clone(),
                    file,
                    config.offset.unwrap_or_default(),
                    durable.clone(),
                    options.region_len,
                    options.randomize_region,
                )?
            } else {
                if options.randomize_region {
                    return Err(LogFsError::new_internal(
                        "Randomized preallocation is only valid while initializing an empty region",
                    ));
                }
                let mut state = tree.write().unwrap();

                Self::open_existing(
                    file,
                    &mut state,
                    &crypto,
                    config.offset.unwrap_or_default(),
                    &tainted,
                    durable.clone(),
                    options,
                )?
            }
        } else {
            if !config.allow_create || config.readonly {
                return Err(if config.readonly {
                    LogFsError::ReadOnly
                } else {
                    LogFsError::new_internal("Database does not exist and creation is disabled")
                });
            }
            require_creatable_format(options.format_version)?;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)?;
            fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
                LogFsError::new_internal(format!("Could not acquire exclusive log lock: {error}"))
            })?;
            if let Some(offset) = config.offset {
                file.set_len(offset)?;
                file.seek(io::SeekFrom::Start(offset))?;
            }

            LogWriter::create_new(
                crypto.clone(),
                tainted.clone(),
                file,
                config.offset.unwrap_or_default(),
                durable.clone(),
                options.region_len,
                options.randomize_region,
            )?
        };
        let readonly = config.readonly || writer.is_legacy_v2();
        // Clone the already-opened object and use positional reads. This stays
        // attached to the same object if its pathname is renamed or replaced,
        // without sharing a logical seek cursor with readers or the writer.
        let backing = Arc::new(read::BackingFile::new(writer.backing_clone()?));
        let v3_crypto = writer.v3_crypto().map(Arc::new);

        let j = Self {
            state: Arc::new(State {
                writer: std::sync::Mutex::new(WriterState::Available(Some(Box::new(writer)))),
                writer_condvar: std::sync::Condvar::new(),
                tainted: tainted.clone(),
            }),
            _tainted: tainted,
            crypto,
            v3_crypto,
            path,
            default_chunk_size: config.default_chunk_size,
            readonly,
            checkpoint_interval: config.full_index_write_interval,
            backing,
            durable,
            verify_reads: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        Ok(j)
    }

    fn open_existing(
        mut file: std::fs::File,
        state: &mut crate::state::State,
        crypto: &Option<Arc<Crypto>>,
        base_offset: u64,
        tainted: &write::TaintedFlag,
        durable: Arc<std::sync::atomic::AtomicBool>,
        options: LogOpenOptions,
    ) -> Result<LogWriter, LogFsError> {
        let meta = file.metadata()?;
        let file_size = meta.len();

        debug_assert_eq!(file.stream_position().unwrap(), base_offset);

        let mut reader =
            read::LogReader::new_start(file, base_offset, crypto.as_ref().map(|x| &**x));
        let superblock = reader.read_superblocks()?;
        if let Some(expected) = options.format_version
            && expected != superblock.block.format_version
        {
            return Err(LogFsError::new_internal(format!(
                "Log format mismatch: requested {expected:?}, found {:?}",
                superblock.block.format_version
            )));
        }
        if options
            .region_len
            .is_some_and(|length| superblock.block.tail_offset > length)
        {
            return Err(LogFsError::new_internal(
                "Committed log tail exceeds configured region",
            ));
        }

        // If an index entry is present, use it to restore the index.
        let checkpoint_started = std::time::Instant::now();
        let mut checkpoint_loaded = false;
        if let Some(index_pointer) = superblock.block.last_index_entry {
            match restore_index(&mut reader, index_pointer) {
                Ok(tree) => {
                    state.set_tree(tree);
                    // Tail replay below records each committed mutation once.
                    state.write_counter = 0;
                    checkpoint_loaded = true;
                }
                Err(error) => {
                    tracing::warn!(?error, "could not restore index - attempting full scan");
                    *state = crate::state::State::new();
                    reader.rewind_to_first_entry()?;
                }
            }
        };

        let checkpoint_load_elapsed = checkpoint_started.elapsed();
        let tail_started = std::time::Instant::now();
        let mut replayed_entries = 0u64;
        while reader.next_sequence.as_u64() <= superblock.block.active_sequence {
            let (entry, _) = reader.next_entry(None)?;
            apply_entry(state, entry)?;
            replayed_entries += 1;
        }
        if !reader.is_at_committed_end() {
            return Err(LogFsError::new_internal(
                "Committed sequence boundary does not match superblock tail",
            ));
        }
        tracing::debug!(
            checkpoint_loaded,
            checkpoint_load_ms = checkpoint_load_elapsed.as_millis(),
            replayed_entries,
            tail_replay_ms = tail_started.elapsed().as_millis(),
            "log bootstrap complete"
        );

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
            durable,
            options.region_len,
        )?;
        Ok(writer)
    }

    fn write_entry(
        &self,
        action: data::JournalAction,
        data: Option<Vec<u8>>,
        chunk_size: u32,
    ) -> Result<PersistedEntry, LogFsError> {
        if self.readonly {
            return Err(LogFsError::ReadOnly);
        }
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
        if self.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let mut writer = self.state.acquire_borrowed_writer()?;
        let result = writer.write_full_index(tree);
        self.state.return_writer(writer);
        result
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
            hash: Some(hash.into()),
            entry_nonce: entry.entry_nonce,
            log_identity: entry.log_identity,
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

    pub fn write_batch(&self, batch: crate::Batch) -> Result<(), LogFsError> {
        let renames = batch
            .renames
            .into_iter()
            .map(|rename| data::KeyRename {
                old_key: rename.old_key,
                new_key: rename.new_key,
            })
            .collect();
        let action = data::JournalAction::Batch(data::ActionBatch {
            renames,
            deleted_keys: batch.deleted_keys,
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
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
            self.v3_crypto.clone(),
            pointer,
            self.backing.clone(),
            self.verify_reads.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        reader.read_all()
    }

    pub(crate) fn set_verify_reads(&self, verify: bool) {
        self.verify_reads
            .store(verify, std::sync::atomic::Ordering::Relaxed);
    }

    fn verify_data(&self, pointer: &KeyPointer) -> Result<bool, LogFsError> {
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
            self.v3_crypto.clone(),
            pointer,
            self.backing.clone(),
            true,
        )?;
        reader.verify_to_end()?;
        Ok(pointer.hash.is_some())
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<read::StdKeyReader, LogFsError> {
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
            self.v3_crypto.clone(),
            pointer,
            self.backing.clone(),
            self.verify_reads.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        Ok(read::StdKeyReader::new(reader))
    }

    fn chunk_iter(&self, pointer: &KeyPointer) -> Result<read::KeyChunkIter, LogFsError> {
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
            self.v3_crypto.clone(),
            pointer,
            self.backing.clone(),
            self.verify_reads.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        Ok(read::KeyChunkIter::new(reader))
    }

    fn repair_insert_writer(
        &self,
        path: data::KeyPath,
        tree: SharedTree,
    ) -> Result<write::KeyWriter, LogFsError> {
        let writer = self.state.acquire_borrowed_writer()?;
        let chunk = match write::LogChunkWriter::new(
            tree,
            self.state.clone(),
            writer,
            self.default_chunk_size,
            path,
            self.checkpoint_interval,
        ) {
            Ok(chunk) => chunk,
            Err(error_and_writer) => {
                let (error, writer) = *error_and_writer;
                self.state.return_writer(writer);
                return Err(error);
            }
        };
        Ok(write::KeyWriter::new(chunk, None))
    }

    /// Get a reference to the journal's path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

fn apply_entry(state: &mut crate::state::State, entry: PersistedEntry) -> Result<(), LogFsError> {
    let is_mutation = !entry.entry.action.is_index_write();
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
                    hash: Some(key.hash.0),
                    entry_nonce: entry.entry_nonce,
                    log_identity: entry.log_identity,
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
        data::JournalAction::IndexWriteV3(_) => {}
        data::JournalAction::Batch(batch) => {
            for deleted_key in &batch.deleted_keys {
                if state.remove_key(deleted_key).is_none() {
                    tracing::trace!("Log entry tried to delete a key that does not exist");
                }
            }

            for rename in batch.renames {
                if let Err(_err) = state.rename_key(&rename.old_key, rename.new_key) {
                    tracing::trace!("Log entry tried to rename a key that does not exist");
                }
            }
        }
    }

    if is_mutation {
        state.record_mutation();
    }

    Ok(())
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
        if self.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let writer = self.state.acquire_borrowed_writer()?;
        let chunk = match write::LogChunkWriter::new(
            tree,
            self.state.clone(),
            writer,
            self.default_chunk_size,
            path,
            self.checkpoint_interval,
        ) {
            Ok(chunk) => chunk,
            Err(error_and_writer) => {
                let (error, writer) = *error_and_writer;
                self.state.return_writer(writer);
                return Err(error);
            }
        };
        Ok(write::KeyWriter::new(chunk, Some(writer_lock)))
    }

    fn write_rename(&self, old_path: crate::Path, new_path: crate::Path) -> Result<(), LogFsError> {
        self.write_rename(old_path, new_path)
    }

    fn write_remove(&self, paths: Vec<crate::Path>) -> Result<(), LogFsError> {
        self.write_remove(paths)
    }

    fn write_batch(&self, batch: crate::Batch) -> Result<(), LogFsError> {
        self.write_batch(batch)
    }

    fn read_data(&self, pointer: &KeyPointer) -> Result<Vec<u8>, LogFsError> {
        self.read_data(pointer)
    }

    fn verify_data(&self, pointer: &KeyPointer) -> Result<bool, LogFsError> {
        self.verify_data(pointer)
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<read::StdKeyReader, LogFsError> {
        Journal2::reader(self, pointer)
    }

    fn read_chunks(&self, pointer: &KeyPointer) -> Result<read::KeyChunkIter, LogFsError> {
        Journal2::chunk_iter(self, pointer)
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
        let block = writer.active_superblock().block.clone();
        self.state.return_writer(writer);
        Ok(block)
    }

    fn write_index(
        &self,
        tree: &BTreeMap<String, KeyPointer>,
        full: bool,
    ) -> Result<(), LogFsError> {
        self.write_index(tree, full)
    }

    fn flush(&self) -> Result<(), LogFsError> {
        let mut writer = self.state.acquire_borrowed_writer()?;
        let result = writer.flush();
        self.state.return_writer(writer);
        result
    }

    fn sync(&self) -> Result<(), LogFsError> {
        let mut writer = self.state.acquire_borrowed_writer()?;
        let result = writer.sync();
        self.state.return_writer(writer);
        result
    }

    fn set_durable(&self, durable: bool) -> Result<(), LogFsError> {
        self.durable
            .store(durable, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn checkpoint_payload_offset(
    path: &std::path::Path,
    crypto: Option<&Crypto>,
    base_offset: u64,
) -> Result<u64, LogFsError> {
    let file = std::fs::File::open(path)?;
    let mut reader = read::LogReader::new_start(file, base_offset, crypto);
    let root = reader.read_superblocks()?;
    let pointer = root
        .block
        .last_index_entry
        .ok_or_else(|| LogFsError::new_internal("test log has no checkpoint"))?;
    reader.seek_to_pointer(pointer)?;
    let (entry, _) = reader.next_entry(None)?;
    Ok(entry.file_data_offset)
}
