mod error;
pub use self::error::{LogFsError, SerializationError};
mod encoding;

mod journal;
mod state;
#[doc(hidden)]
pub use journal::RepairConfig as JournalRepairConfig;
use journal::SequenceId;
pub use journal::v2::{
    read::{KeyChunkIter, StdKeyReader},
    write::KeyWriter,
};
pub use journal::{Journal2, JournalStore, LogFormatVersion, Superblock};

mod crypto;
#[doc(hidden)]
pub use crypto::Crypto;
pub use crypto::{CryptoConfig, CryptoProfile};
#[doc(hidden)]
pub use state::{KeyPointer, SharedTree};

use std::{
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, RwLock},
};

type Path = String;

fn sync_parent_directory(path: &std::path::Path) -> Result<(), LogFsError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub struct ConfigBuilder {
    config: LogConfig,
}

/// Additive options for storage behavior that cannot be added to [`LogConfig`]
/// without breaking existing struct-literal users.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogOpenOptions {
    /// Maximum bytes occupied by the log starting at `LogConfig::offset`.
    /// This is especially useful for a bounded region inside a raw device.
    pub region_len: Option<u64>,
    /// Use ordered, synchronized root publication for each mutation.
    pub durable: bool,
    /// On initialization, random-fill the complete owned region. This hides
    /// unwritten capacity but requires `region_len` and performs a full-region
    /// write. It is never applied while opening an existing log.
    pub randomize_region: bool,
    /// Require an existing log to use this on-disk format. New logs currently
    /// support only [`LogFormatVersion::V3`].
    pub format_version: Option<LogFormatVersion>,
}

/// Controls optional whole-value hash checking during routine reads. Hashes are
/// always generated and stored for new values; structural validation and AEAD
/// authentication are mandatory in both modes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReadIntegrity {
    #[default]
    SkipHash,
    VerifyHash,
}

const DEFAULT_CHUNK_SIZE: u32 = 4_000_000;

impl ConfigBuilder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            config: LogConfig {
                path: path.into(),
                offset: None,
                allow_create: false,
                raw_mode: false,
                crypto: None,
                default_chunk_size: DEFAULT_CHUNK_SIZE,
                // TODO: determine good defaults for these values!
                partial_index_write_interval: 100,
                full_index_write_interval: 1000,
                readonly: false,
            },
        }
    }

    pub fn raw_mode(mut self) -> Self {
        self.config.raw_mode = true;
        self
    }

    pub fn offset(mut self, offset: Option<u64>) -> Self {
        self.config.offset = offset;
        self
    }

    pub fn default_chunk_size(mut self, size: u32) -> Self {
        self.config.default_chunk_size = size;
        self
    }

    pub fn allow_create(mut self) -> Self {
        self.config.allow_create = true;
        self
    }

    pub fn crypto(mut self, crypto: CryptoConfig) -> Self {
        self.config.crypto = Some(crypto);
        self
    }

    pub fn full_index_write_interval(mut self, interval: u64) -> Self {
        self.config.full_index_write_interval = interval;
        self
    }

    pub fn readonly(mut self, readonly: bool) -> Self {
        self.config.readonly = readonly;
        self
    }

    pub fn build(self) -> LogConfig {
        self.config
    }

    pub fn open(self) -> Result<LogFs, LogFsError> {
        LogFs::open(self.config)
    }
}

#[derive(Clone, Debug)]
pub struct LogConfig {
    pub path: PathBuf,
    pub raw_mode: bool,
    /// Optional file offset where the DB should start.
    pub offset: Option<u64>,
    pub allow_create: bool,
    pub crypto: Option<crypto::CryptoConfig>,
    /// Data is chunked into separate slices, which allows incrementally reading
    /// large keys.
    /// This setting specifies the size of chunks in bytes.
    ///
    /// Note that keys can also be created with a custom chunk size.
    pub default_chunk_size: u32,

    /// Determines after how many journal entries a new partial index snapshot
    /// is written.
    pub partial_index_write_interval: u64,
    /// Determines after how many journal entries a new full index snapshot is
    /// written.
    pub full_index_write_interval: u64,
    pub readonly: bool,
}

pub struct RepairConfig {
    pub dry_run: bool,
    pub start_sequence: Option<u64>,
    /// The path to which a recovered log should be written.
    pub recovery_path: Option<PathBuf>,
    pub skip_bytes: Option<u64>,
}

pub struct LogFs<J = journal::Journal2> {
    inner: Arc<Inner<J>>,
    path: PathBuf,
}

impl Clone for LogFs {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            path: self.path.clone(),
        }
    }
}

struct Inner<J> {
    config: LogConfig,
    state: Arc<RwLock<state::State>>,
    locks: Arc<Locks>,
    journal: J,
}

struct Locks {
    key_lock: Mutex<bool>,
    key_lock_condvar: Condvar,
}

#[derive(Clone, Debug)]
pub struct KeyMeta {
    pub size: u64,
    pub chunk_size: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrubReport {
    pub keys_verified: u64,
    pub logical_bytes_verified: u64,
    /// Legacy checkpoint-restored plaintext values whose historical format did
    /// not retain a whole-value hash.
    pub keys_unverifiable: u64,
    pub logical_bytes_unverifiable: u64,
}

pub struct KeyLock(Arc<Locks>);

impl Drop for KeyLock {
    fn drop(&mut self) {
        let mut flag = self.0.key_lock.lock().unwrap();
        *flag = false;
        self.0.key_lock_condvar.notify_all();
    }
}

type DataOffset = u64;

impl<J: JournalStore> LogFs<J> {
    // TODO: add open() without key and open_encrypted() with key.
    pub fn open(mut config: LogConfig) -> Result<Self, LogFsError> {
        tracing::debug!(?config, "opening log");
        let crypto = config
            .crypto
            .take()
            .map(|c| Arc::new(crypto::Crypto::new(c)));
        let state = Arc::new(RwLock::new(state::State::new()));
        let path = config.path.clone();
        let journal = J::open(path.clone(), state.clone(), crypto, &config)?;

        tracing::info!(?config, "log opened");

        Ok(Self {
            path,
            inner: Arc::new(Inner {
                state,
                config,
                journal,
                locks: Arc::new(Locks {
                    key_lock: Mutex::new(false),
                    key_lock_condvar: Condvar::new(),
                }),
            }),
        })
    }

    /// Open with ordered durable commits. Each successful mutation syncs its
    /// records before publishing and syncing the root that acknowledges it.
    /// The existing `open` method retains buffered compatibility semantics.
    pub fn open_durable(config: LogConfig) -> Result<Self, LogFsError> {
        let log = Self::open(config)?;
        log.inner.journal.set_durable(true)?;
        log.inner.journal.sync()?;
        sync_parent_directory(&log.path)?;
        Ok(log)
    }

    pub fn superblock(&self) -> Result<Superblock, LogFsError> {
        self.inner.journal.supberlock()
    }

    pub fn repair(mut config: LogConfig, repair_config: RepairConfig) -> Result<(), LogFsError> {
        if repair_config.start_sequence == Some(0) {
            return Err(LogFsError::new_internal(
                "Repair start_sequence must be greater than zero",
            ));
        }
        let crypto = config
            .crypto
            .take()
            .map(|c| Arc::new(crypto::Crypto::new(c)));
        J::repair(
            &config,
            crypto.clone(),
            journal::RepairConfig {
                dry_run: repair_config.dry_run,
                start_sequence: repair_config.start_sequence.map(SequenceId::from_u64),
                recovery_path: repair_config.recovery_path,
                skip_bytes: repair_config.skip_bytes,
            },
        )?;

        Ok(())
    }

    /// Get the file system path.
    pub fn path(&self) -> std::path::PathBuf {
        self.path.clone()
    }

    /// Returns the approximate amount of bytes that could be saved when
    /// re-writing the log.
    ///
    /// Returns [`None`] if no estimate is available.
    /// This is the case if the log was restored from an index without a full
    /// scan.
    // TODO: if estimate is not available, do a full scan to determine estimate.
    pub fn redundant_data_estimate(&self) -> Option<u128> {
        self.inner
            .state
            .read()
            .unwrap()
            .redundant_data_bytes_estimate()
    }

    pub fn get_meta(&self, path: impl AsRef<str>) -> Result<Option<KeyMeta>, LogFsError> {
        match self.inner.state.read().unwrap().get_key(path.as_ref()) {
            Some(pointer) => Ok(Some(KeyMeta {
                size: pointer.size,
                chunk_size: pointer.chunk_size,
            })),
            None => Ok(None),
        }
    }

    /// Get a key.
    pub fn get(&self, path: impl AsRef<str>) -> Result<Option<Vec<u8>>, LogFsError> {
        let pointer = match self
            .inner
            .state
            .read()
            .unwrap()
            .get_key(path.as_ref())
            .cloned()
        {
            Some(pointer) => pointer,
            None => {
                return Ok(None);
            }
        };
        let data = self.inner.journal.read_data(&pointer)?;
        Ok(Some(data))
    }

    pub fn get_reader(&self, path: impl AsRef<str>) -> Result<StdKeyReader, LogFsError> {
        let path = path.as_ref();

        let pointer = match self.inner.state.read().unwrap().get_key(path).cloned() {
            Some(pointer) => pointer,
            None => return Err(LogFsError::NotFound { path: path.into() }),
        };
        let reader = self.inner.journal.reader(&pointer)?;
        Ok(reader)
    }

    pub fn get_chunks(&self, path: impl AsRef<str>) -> Result<KeyChunkIter, LogFsError> {
        let path = path.as_ref();

        let pointer = match self.inner.state.read().unwrap().get_key(path).cloned() {
            Some(pointer) => pointer,
            None => return Err(LogFsError::NotFound { path: path.into() }),
        };
        let reader = self.inner.journal.read_chunks(&pointer)?;
        Ok(reader)
    }

    /// Get all paths in the given range.
    pub fn paths_range<R>(&self, range: R) -> Result<Vec<Path>, LogFsError>
    where
        R: std::ops::RangeBounds<String>,
    {
        Ok(self.inner.state.read().unwrap().paths_range(range))
    }

    /// Get all paths with a given prefix.
    pub fn paths_offset(&self, offset: usize, max: usize) -> Result<Vec<Path>, LogFsError> {
        Ok(self.inner.state.read().unwrap().paths_offset(offset, max))
    }

    /// Get all paths with a given prefix.
    pub fn paths_prefix(&self, prefix: &str) -> Result<Vec<Path>, LogFsError> {
        Ok(self.inner.state.read().unwrap().paths_prefix(prefix))
    }

    fn acquire_key_lock(&self) -> KeyLock {
        let mut flag = self.inner.locks.key_lock.lock().unwrap();
        while *flag {
            flag = self.inner.locks.key_lock_condvar.wait(flag).unwrap();
        }
        *flag = true;
        KeyLock(self.inner.locks.clone())
    }

    fn write_index_if_required(&self, state: &mut state::State) -> Result<(), LogFsError> {
        // TODO: support partial index writes!

        let interval = self.inner.config.full_index_write_interval;
        if interval != 0 && state.write_counter >= interval {
            self.inner.journal.write_index(&state.tree, true)?;
            state.write_counter = 0;
        }

        Ok(())
    }

    /// Insert a key.
    pub fn insert(&self, path: impl Into<String>, data: Vec<u8>) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let path = path.into();
        let size = data.len();
        tracing::trace!(?path, size, "inserting key");
        let _lock = self.acquire_key_lock();

        let pointer = self.inner.journal.write_insert(path.clone(), data)?;

        let mut state = self.inner.state.write().unwrap();
        state.add_key(path.clone(), pointer);
        state.record_mutation();

        if let Err(error) = self.write_index_if_required(&mut state) {
            // The user mutation was already committed and visible. Returning
            // the checkpoint error would invite an unsafe retry.
            tracing::error!(?error, "automatic checkpoint failed after committed insert");
        }

        tracing::trace!(?path, size, "key inserted");

        Ok(())
    }

    pub fn insert_writer(
        &self,
        path: impl Into<String>,
    ) -> Result<journal::v3::write::KeyWriter, LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let lock = self.acquire_key_lock();
        self.inner
            .journal
            .insert_writer(path.into(), self.inner.state.clone(), lock)
    }

    /// Rename a key.
    pub fn rename(
        &self,
        old_key: impl Into<String>,
        new_key: impl Into<String>,
    ) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let old_key = old_key.into();
        let new_key = new_key.into();

        let _lock = self.acquire_key_lock();

        // Ensure key exists.
        if self.inner.state.read().unwrap().get_key(&old_key).is_none() {
            return Err(LogFsError::NotFound {
                path: old_key.to_string(),
            });
        }

        self.inner
            .journal
            .write_rename(old_key.clone(), new_key.clone())?;

        let mut state = self.inner.state.write().unwrap();
        // NOTE: unwrap can't fail, since key existence was checked above.
        state.rename_key(&old_key, new_key).unwrap();
        state.record_mutation();
        if let Err(error) = self.write_index_if_required(&mut state) {
            tracing::error!(?error, "automatic checkpoint failed after committed rename");
        }

        Ok(())
    }

    /// Remove a key.
    pub fn remove(&self, path: impl AsRef<str>) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let path = path.as_ref();

        let _lock = self.acquire_key_lock();

        let exists = self.inner.state.read().unwrap().get_key(path).is_some();
        if exists {
            self.inner.journal.write_remove(vec![path.to_string()])?;

            let mut state = self.inner.state.write().unwrap();
            state.remove_key(path);
            state.record_mutation();
            if let Err(error) = self.write_index_if_required(&mut state) {
                tracing::error!(?error, "automatic checkpoint failed after committed remove");
            }
        }

        Ok(())
    }

    /// Remove a whole key prefix.
    pub fn remove_prefix(&self, prefix: impl AsRef<str>) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let prefix = prefix.as_ref();
        let _lock = self.acquire_key_lock();
        let paths = {
            let state = self.inner.state.read().unwrap();
            state.paths_prefix(prefix)
        };

        tracing::trace!(%prefix, key_count=%paths.len(), "deleting keys with prefix");

        if paths.is_empty() {
            return Ok(());
        }

        self.inner.journal.write_remove(paths.clone())?;

        let mut state = self.inner.state.write().unwrap();
        for path in &paths {
            state.remove_key(path);
        }
        state.record_mutation();

        if let Err(error) = self.write_index_if_required(&mut state) {
            tracing::error!(
                ?error,
                "automatic checkpoint failed after committed prefix removal"
            );
        }

        Ok(())
    }

    pub fn batch(&self, batch: Batch) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }

        let _lock = self.acquire_key_lock();
        let state = self.inner.state.read().unwrap();

        // Validate.

        let mut touched = std::collections::BTreeMap::<String, bool>::new();
        let present = |key: &str, overlay: &std::collections::BTreeMap<String, bool>| {
            overlay
                .get(key)
                .copied()
                .unwrap_or_else(|| state.get_key(key).is_some())
        };
        for deleted_key in &batch.deleted_keys {
            if !present(deleted_key, &touched) {
                return Err(LogFsError::NotFound {
                    path: deleted_key.clone(),
                });
            }
            touched.insert(deleted_key.clone(), false);
        }

        for rename in &batch.renames {
            if !present(&rename.old_key, &touched) {
                return Err(LogFsError::NotFound {
                    path: rename.old_key.clone(),
                });
            }
            touched.insert(rename.old_key.clone(), false);
            touched.insert(rename.new_key.clone(), true);
        }
        drop(state);

        self.inner.journal.write_batch(batch.clone())?;

        let mut state = self.inner.state.write().unwrap();

        for key in &batch.deleted_keys {
            state.remove_key(key);
        }
        for rename in batch.renames {
            // Unwrap is fine since key existence was validated above.
            state.rename_key(&rename.old_key, rename.new_key).unwrap();
        }
        state.record_mutation();

        if let Err(error) = self.write_index_if_required(&mut state) {
            tracing::error!(?error, "automatic checkpoint failed after committed batch");
        }

        Ok(())
    }

    pub fn size_data(&self) -> Result<u64, LogFsError> {
        let size = self
            .inner
            .state
            .read()
            .unwrap()
            .tree
            .values()
            .map(|v| v.size)
            .sum();
        Ok(size)
    }

    pub fn size_log(&self) -> Result<u64, LogFsError> {
        self.inner.journal.size_log()
    }

    /// Write a full checkpoint immediately. An interval of zero disables only
    /// automatic checkpoints; explicit checkpoints remain available.
    pub fn checkpoint(&self) -> Result<(), LogFsError> {
        if self.inner.config.readonly {
            return Err(LogFsError::ReadOnly);
        }
        let _lock = self.acquire_key_lock();
        let mut state = self.inner.state.write().unwrap();
        self.inner.journal.write_index(&state.tree, true)?;
        state.write_counter = 0;
        Ok(())
    }

    /// Flush buffered journal bytes. This makes them visible to the operating
    /// system but is not a power-loss durability guarantee.
    pub fn flush(&self) -> Result<(), LogFsError> {
        self.inner.journal.flush()
    }

    /// Synchronize all accepted journal and root writes to the backing object.
    /// A synchronization error leaves durability indeterminate.
    pub fn sync(&self) -> Result<(), LogFsError> {
        self.inner.journal.sync()
    }

    /// Read and authenticate/hash every live value. Legacy v2 checkpoints did
    /// not retain plaintext value hashes; encrypted values are still
    /// authenticated chunk-by-chunk, while full plaintext hash coverage is
    /// available after replay and in all v3 checkpoints.
    pub fn scrub(&self) -> Result<ScrubReport, LogFsError> {
        let pointers: Vec<_> = self
            .inner
            .state
            .read()
            .unwrap()
            .tree
            .values()
            .cloned()
            .collect();
        let mut report = ScrubReport {
            keys_verified: 0,
            logical_bytes_verified: 0,
            keys_unverifiable: 0,
            logical_bytes_unverifiable: 0,
        };
        for pointer in pointers {
            if self.inner.journal.verify_data(&pointer)? {
                report.keys_verified += 1;
                report.logical_bytes_verified = report
                    .logical_bytes_verified
                    .checked_add(pointer.size)
                    .ok_or_else(|| LogFsError::new_internal("Scrub byte count overflow"))?;
            } else {
                report.keys_unverifiable += 1;
                report.logical_bytes_unverifiable = report
                    .logical_bytes_unverifiable
                    .checked_add(pointer.size)
                    .ok_or_else(|| LogFsError::new_internal("Scrub byte count overflow"))?;
            }
        }
        Ok(report)
    }

    /// Bytes occupied by this log region, excluding any configured backing
    /// prefix before `offset`. This is distinct from logical payload size.
    pub fn occupied_log_bytes(&self) -> Result<u64, LogFsError> {
        self.size_log()?
            .checked_sub(self.inner.config.offset.unwrap_or_default())
            .ok_or_else(|| LogFsError::new_internal("Log size is before configured offset"))
    }
}

impl LogFs<Journal2> {
    /// Atomically create a new log, failing if the destination path already
    /// exists. Opening an existing path is a separate operation, so an
    /// authentication failure can never trigger formatting.
    pub fn create_new(config: LogConfig) -> Result<Self, LogFsError> {
        Self::create_new_with_options(config, LogOpenOptions::default())
    }

    /// Atomically create a new durable log, failing if the destination path
    /// already exists.
    pub fn create_new_durable(config: LogConfig) -> Result<Self, LogFsError> {
        Self::create_new_with_options(
            config,
            LogOpenOptions {
                durable: true,
                ..LogOpenOptions::default()
            },
        )
    }

    /// Atomically create a new log with bounded-region and durability options.
    pub fn create_new_with_options(
        mut config: LogConfig,
        options: LogOpenOptions,
    ) -> Result<Self, LogFsError> {
        tracing::debug!(?config, "creating log exclusively");
        let crypto = config
            .crypto
            .take()
            .map(|value| Arc::new(crypto::Crypto::new(value)));
        let state = Arc::new(RwLock::new(state::State::new()));
        let path = config.path.clone();
        let journal =
            Journal2::create_new_exclusive(path.clone(), state.clone(), crypto, &config, options)?;
        journal.set_durable(options.durable)?;
        if options.durable {
            journal.sync()?;
            sync_parent_directory(&path)?;
        }
        Ok(Self {
            path,
            inner: Arc::new(Inner {
                state,
                config,
                journal,
                locks: Arc::new(Locks {
                    key_lock: Mutex::new(false),
                    key_lock_condvar: Condvar::new(),
                }),
            }),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Rename {
    pub old_key: String,
    pub new_key: String,
}

#[derive(Clone, Debug, Default)]
pub struct Batch {
    pub renames: Vec<Rename>,
    pub deleted_keys: Vec<String>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn and_rename(mut self, old_key: impl Into<String>, new_key: impl Into<String>) -> Self {
        self.renames.push(Rename {
            old_key: old_key.into(),
            new_key: new_key.into(),
        });
        self
    }

    pub fn and_remove(mut self, keys: Vec<String>) -> Self {
        self.deleted_keys.extend(keys);
        self
    }
}

impl LogFs<Journal2> {
    pub fn open_with_options(
        mut config: LogConfig,
        options: LogOpenOptions,
    ) -> Result<Self, LogFsError> {
        tracing::debug!(?config, ?options, "opening log with storage options");
        let crypto = config
            .crypto
            .take()
            .map(|value| Arc::new(crypto::Crypto::new(value)));
        let state = Arc::new(RwLock::new(state::State::new()));
        let path = config.path.clone();
        let journal =
            Journal2::open_with_region(path.clone(), state.clone(), crypto, &config, options)?;
        journal.set_durable(options.durable)?;
        if options.durable {
            journal.sync()?;
            sync_parent_directory(&path)?;
        }
        Ok(Self {
            path,
            inner: Arc::new(Inner {
                state,
                config,
                journal,
                locks: Arc::new(Locks {
                    key_lock: Mutex::new(false),
                    key_lock_condvar: Condvar::new(),
                }),
            }),
        })
    }

    /// Open with the requested routine-read integrity policy. The default
    /// [`LogFs::open`] policy skips whole-value hashing for performance.
    pub fn open_with_integrity(
        config: LogConfig,
        integrity: ReadIntegrity,
    ) -> Result<Self, LogFsError> {
        let log = Self::open_with_options(config, LogOpenOptions::default())?;
        log.set_read_integrity(integrity);
        Ok(log)
    }

    pub fn set_read_integrity(&self, integrity: ReadIntegrity) {
        self.inner
            .journal
            .set_verify_reads(integrity == ReadIntegrity::VerifyHash);
    }

    pub fn migrate(self) -> Result<(), LogFsError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Seek, Write},
        num::NonZeroU32,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use crate::journal::Journal2;
    use sha2::Digest;

    use super::*;

    fn test_config(name: &str) -> LogConfig {
        LogConfig {
            path: temp_test_dir(name),
            offset: None,
            raw_mode: false,
            allow_create: true,
            readonly: false,
            crypto: Some(CryptoConfig {
                key: "logfs".to_string().into(),
                salt: b"salt".to_vec().into(),
                iterations: NonZeroU32::new(1).unwrap(),
                profile: CryptoProfile::LowMemory,
            }),
            // Set a very low chunk size to test chunking.
            default_chunk_size: 3,
            partial_index_write_interval: 5,
            full_index_write_interval: 10,
        }
    }

    pub fn temp_test_dir(name: &str) -> PathBuf {
        let tmp_dir = std::env::temp_dir().join("logfs_tests");
        if !tmp_dir.is_dir() {
            std::fs::create_dir_all(&tmp_dir).unwrap();
        }
        let path = tmp_dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        path
    }

    fn test_db<J: JournalStore>(name: &str) -> LogFs<J> {
        LogFs::<J>::open(test_config(name)).unwrap()
    }

    fn write_legacy_v2_fixture(
        path: &std::path::Path,
        crypto_config: Option<CryptoConfig>,
        value: Vec<u8>,
        base_offset: u64,
    ) -> Vec<u8> {
        // Independent encoding of the released v2 layout. This deliberately
        // does not call the current Journal2 writer, so v3 framing changes
        // cannot accidentally redefine the compatibility fixture.
        use crate::journal::v2::data::{
            ActionKeyInsert, JournalAction, JournalEntryHeader, JournalEntryHeaderFlags,
            KeyMeta as StoredKeyMeta, LogFormatVersion, Sha256Hash, SuperblockFlags,
        };

        let crypto = crypto_config.map(crate::crypto::Crypto::new);
        let action = JournalAction::KeyInsert(ActionKeyInsert {
            meta: StoredKeyMeta {
                size: value.len() as u64,
                chunk_size: Some(3),
                hash: Sha256Hash(sha2::Sha256::digest(&value).into()),
                path: "legacy".into(),
            },
        });
        let mut action_bytes = crate::encoding::serialize(&action).unwrap();
        if let Some(crypto) = &crypto {
            crypto.encrypt_data(1, 1, &mut action_bytes).unwrap();
        }
        let header = JournalEntryHeader {
            offset: crate::journal::v2::data::Superblock::HEADER_SIZE,
            sequence_id: SequenceId::first(),
            action_size: action_bytes.len() as u32,
            flags: JournalEntryHeaderFlags::empty(),
        };
        let mut header_bytes = crate::encoding::serialize(&header).unwrap();
        if let Some(crypto) = &crypto {
            crypto.encrypt_data(1, 0, &mut header_bytes).unwrap();
        }
        let mut payload = Vec::new();
        for (index, chunk) in value.chunks(3).enumerate() {
            let mut bytes = chunk.to_vec();
            if let Some(crypto) = &crypto {
                crypto
                    .encrypt_data(1, 2 + index as u32, &mut bytes)
                    .unwrap();
            }
            payload.extend(bytes);
        }
        let tail = crate::journal::v2::data::Superblock::HEADER_SIZE
            + header_bytes.len() as u64
            + action_bytes.len() as u64
            + payload.len() as u64;
        let root = crate::journal::v2::data::Superblock {
            format_version: LogFormatVersion::V2,
            flags: SuperblockFlags::empty(),
            active_sequence: 1,
            tail_offset: tail,
            last_index_entry: None,
        };
        let mut file = std::fs::File::create(path).unwrap();
        file.set_len(base_offset).unwrap();
        file.seek(std::io::SeekFrom::Start(base_offset)).unwrap();
        for slot in 0..crate::journal::v2::data::Superblock::HEADER_COUNT {
            let padding = crypto.as_ref().map(|_| 16).unwrap_or(0);
            let mut bytes = crate::encoding::serialize(&root).unwrap();
            bytes.resize(
                crate::journal::v2::data::Superblock::SERIALIZED_LEN as usize - padding,
                0,
            );
            if let Some(crypto) = &crypto {
                crypto.encrypt_data(0, slot as u32, &mut bytes).unwrap();
            }
            file.write_all(&bytes).unwrap();
        }
        file.write_all(&header_bytes).unwrap();
        file.write_all(&action_bytes).unwrap();
        file.write_all(&payload).unwrap();
        value
    }

    #[test]
    fn reads_plain_and_encrypted_legacy_v2_fixtures() {
        for encrypted in [false, true] {
            let name = if encrypted {
                "legacy-crypto"
            } else {
                "legacy-plain"
            };
            let mut config = test_config(name);
            let crypto = encrypted.then(|| config.crypto.clone().unwrap());
            if !encrypted {
                config.crypto = None;
            }
            let expected =
                write_legacy_v2_fixture(&config.path, crypto, b"legacy multi chunk".to_vec(), 0);
            config.allow_create = false;
            let compatibility = LogFs::<Journal2>::open(config.clone()).unwrap();
            assert!(matches!(
                compatibility.insert("write", Vec::new()),
                Err(LogFsError::ReadOnly)
            ));
            drop(compatibility);
            config.readonly = true;
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            assert_eq!(db.get("legacy").unwrap(), Some(expected));
            drop(db);
        }

        let mut config = test_config("legacy-encrypted-empty-stream");
        let crypto = config.crypto.clone();
        let expected = write_legacy_v2_fixture(&config.path, crypto, Vec::new(), 0);
        let frozen_digest: [u8; 32] = [
            0x37, 0x4f, 0xce, 0x21, 0xec, 0x36, 0x23, 0xe6, 0xed, 0xc2, 0x97, 0x11, 0x78, 0xd5,
            0x40, 0x6e, 0x48, 0x7a, 0x38, 0x68, 0xc6, 0xfc, 0xe9, 0x8d, 0x3d, 0x9c, 0xcd, 0x4c,
            0x50, 0x81, 0x17, 0x2f,
        ];
        assert_eq!(
            <[u8; 32]>::from(sha2::Sha256::digest(std::fs::read(&config.path).unwrap())),
            frozen_digest,
            "the frozen pre-v3 encrypted-empty fixture bytes changed"
        );
        config.allow_create = false;
        config.readonly = true;
        assert!(
            LogFs::<Journal2>::open_with_options(
                config.clone(),
                LogOpenOptions {
                    format_version: Some(LogFormatVersion::V3),
                    ..LogOpenOptions::default()
                },
            )
            .is_err()
        );
        let db = LogFs::<Journal2>::open_with_options(
            config.clone(),
            LogOpenOptions {
                format_version: Some(LogFormatVersion::V2),
                ..LogOpenOptions::default()
            },
        )
        .unwrap();
        assert_eq!(db.get("legacy").unwrap(), Some(expected));
    }

    #[test]
    fn valid_v2_roots_win_over_marker_shaped_value_bytes() {
        let mut config = test_config("legacy-v3-marker-payload");
        config.crypto = None;
        let seed = vec![0x41; 8_000];
        write_legacy_v2_fixture(&config.path, None, seed.clone(), 0);
        config.allow_create = false;
        config.readonly = true;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        let pointer = db
            .inner
            .state
            .read()
            .unwrap()
            .get_key("legacy")
            .unwrap()
            .clone();
        drop(db);

        let marker_position = 4096u64
            .checked_sub(pointer.file_offset)
            .expect("fixture payload must cover the second v3 root offset");
        let mut value = seed;
        value[marker_position as usize..marker_position as usize + 8].copy_from_slice(b"LOGFS3R\0");
        let expected = write_legacy_v2_fixture(&config.path, None, value, 0);
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("legacy").unwrap(), Some(expected));
    }

    #[test]
    fn exclusive_creation_preserves_existing_destination() {
        let config = test_config("exclusive-create");
        let sentinel = b"do not overwrite";
        std::fs::write(&config.path, sentinel).unwrap();
        assert!(LogFs::<Journal2>::create_new_durable(config.clone()).is_err());
        assert_eq!(std::fs::read(config.path).unwrap(), sentinel);
    }

    #[test]
    fn requested_legacy_format_does_not_create_a_new_log() {
        let config = test_config("version-constrained-create");
        let result = LogFs::<Journal2>::open_with_options(
            config.clone(),
            LogOpenOptions {
                format_version: Some(LogFormatVersion::V2),
                ..LogOpenOptions::default()
            },
        );

        assert!(result.is_err());
        assert!(!config.path.exists());
    }

    #[test]
    fn exclusive_creation_supports_nonzero_offsets() {
        let mut config = test_config("exclusive-create-offset");
        config.offset = Some(37);
        let log = LogFs::<Journal2>::create_new(config.clone()).unwrap();
        log.insert("key", b"value".to_vec()).unwrap();
        log.sync().unwrap();
        drop(log);

        let bytes = std::fs::read(&config.path).unwrap();
        assert_eq!(&bytes[..37], &[0; 37]);
        config.allow_create = false;
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn legacy_nonzero_offset_fixture_is_readable_for_export() {
        let mut config = test_config("legacy-history-checkpoint-offset");
        config.offset = Some(37);
        config.full_index_write_interval = 0;
        let expected = write_legacy_v2_fixture(
            &config.path,
            config.crypto.clone(),
            b"original".to_vec(),
            37,
        );
        config.allow_create = false;
        config.readonly = true;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert_eq!(db.get("legacy").unwrap(), Some(expected));
        let report = db.scrub().unwrap();
        assert_eq!(report.keys_verified, 1);
        assert_eq!(report.keys_unverifiable, 0);
    }

    #[test]
    fn zero_length_values_and_streaming_offsets_round_trip() {
        for encrypted in [false, true] {
            let mut config = test_config(if encrypted {
                "empty-crypto"
            } else {
                "empty-plain"
            });
            if !encrypted {
                config.crypto = None;
            }
            let prefix = b"preserved prefix";
            config.offset = Some(prefix.len() as u64);
            std::fs::write(&config.path, prefix).unwrap();
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            db.insert("regular-empty", Vec::new()).unwrap();
            db.insert_writer("stream-empty").unwrap().finish().unwrap();
            let mut writer = db.insert_writer("stream-data").unwrap();
            writer.write_all(b"abcdef").unwrap();
            writer.finish().unwrap();
            db.checkpoint().unwrap();
            db.sync().unwrap();
            drop(db);
            let db = LogFs::<Journal2>::open(config).unwrap();
            assert_eq!(db.get("regular-empty").unwrap(), Some(Vec::new()));
            assert_eq!(db.get("stream-empty").unwrap(), Some(Vec::new()));
            assert_eq!(db.get("stream-data").unwrap(), Some(b"abcdef".to_vec()));
            assert_eq!(db.scrub().unwrap().keys_verified, 3);
            assert_eq!(&std::fs::read(db.path()).unwrap()[..prefix.len()], prefix);
        }
    }

    #[test]
    fn readonly_streaming_and_creation_are_rejected_without_writes() {
        let config = test_config("readonly");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"value".to_vec()).unwrap();
        drop(db);
        let before = std::fs::read(&config.path).unwrap();
        let path = config.path.clone();
        let mut readonly = config;
        readonly.readonly = true;
        readonly.allow_create = false;
        let db = LogFs::<Journal2>::open(readonly).unwrap();
        assert!(matches!(
            db.insert_writer("nope"),
            Err(LogFsError::ReadOnly)
        ));
        drop(db);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn batch_validation_uses_delete_then_rename_evolving_state() {
        let config = test_config("batch-overlay");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("a", b"A".to_vec()).unwrap();
        db.insert("b", b"B".to_vec()).unwrap();
        db.insert("c", b"C".to_vec()).unwrap();
        let sequence = db.superblock().unwrap().active_sequence;
        let invalid = Batch::new()
            .and_remove(vec!["a".into()])
            .and_rename("a", "x");
        assert!(matches!(
            db.batch(invalid),
            Err(LogFsError::NotFound { .. })
        ));
        assert_eq!(db.superblock().unwrap().active_sequence, sequence);

        db.batch(
            Batch::new()
                .and_remove(vec!["c".into()])
                .and_rename("a", "b")
                .and_rename("b", "d"),
        )
        .unwrap();
        assert_eq!(db.get("a").unwrap(), None);
        assert_eq!(db.get("b").unwrap(), None);
        assert_eq!(db.get("c").unwrap(), None);
        assert_eq!(db.get("d").unwrap(), Some(b"A".to_vec()));
        drop(db);
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("d").unwrap(), Some(b"A".to_vec()));
    }

    #[test]
    fn corrupt_checkpoint_falls_back_without_losing_tail_mutations() {
        let mut config = test_config("checkpoint-fallback");
        config.full_index_write_interval = 0;
        let crypto_config = config.crypto.clone().unwrap();
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("before", b"before".to_vec()).unwrap();
        db.checkpoint().unwrap();
        db.insert("after", b"after".to_vec()).unwrap();
        drop(db);

        let crypto = crate::crypto::Crypto::new(crypto_config);
        let payload_offset =
            crate::journal::v3::checkpoint_payload_offset(&config.path, Some(&crypto), 0).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.path)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(payload_offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0x80;
        file.seek(std::io::SeekFrom::Start(payload_offset)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("before").unwrap(), Some(b"before".to_vec()));
        assert_eq!(reopened.get("after").unwrap(), Some(b"after".to_vec()));
    }

    #[test]
    fn checkpoint_counter_replays_tail_mutations_once() {
        let mut config = test_config("checkpoint-counter-replay");
        config.full_index_write_interval = 10;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("base", b"base".to_vec()).unwrap();
        db.checkpoint().unwrap();
        let checkpoint = db.superblock().unwrap().last_index_entry.unwrap();
        for index in 0..4 {
            db.insert(format!("tail-{index}"), vec![index as u8])
                .unwrap();
        }
        drop(db);

        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.inner.state.read().unwrap().write_counter, 4);
        reopened.insert("later-1", vec![1]).unwrap();
        reopened.insert("later-2", vec![2]).unwrap();
        assert_eq!(reopened.inner.state.read().unwrap().write_counter, 6);
        let still_checkpoint = reopened.superblock().unwrap().last_index_entry.unwrap();
        assert_eq!(still_checkpoint.offset, checkpoint.offset);
        assert_eq!(still_checkpoint.sequence, checkpoint.sequence);
    }

    #[test]
    fn v3_wrong_key_never_downgrades_and_value_corruption_is_scrubbed() {
        let mut config = test_config("v3-integrity");
        config.full_index_write_interval = 0;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"integrity".to_vec()).unwrap();
        db.checkpoint().unwrap();
        let pointer = db
            .inner
            .state
            .read()
            .unwrap()
            .get_key("key")
            .unwrap()
            .clone();
        drop(db);

        let mut wrong = config.clone();
        wrong.crypto.as_mut().unwrap().key = "wrong key".to_string().into();
        assert!(LogFs::<Journal2>::open(wrong).is_err());

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.path)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(pointer.file_offset))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        file.seek(std::io::SeekFrom::Start(pointer.file_offset))
            .unwrap();
        file.write_all(&byte).unwrap();
        drop(file);
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert!(reopened.scrub().is_err());
    }

    #[test]
    fn routine_plain_reads_make_hash_checking_opt_in_and_streams_verify_at_eof() {
        let mut config = test_config("optional-read-integrity");
        config.crypto = None;
        config.full_index_write_interval = 0;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"abcdef".to_vec()).unwrap();
        let pointer = db
            .inner
            .state
            .read()
            .unwrap()
            .get_key("key")
            .unwrap()
            .clone();
        drop(db);

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config.path)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(pointer.file_offset))
            .unwrap();
        file.write_all(b"X").unwrap();
        drop(file);

        let unchecked = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert_eq!(unchecked.get("key").unwrap(), Some(b"Xbcdef".to_vec()));
        drop(unchecked);

        let checked =
            LogFs::<Journal2>::open_with_integrity(config, ReadIntegrity::VerifyHash).unwrap();
        assert!(checked.get("key").is_err());
        let mut reader = checked.get_reader("key").unwrap();
        let mut bytes = Vec::new();
        assert!(reader.read_to_end(&mut bytes).is_err());
        assert!(checked.scrub().is_err());
    }

    #[test]
    fn encrypted_v3_ciphertext_is_bound_to_file_identity() {
        let config_a = test_config("identity-a");
        let mut config_b = config_a.clone();
        config_b.path = temp_test_dir("identity-b");
        let a = LogFs::<Journal2>::open(config_a.clone()).unwrap();
        let b = LogFs::<Journal2>::open(config_b.clone()).unwrap();
        a.insert("key", b"abcdef".to_vec()).unwrap();
        b.insert("key", b"abcdef".to_vec()).unwrap();
        let pointer_a = a
            .inner
            .state
            .read()
            .unwrap()
            .get_key("key")
            .unwrap()
            .clone();
        let pointer_b = b
            .inner
            .state
            .read()
            .unwrap()
            .get_key("key")
            .unwrap()
            .clone();
        drop((a, b));

        let encoded_len = 6 + 2 * crate::crypto::Crypto::EXTRA_PAYLOAD_LEN;
        let mut source = std::fs::File::open(&config_b.path).unwrap();
        source
            .seek(std::io::SeekFrom::Start(pointer_b.file_offset))
            .unwrap();
        let mut ciphertext = vec![0u8; encoded_len];
        source.read_exact(&mut ciphertext).unwrap();
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .open(&config_a.path)
            .unwrap();
        target
            .seek(std::io::SeekFrom::Start(pointer_a.file_offset))
            .unwrap();
        target.write_all(&ciphertext).unwrap();
        drop(target);

        let reopened = LogFs::<Journal2>::open(config_a).unwrap();
        assert!(reopened.get("key").is_err());
    }

    #[test]
    fn v3_root_envelope_corruption_never_rolls_back() {
        let corrupt_offsets = [0usize, 8, 16, 17, 20, 28, 44, 56, 70, 110, 4095];
        for (case, corrupt_offset) in corrupt_offsets.into_iter().enumerate() {
            let mut config = test_config(&format!("root-envelope-{case}"));
            config.crypto = None;
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            db.insert("key", b"value".to_vec()).unwrap();
            drop(db);
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&config.path)
                .unwrap();
            file.seek(std::io::SeekFrom::Start(corrupt_offset as u64))
                .unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x80;
            file.seek(std::io::SeekFrom::Start(corrupt_offset as u64))
                .unwrap();
            file.write_all(&byte).unwrap();
            drop(file);
            assert!(LogFs::<Journal2>::open(config).is_err());
        }

        let mut config = test_config("root-tail-past-eof");
        config.crypto = None;
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"value".to_vec()).unwrap();
        drop(db);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&config.path)
            .unwrap()
            .set_len(crate::journal::v3::V3_HEADER_SIZE)
            .unwrap();
        assert!(LogFs::<Journal2>::open(config).is_err());
    }

    #[test]
    fn plain_v3_metadata_corruption_is_mandatory_to_detect() {
        for (case, relative) in [8u64, 8 + 56].into_iter().enumerate() {
            let mut config = test_config(&format!("metadata-integrity-{case}"));
            config.crypto = None;
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            db.insert("key", b"value".to_vec()).unwrap();
            drop(db);
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&config.path)
                .unwrap();
            file.seek(std::io::SeekFrom::Start(
                crate::journal::v3::V3_HEADER_SIZE + relative,
            ))
            .unwrap();
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).unwrap();
            byte[0] ^= 1;
            file.seek(std::io::SeekFrom::Start(
                crate::journal::v3::V3_HEADER_SIZE + relative,
            ))
            .unwrap();
            file.write_all(&byte).unwrap();
            drop(file);
            assert!(LogFs::<Journal2>::open(config).is_err());
        }
    }

    #[test]
    fn injected_persistence_failures_taint_without_stranding_writer() {
        use crate::journal::v3::write::{
            FAIL_DATA_FLUSH, FAIL_DATA_SYNC, FAIL_DATA_WRITE, FAIL_METADATA_WRITE, FAIL_ROOT_SYNC,
            FAIL_ROOT_WRITE, inject_next_io_failure,
        };
        for point in [
            FAIL_METADATA_WRITE,
            FAIL_DATA_WRITE,
            FAIL_DATA_FLUSH,
            FAIL_DATA_SYNC,
            FAIL_ROOT_WRITE,
            FAIL_ROOT_SYNC,
        ] {
            let mut config = test_config(&format!("io-failure-{point}"));
            config.crypto = None;
            let db = LogFs::<Journal2>::open_with_options(
                config.clone(),
                LogOpenOptions {
                    region_len: None,
                    durable: true,
                    randomize_region: false,
                    format_version: None,
                },
            )
            .unwrap();
            inject_next_io_failure(point);
            assert!(db.insert("key", b"value".to_vec()).is_err());
            assert!(matches!(
                db.insert("after", b"value".to_vec()),
                Err(LogFsError::Tainted)
            ));
            drop(db);
            config.allow_create = false;
            let reopened = LogFs::<Journal2>::open(config).unwrap();
            if point == FAIL_ROOT_SYNC {
                assert_eq!(reopened.get("key").unwrap(), Some(b"value".to_vec()));
            } else {
                assert_eq!(reopened.get("key").unwrap(), None);
            }
        }

        for point in [
            FAIL_METADATA_WRITE,
            FAIL_DATA_WRITE,
            FAIL_DATA_FLUSH,
            FAIL_DATA_SYNC,
            FAIL_ROOT_WRITE,
            FAIL_ROOT_SYNC,
        ] {
            let mut config = test_config(&format!("stream-io-failure-{point}"));
            config.crypto = None;
            let db = LogFs::<Journal2>::open_with_options(
                config.clone(),
                LogOpenOptions {
                    region_len: None,
                    durable: true,
                    randomize_region: false,
                    format_version: None,
                },
            )
            .unwrap();
            inject_next_io_failure(point);
            match db.insert_writer("key") {
                Ok(mut writer) => match writer.write_all(b"value") {
                    Ok(()) => assert!(writer.finish().is_err()),
                    Err(_) => drop(writer),
                },
                Err(_) => assert_eq!(point, FAIL_ROOT_WRITE),
            }
            assert!(matches!(
                db.insert("after", b"value".to_vec()),
                Err(LogFsError::Tainted)
            ));
            drop(db);
            config.allow_create = false;
            let reopened = LogFs::<Journal2>::open(config).unwrap();
            if point == FAIL_ROOT_SYNC {
                assert_eq!(reopened.get("key").unwrap(), Some(b"value".to_vec()));
            } else {
                assert_eq!(reopened.get("key").unwrap(), None);
            }
        }
    }

    #[test]
    fn writable_open_is_exclusive_and_readonly_opens_can_coexist() {
        let config = test_config("locking");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert!(LogFs::<Journal2>::open(config.clone()).is_err());
        drop(db);

        let mut readonly = config;
        readonly.readonly = true;
        readonly.allow_create = false;
        let first = LogFs::<Journal2>::open(readonly.clone()).unwrap();
        let second = LogFs::<Journal2>::open(readonly).unwrap();
        drop((first, second));
    }

    #[test]
    fn bounded_region_rejects_overflow_and_preserves_surrounding_bytes() {
        let mut config = test_config("bounded-region");
        config.crypto = None;
        let prefix = b"prefix";
        let suffix = b"suffix";
        let region_len = 9_000u64;
        config.offset = Some(prefix.len() as u64);
        std::fs::write(&config.path, prefix).unwrap();
        let formatted = LogFs::<Journal2>::open_with_options(
            config.clone(),
            LogOpenOptions {
                region_len: Some(region_len),
                durable: false,
                randomize_region: false,
                format_version: None,
            },
        )
        .unwrap();
        drop(formatted);
        let mut backing = std::fs::read(&config.path).unwrap();
        backing.resize(prefix.len() + region_len as usize, 0);
        backing.extend_from_slice(suffix);
        std::fs::write(&config.path, &backing).unwrap();
        let db = LogFs::<Journal2>::open_with_options(
            config.clone(),
            LogOpenOptions {
                region_len: Some(region_len),
                durable: false,
                randomize_region: false,
                format_version: None,
            },
        )
        .unwrap();
        assert!(db.insert("too-large", vec![1; 1000]).is_err());
        drop(db);
        let after = std::fs::read(&config.path).unwrap();
        assert_eq!(&after[..prefix.len()], prefix);
        assert_eq!(&after[prefix.len() + region_len as usize..], suffix);
    }

    #[test]
    fn batch_waits_for_streaming_without_deadlock() {
        let config = test_config("stream-batch-lock");
        let db = LogFs::<Journal2>::open(config).unwrap();
        db.insert("source", b"source".to_vec()).unwrap();
        let mut stream = db.insert_writer("stream").unwrap();
        stream.write_all(b"abc").unwrap();
        let (tx, rx) = mpsc::channel();
        let clone = db.clone();
        let handle = thread::spawn(move || {
            let result = clone.batch(Batch::new().and_rename("source", "renamed"));
            tx.send(result).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
        stream.finish().unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        handle.join().unwrap();
        assert_eq!(db.get("renamed").unwrap(), Some(b"source".to_vec()));
    }

    #[test]
    fn failed_streaming_write_wakes_waiters_with_tainted_error() {
        let mut config = test_config("stream-capacity-failure");
        config.crypto = None;
        config.default_chunk_size = 32;
        let region_len = 9_000;
        let db = LogFs::<Journal2>::open_with_options(
            config,
            LogOpenOptions {
                region_len: Some(region_len),
                durable: false,
                randomize_region: false,
                format_version: None,
            },
        )
        .unwrap();
        let mut writer = db.insert_writer("large").unwrap();
        assert!(writer.write_all(&vec![7; 1024]).is_err());
        drop(writer);
        let (tx, rx) = mpsc::channel();
        let clone = db.clone();
        let handle = thread::spawn(move || {
            tx.send(clone.insert("after", b"value".to_vec())).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
        handle.join().unwrap();
    }

    #[test]
    fn explicit_stream_abort_does_not_publish_and_writer_remains_usable() {
        let config = test_config("stream-abort");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        let mut stream = db.insert_writer("aborted").unwrap();
        stream.write_all(b"partial").unwrap();
        stream.abort().unwrap();
        assert_eq!(db.get("aborted").unwrap(), None);
        db.insert("after", b"value".to_vec()).unwrap();
        drop(db);
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("aborted").unwrap(), None);
        assert_eq!(reopened.get("after").unwrap(), Some(b"value".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn reads_remain_attached_after_backing_path_is_renamed() {
        let config = test_config("renamed-backing");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"value".to_vec()).unwrap();
        let renamed = config.path.with_extension("moved");
        if renamed.exists() {
            std::fs::remove_file(&renamed).unwrap();
        }
        std::fs::rename(&config.path, &renamed).unwrap();
        assert_eq!(db.get("key").unwrap(), Some(b"value".to_vec()));
        drop(db);
        std::fs::remove_file(renamed).unwrap();
    }

    #[test]
    fn repair_dry_run_does_not_write_and_recovery_is_verified() {
        let mut config = test_config("repair-source");
        config.crypto = None;
        config.allow_create = false;
        let expected =
            write_legacy_v2_fixture(&config.path, None, b"legacy multi chunk".to_vec(), 0);
        let destination = config.path.with_extension("recovered");
        if destination.exists() {
            std::fs::remove_file(&destination).unwrap();
        }
        LogFs::<Journal2>::repair(
            config.clone(),
            RepairConfig {
                dry_run: true,
                start_sequence: None,
                recovery_path: Some(destination.clone()),
                skip_bytes: None,
            },
        )
        .unwrap();
        assert!(!destination.exists());

        LogFs::<Journal2>::repair(
            config,
            RepairConfig {
                dry_run: false,
                start_sequence: None,
                recovery_path: Some(destination.clone()),
                skip_bytes: None,
            },
        )
        .unwrap();
        let recovered = LogFs::<Journal2>::open(LogConfig {
            path: destination,
            raw_mode: false,
            offset: None,
            allow_create: false,
            crypto: None,
            default_chunk_size: 3,
            partial_index_write_interval: 0,
            full_index_write_interval: 0,
            readonly: true,
        })
        .unwrap();
        assert_eq!(recovered.get("legacy").unwrap(), Some(expected));
    }

    #[test]
    fn repair_streams_large_v3_values_to_fresh_zero_offset_destination() {
        let mut config = test_config("repair-v3-source");
        config.crypto = None;
        config.offset = Some(123);
        std::fs::write(&config.path, vec![0x5a; 123]).unwrap();
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        let expected = vec![0x42; 200_000];
        let large_action_key = "k".repeat(120_000);
        db.insert(&large_action_key, expected.clone()).unwrap();
        drop(db);

        let destination = config.path.with_extension("v3-recovered");
        if destination.exists() {
            std::fs::remove_file(&destination).unwrap();
        }
        let mut repair_config = config.clone();
        repair_config.allow_create = false;
        LogFs::<Journal2>::repair(
            repair_config,
            RepairConfig {
                dry_run: false,
                start_sequence: None,
                recovery_path: Some(destination.clone()),
                skip_bytes: None,
            },
        )
        .unwrap();
        let reopened = LogFs::<Journal2>::open(LogConfig {
            path: destination,
            offset: None,
            allow_create: false,
            readonly: true,
            ..config
        })
        .unwrap();
        assert_eq!(reopened.get(&large_action_key).unwrap(), Some(expected));
        assert_eq!(reopened.scrub().unwrap().keys_unverifiable, 0);
    }

    #[test]
    fn durable_open_and_explicit_sync_round_trip() {
        let config = test_config("durable-open");
        let db = LogFs::<Journal2>::open_durable(config.clone()).unwrap();
        db.insert("durable", b"value".to_vec()).unwrap();
        db.sync().unwrap();
        drop(db);
        let reopened = LogFs::<Journal2>::open(config).unwrap();
        assert_eq!(reopened.get("durable").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn test_full_flow() {
        let config = test_config("full_flow");
        let log = LogFs::<Journal2>::open(config.clone()).unwrap();

        let key1 = "a/b/c";
        let content1 = b"hello there".to_vec();

        let key2 = "x";
        let content2 = b"xyz".to_vec();

        let key3_a = "rename/first";
        let key3_b = "rename/second";
        let content3 = b"key3!".to_vec();

        // Just insert some keys first.

        log.insert(key1, content1.clone()).unwrap();
        assert_eq!(log.get(key1).unwrap(), Some(content1.clone()));

        log.insert(key2, content2.clone()).unwrap();
        assert_eq!(log.get(key2).unwrap(), Some(content2.clone()));

        // Now drop the DB and re-open to verify that re-loading works.
        std::mem::drop(log);

        let log2 = LogFs::<Journal2>::open(config.clone()).unwrap();

        assert_eq!(log2.get(key1).unwrap(), Some(content1.clone()));
        assert_eq!(log2.get(key2).unwrap(), Some(content2.clone()));

        log2.remove(key1).unwrap();

        log2.insert(key3_a, content3.clone()).unwrap();
        assert_eq!(&log2.get(key3_a).unwrap().unwrap(), &content3);
        log2.rename(key3_a, key3_b).unwrap();
        assert_eq!(log2.get(key3_a).unwrap(), None);
        assert_eq!(&log2.get(key3_b).unwrap().unwrap(), &content3);

        std::mem::drop(log2);

        let log3 = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert_eq!(log3.get(key1).unwrap(), None);
        assert_eq!(log3.get(key2).unwrap(), Some(content2.clone()));

        assert_eq!(log3.get(key3_a).unwrap(), None);
        assert_eq!(&log3.get(key3_b).unwrap().unwrap(), &content3);
    }

    #[test]
    fn test_full_flow_with_offset() {
        let header_content: &[u8] = b"this is a long header in the filer that must not be touched !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Ok?";

        let mut config = test_config("full_flow_with_offset");
        config.offset = Some(header_content.len() as u64);
        config.allow_create = true;

        // create the file up to the offset.

        {
            let mut f = std::fs::File::create(&config.path).unwrap();
            f.write_all(header_content).unwrap();
        }

        let log = LogFs::<Journal2>::open(config.clone()).unwrap();

        let key1 = "a/b/c";
        let content1 = b"hello there".to_vec();

        let key2 = "x";
        let content2 = b"xyz".to_vec();

        let key3_a = "rename/first";
        let key3_b = "rename/second";
        let content3 = b"key3!".to_vec();

        // Just insert some keys first.

        log.insert(key1, content1.clone()).unwrap();
        assert_eq!(log.get(key1).unwrap(), Some(content1.clone()));

        log.insert(key2, content2.clone()).unwrap();
        assert_eq!(log.get(key2).unwrap(), Some(content2.clone()));

        // Now drop the DB and re-open to verify that re-loading works.
        std::mem::drop(log);

        let log2 = LogFs::<Journal2>::open(config.clone()).unwrap();

        assert_eq!(log2.get(key1).unwrap(), Some(content1.clone()));
        assert_eq!(log2.get(key2).unwrap(), Some(content2.clone()));

        log2.remove(key1).unwrap();

        log2.insert(key3_a, content3.clone()).unwrap();
        assert_eq!(&log2.get(key3_a).unwrap().unwrap(), &content3);
        log2.rename(key3_a, key3_b).unwrap();
        assert_eq!(log2.get(key3_a).unwrap(), None);
        assert_eq!(&log2.get(key3_b).unwrap().unwrap(), &content3);

        std::mem::drop(log2);

        let log3 = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert_eq!(log3.get(key1).unwrap(), None);
        assert_eq!(log3.get(key2).unwrap(), Some(content2.clone()));

        assert_eq!(log3.get(key3_a).unwrap(), None);
        assert_eq!(&log3.get(key3_b).unwrap().unwrap(), &content3);

        std::mem::drop(log3);

        // Now verify that the header content is still there.

        let mut f = std::fs::File::open(&config.path).unwrap();
        let mut buf = vec![0u8; header_content.len()];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(header_content, &buf)
    }

    #[test]
    fn test_iterate_range() -> Result<(), LogFsError> {
        let db = test_db::<Journal2>("iterate_range");
        db.insert("a", vec![0])?;
        db.insert("b", vec![0])?;
        db.insert("c/1", vec![1])?;
        db.insert("c/2", vec![3])?;
        db.insert("d", vec![0])?;
        db.insert("e", vec![0])?;

        // Exclusive range.
        let mut keys = db.paths_range("b".to_string().."d".to_string())?;
        keys.sort();
        assert_eq!(
            keys,
            vec!["b".to_string(), "c/1".to_string(), "c/2".to_string(),]
        );

        // Inclusive range.
        let mut keys = db.paths_range("b".to_string()..="d".to_string())?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "b".to_string(),
                "c/1".to_string(),
                "c/2".to_string(),
                "d".to_string(),
            ]
        );

        // All.
        let mut keys = db.paths_range(..)?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c/1".to_string(),
                "c/2".to_string(),
                "d".to_string(),
                "e".to_string(),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_iterate_prefix() -> Result<(), LogFsError> {
        let db = test_db::<Journal2>("iterate_prefix");
        db.insert("a", vec![0])?;
        db.insert("b", vec![0])?;
        db.insert("c", vec![1])?;
        db.insert("c/1", vec![1])?;
        db.insert("c/2", vec![3])?;
        db.insert("d", vec![0])?;
        db.insert("e", vec![0])?;

        let mut keys = db.paths_prefix("c")?;
        keys.sort();
        assert_eq!(
            keys,
            vec!["c".to_string(), "c/1".to_string(), "c/2".to_string(),]
        );

        let keys = db.paths_prefix("d")?;
        assert_eq!(keys, vec!["d".to_string(),]);

        // All.
        let mut keys = db.paths_prefix("")?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "c/1".to_string(),
                "c/2".to_string(),
                "d".to_string(),
                "e".to_string(),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_remove_multiple_paths() -> Result<(), LogFsError> {
        let db = test_db::<Journal2>("remove_multiple_paths");
        db.insert("other", vec![0])?;
        db.insert("prefix", vec![0])?;
        db.insert("prefix/1", vec![1])?;
        db.insert("prefix/2", vec![2])?;
        db.insert("prefix/3", vec![3])?;
        db.insert("blub", vec![0])?;

        db.remove_prefix("prefix")?;

        let mut keys = db.paths_range(..)?;
        keys.sort();
        assert_eq!(keys, vec!["blub".to_string(), "other".to_string()]);

        Ok(())
    }

    #[test]
    fn test_writer() -> Result<(), LogFsError> {
        let config = test_config("writer");

        let db = LogFs::<Journal2>::open(config.clone())?;

        let path1 = "regular";
        let data1 = b"regular111111111".to_vec();
        db.insert(path1, data1.clone())?;

        let path2 = "writer/1";
        let mut writer = db.insert_writer(path2)?;
        let data2 = b"123456789123456789123456789123456789";
        writer.write_all(data2)?;
        writer.finish()?;

        let path3 = "writer/2";
        let mut writer = db.insert_writer(path3)?;
        let data3 = b"123456789123456789123456789123456789";
        writer.write_all(data3)?;
        writer.finish()?;

        assert_eq!(db.get(path1)?.unwrap(), data1);
        assert_eq!(db.get(path2)?.unwrap(), data2);
        assert_eq!(db.get(path3)?.unwrap(), data3);

        std::mem::drop(db);
        let db = LogFs::<Journal2>::open(config.clone())?;

        assert_eq!(db.get(path1)?.unwrap(), data1);
        assert_eq!(db.get(path2)?.unwrap(), data2);
        assert_eq!(db.get(path3)?.unwrap(), data3);

        Ok(())
    }

    #[test]
    fn test_reader() -> Result<(), LogFsError> {
        let config = test_config("reader");
        let path = "key";
        let data = "aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbb";

        let db = LogFs::<Journal2>::open(config.clone())?;
        db.insert(path, data.into())?;
        assert_eq!(db.get(path)?.unwrap(), data.as_bytes());

        let mut reader = db.get_reader(path)?;
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        assert_eq!(&buf, data);

        std::mem::drop(db);

        let db = LogFs::<Journal2>::open(config.clone())?;
        assert_eq!(db.get(path)?.unwrap(), data.as_bytes());

        let mut reader = db.get_reader(path)?;
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        assert_eq!(&buf, data);

        let mut all = Vec::new();
        for res in db.get_chunks(path)? {
            all.extend(res?);
        }
        assert_eq!(&all, data.as_bytes());

        Ok(())
    }

    #[test]
    fn test_chunk_iter() {
        let db = test_db::<Journal2>("chunk_iter");

        let data = "000111222333444555666777888999";
        let path = "a";
        db.insert(path, data.as_bytes().to_vec()).unwrap();

        assert_eq!(&db.get(path).unwrap().unwrap(), data.as_bytes());

        let mut chunks = db.get_chunks(path).unwrap();
        assert_eq!(&chunks.next().unwrap().unwrap(), b"000");

        chunks.skip_bytes(6).unwrap();
        assert_eq!(&chunks.next().unwrap().unwrap(), b"333");
        assert_eq!(&chunks.next().unwrap().unwrap(), b"444");

        // Partial chunk seek.
        chunks.skip_bytes(2).unwrap();
        assert_eq!(&chunks.next().unwrap().unwrap(), b"5");
        assert_eq!(&chunks.next().unwrap().unwrap(), b"666");

        chunks.skip_bytes(1).unwrap();
        assert_eq!(&chunks.next().unwrap().unwrap(), b"77");

        // assert_eq!(&chunks.next().unwrap().unwrap(), b"888");
        // assert_eq!(&chunks.next().unwrap().unwrap(), b"999");

        chunks.skip_bytes(5).unwrap();
        assert_eq!(&chunks.next().unwrap().unwrap(), b"9");

        assert!(chunks.next().is_none());

        assert!(chunks.skip_bytes(6).is_err());
    }

    #[test]
    fn test_minimal_index_writes() {
        let mut config = test_config("test_minimal_index_writes");
        config.partial_index_write_interval = 1;
        config.full_index_write_interval = 1;

        {
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            db.insert("a", b"a".to_vec()).unwrap();
        }

        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        assert_eq!(db.get("a").unwrap().unwrap(), b"a");
    }

    #[test]
    fn test_many_index_writes() {
        let mut config = test_config("test_many_index_writes");
        config.partial_index_write_interval = 1;
        config.full_index_write_interval = 2;

        let db = LogFs::<Journal2>::open(config.clone()).unwrap();

        // Insert 100 keys.
        for x in 0..100 {
            eprintln!("writing key {x}");
            db.insert(x.to_string(), x.to_string().into_bytes())
                .unwrap();
        }

        // Rename a third of the keys.

        for x in (0..100).skip(1).step_by(3) {
            eprintln!("renaming key {x}");
            db.rename(x.to_string(), format!("{x}_renamed")).unwrap();
        }

        // delete a third of the keys.
        for x in (0..100).skip(2).step_by(3) {
            eprintln!("deleting key {x}");
            db.remove(x.to_string()).unwrap();
        }

        std::mem::drop(db);

        let db = LogFs::<Journal2>::open(config).unwrap();

        for x in 0..100 {
            if x % 3 == 0 {
                assert_eq!(
                    db.get(x.to_string()).unwrap().unwrap(),
                    x.to_string().into_bytes()
                );
            } else if x % 3 == 1 {
                assert_eq!(
                    db.get(format!("{x}_renamed")).unwrap().unwrap(),
                    x.to_string().into_bytes()
                );
            } else {
                assert_eq!(db.get(x.to_string()).unwrap(), None);
            }
        }
    }

    #[test]
    fn test_batch_writes() {
        let config = test_config("batch_writes");

        {
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            for x in 1..20 {
                let val = format!("k{x}");
                db.insert(&val, val.as_bytes().to_vec()).unwrap();
            }

            let batch = Batch::new()
                .and_rename("k1", "n1")
                .and_rename("k2", "n2")
                .and_remove(vec!["k3".to_string(), "k4".to_string(), "k5".to_string()])
                .and_rename("k6", "n6")
                .and_remove(vec!["k7".to_string()]);

            db.batch(batch).unwrap();

            assert_eq!(db.get("n1").unwrap().unwrap(), b"k1");
            assert_eq!(db.get("n2").unwrap().unwrap(), b"k2");
            assert_eq!(db.get("n6").unwrap().unwrap(), b"k6");

            assert_eq!(db.get("k4").unwrap(), None);
            assert_eq!(db.get("k5").unwrap(), None);
            assert_eq!(db.get("k7").unwrap(), None);
        }

        {
            let db = LogFs::<Journal2>::open(config.clone()).unwrap();
            assert_eq!(db.get("n1").unwrap().unwrap(), b"k1");
            assert_eq!(db.get("n2").unwrap().unwrap(), b"k2");
            assert_eq!(db.get("n6").unwrap().unwrap(), b"k6");

            assert_eq!(db.get("k4").unwrap(), None);
            assert_eq!(db.get("k5").unwrap(), None);
            assert_eq!(db.get("k7").unwrap(), None);
        }
    }

    #[test]
    fn encrypted_v3_has_opaque_roots_and_unique_nonces() {
        let config = test_config("opaque-v3-layout");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        let initial_roots = std::fs::read(&config.path).unwrap();
        db.insert("first", b"same payload".to_vec()).unwrap();
        let second_offset = std::fs::metadata(&config.path).unwrap().len();
        db.insert("second", b"same payload".to_vec()).unwrap();
        drop(db);

        let bytes = std::fs::read(&config.path).unwrap();
        assert!(!bytes.windows(8).any(|window| window == b"LOGFS3R\0"));
        assert!(
            !bytes
                .windows(b"LOGFS-OPAQUE-V3\0".len())
                .any(|window| window == b"LOGFS-OPAQUE-V3\0")
        );
        assert!(!bytes.windows(64).any(|window| window == [0u8; 64]));
        assert_ne!(&bytes[..16], &bytes[4096..4112]);
        assert_ne!(&bytes[16..40], &bytes[4112..4136]);
        assert_eq!(&initial_roots[..16], &bytes[..16]);
        assert_eq!(&initial_roots[4096..4112], &bytes[4096..4112]);
        assert_ne!(&initial_roots[16..40], &bytes[16..40]);
        assert_ne!(&initial_roots[4112..4136], &bytes[4112..4136]);
        assert_ne!(
            &bytes[crate::journal::v3::V3_HEADER_SIZE as usize
                ..crate::journal::v3::V3_HEADER_SIZE as usize + 24],
            &bytes[second_offset as usize..second_offset as usize + 24]
        );
    }

    #[test]
    fn wrong_v3_profile_or_key_never_formats_the_file() {
        let config = test_config("wrong-v3-profile-key");
        let db = LogFs::<Journal2>::open(config.clone()).unwrap();
        db.insert("key", b"value".to_vec()).unwrap();
        drop(db);
        let original = std::fs::read(&config.path).unwrap();

        let mut wrong_profile = config.clone();
        wrong_profile.crypto.as_mut().unwrap().profile = CryptoProfile::Standard;
        assert!(LogFs::<Journal2>::open(wrong_profile).is_err());
        assert_eq!(std::fs::read(&config.path).unwrap(), original);

        let mut wrong_key = config;
        wrong_key.crypto.as_mut().unwrap().key = "wrong".to_owned().into();
        assert!(LogFs::<Journal2>::open(wrong_key.clone()).is_err());
        assert_eq!(std::fs::read(&wrong_key.path).unwrap(), original);
    }

    #[test]
    fn root_slot_substitution_is_rejected() {
        let first = test_config("root-substitution-a");
        let mut second = first.clone();
        second.path = temp_test_dir("root-substitution-b");
        drop(LogFs::<Journal2>::open(first.clone()).unwrap());
        drop(LogFs::<Journal2>::open(second.clone()).unwrap());
        let donor = std::fs::read(&second.path).unwrap();
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .open(&first.path)
            .unwrap();
        target.write_all(&donor[..4096]).unwrap();
        drop(target);
        assert!(LogFs::<Journal2>::open(first).is_err());
    }

    #[test]
    fn sibling_history_splices_are_rejected_with_and_without_checkpoint() {
        for checkpoint in [false, true] {
            let suffix = if checkpoint { "checkpoint" } else { "scan" };
            let first = test_config(&format!("history-splice-a-{suffix}"));
            let mut second = first.clone();
            second.path = temp_test_dir(&format!("history-splice-b-{suffix}"));
            let db = LogFs::<Journal2>::open(first.clone()).unwrap();
            db.insert("seed", b"seed".to_vec()).unwrap();
            if checkpoint {
                db.checkpoint().unwrap();
            }
            drop(db);
            std::fs::copy(&first.path, &second.path).unwrap();
            let branch_offset = std::fs::metadata(&first.path).unwrap().len();

            let first_db = LogFs::<Journal2>::open(first.clone()).unwrap();
            first_db.insert("branch", b"aaaaaaaa".to_vec()).unwrap();
            drop(first_db);
            let second_db = LogFs::<Journal2>::open(second.clone()).unwrap();
            second_db.insert("branch", b"bbbbbbbb".to_vec()).unwrap();
            drop(second_db);

            let donor = std::fs::read(&second.path).unwrap();
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .open(&first.path)
                .unwrap();
            target
                .seek(std::io::SeekFrom::Start(branch_offset))
                .unwrap();
            target.write_all(&donor[branch_offset as usize..]).unwrap();
            drop(target);
            assert!(LogFs::<Journal2>::open(first).is_err());
        }
    }

    #[test]
    fn randomized_bounded_initialization_fills_only_the_owned_region() {
        let mut config = test_config("randomized-region");
        config.crypto = None;
        let region_len = 16 * 1024;
        let db = LogFs::<Journal2>::create_new_with_options(
            config.clone(),
            LogOpenOptions {
                region_len: Some(region_len),
                durable: false,
                randomize_region: true,
                format_version: None,
            },
        )
        .unwrap();
        drop(db);
        let bytes = std::fs::read(&config.path).unwrap();
        assert_eq!(bytes.len(), region_len as usize);
        assert!(
            !bytes[crate::journal::v3::V3_HEADER_SIZE as usize..]
                .windows(64)
                .any(|window| window == [0u8; 64])
        );

        config.allow_create = false;
        LogFs::<Journal2>::open_with_options(
            config,
            LogOpenOptions {
                region_len: Some(region_len),
                durable: false,
                randomize_region: false,
                format_version: None,
            },
        )
        .unwrap();
    }

    #[test]
    fn obsolete_development_v3_is_not_opened_or_reformatted() {
        let config = test_config("obsolete-v3-no-fallback");
        let mut bytes = vec![0x5a; crate::journal::v3::V3_HEADER_SIZE as usize];
        bytes[..8].copy_from_slice(b"LOGFS3R\0");
        std::fs::write(&config.path, &bytes).unwrap();
        assert!(LogFs::<Journal2>::open(config.clone()).is_err());
        assert_eq!(std::fs::read(config.path).unwrap(), bytes);
    }
}
