pub mod v2;
pub use v2::{Journal2, Superblock};

use std::{collections::BTreeMap, num::NonZeroU64, path::PathBuf, sync::Arc};

use crate::{
    crypto::Crypto,
    state::{KeyPointer, SharedTree},
    Batch, KeyLock, LogConfig, LogFsError,
};

use self::v2::{
    read::{KeyChunkIter, StdKeyReader},
    write::KeyWriter,
};

use super::Path;

pub type NextEntryOffset = usize;

/// Monotonically increasing, unique sequence numer of a log entry.
/// This is important for proper encryption with AEAD.
#[derive(
    serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
pub struct SequenceId(NonZeroU64);

impl SequenceId {
    // TODO: remove! only needed for now until state is refactored.
    pub fn from_u64(value: u64) -> Self {
        Self(NonZeroU64::new(value).unwrap())
    }

    pub fn first() -> Self {
        Self(NonZeroU64::new(1).unwrap())
    }

    pub fn try_increment(self) -> Result<Self, LogFsError> {
        self.0
            .get()
            .checked_add(1)
            .map(|x| Self(NonZeroU64::new(x).unwrap()))
            .ok_or_else(|| {
                // TODO: use special error variant.
                LogFsError::new_internal(
                    "Number of log entries exceeds the maximum. Rewrite the log to fix this.",
                )
            })
    }

    pub fn try_decrement(self) -> Result<Self, LogFsError> {
        self.0
            .get()
            .checked_sub(1)
            .map(|x| Self(NonZeroU64::new(x).unwrap()))
            .ok_or_else(|| {
                // TODO: use special error variant.
                LogFsError::new_internal(
                    "Number of log entries exceeds the maximum. Rewrite the log to fix this.",
                )
            })
    }

    pub fn as_u64(self) -> u64 {
        self.0.get()
    }
}

pub struct RepairConfig {
    pub dry_run: bool,
    pub start_sequence: Option<SequenceId>,
    pub skip_bytes: Option<u64>,
    /// The path to which a recovered log should be written.
    pub recovery_path: Option<PathBuf>,
}

pub trait JournalStore {
    fn open(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError>
    where
        Self: Sized;

    fn repair(
        log_config: &LogConfig,
        crypto: Option<Arc<Crypto>>,
        repair_config: RepairConfig,
    ) -> Result<(), LogFsError>
    where
        Self: Sized;

    fn write_batch(&self, batch: Batch) -> Result<(), LogFsError>;

    fn write_insert(&self, path: Path, data: Vec<u8>) -> Result<KeyPointer, LogFsError>;

    fn insert_writer(
        &self,
        path: Path,
        tree: SharedTree,
        writer_lock: KeyLock,
    ) -> Result<KeyWriter, LogFsError>;

    fn write_rename(&self, old_path: Path, new_path: Path) -> Result<(), LogFsError>;

    fn write_remove(&self, paths: Vec<Path>) -> Result<(), LogFsError>;

    fn write_index(
        &self,
        tree: &BTreeMap<String, KeyPointer>,
        full: bool,
    ) -> Result<(), LogFsError>;

    fn read_data(&self, pointer: &KeyPointer) -> Result<Vec<u8>, LogFsError>;

    fn reader(&self, pointer: &KeyPointer) -> Result<StdKeyReader, LogFsError>;

    fn read_chunks(&self, pointer: &KeyPointer) -> Result<KeyChunkIter, LogFsError>;

    fn size_log(&self) -> Result<u64, LogFsError>;
    fn supberlock(&self) -> Result<Superblock, LogFsError>;
}
