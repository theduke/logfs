use std::{collections::BTreeMap, sync::RwLock};

use crate::LogFsError;

use super::Path;

pub type DataOffset = u64;

/// Stores the offset to a key.
///
/// Only used at runtime.
#[derive(Clone, Debug)]
pub struct KeyPointer {
    pub sequence_id: u64,
    pub file_offset: DataOffset,
    pub size: u64,
    pub chunk_size: Option<u32>,
    /// Whole-value hash when it was recovered from an entry rather than a
    /// legacy v2 checkpoint (which did not store hashes).
    pub(crate) hash: Option<[u8; 32]>,
    /// Opaque v3 entry nonce. Legacy v2 entries leave this unset.
    pub(crate) entry_nonce: Option<[u8; 24]>,
    /// V3 file identity used as AEAD associated data. Legacy entries leave it
    /// unset.
    pub(crate) log_identity: Option<[u8; 16]>,
}

/// Runtime state of the db.
pub struct State {
    /// A tree mapping keys to key metadata.
    /// This allows quickly finding keys and their file system location.
    ///
    /// NOTE: all paths are kept in memory, which increases memory usage but
    /// allows for keeping the on-disk log structure very simple and enables
    /// fast key lookups.
    /// A [`BTreeMap`] keeps keys sorted and gives predictable range scans. It
    /// does not share storage between common string prefixes.
    pub(crate) tree: BTreeMap<Path, KeyPointer>,

    /// Amount of bytes of redundant (deleted) file data that could be removed
    /// by re-writing the log.
    /// Does not include the space taken up by journal log messages, only the
    /// aggregated file size.
    redundant_data_bytes_estimate: Option<u128>,

    pub(crate) write_counter: u64,
}

pub type SharedTree = std::sync::Arc<RwLock<State>>;

impl State {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
            redundant_data_bytes_estimate: Some(0),
            write_counter: 0,
        }
    }

    pub(crate) fn set_tree(&mut self, tree: BTreeMap<Path, KeyPointer>) {
        self.tree = tree;
        self.redundant_data_bytes_estimate = None;
    }

    pub fn get_key(&self, path: &str) -> Option<&KeyPointer> {
        self.tree.get(path)
    }

    pub fn paths_range<R>(&self, range: R) -> Vec<Path>
    where
        R: std::ops::RangeBounds<String>,
    {
        self.tree.range(range).map(|x| x.0).cloned().collect()
    }

    pub fn paths_offset(&self, offset: usize, max: usize) -> Vec<Path> {
        self.tree
            .iter()
            .skip(offset)
            .take(max)
            .map(|x| x.0)
            .cloned()
            .collect()
    }

    pub fn paths_prefix(&self, prefix: &str) -> Vec<Path> {
        self.tree
            .range(prefix.to_string()..)
            .take_while(|(path, _v)| path.starts_with(prefix))
            .map(|x| x.0)
            .cloned()
            .collect()
    }

    pub fn add_key(&mut self, path: Path, pointer: KeyPointer) {
        if let Some(old) = self.tree.insert(path, pointer)
            && let Some(estimate) = self.redundant_data_bytes_estimate.as_mut()
        {
            *estimate += old.size as u128;
        }
    }

    pub fn remove_key(&mut self, path: &str) -> Option<KeyPointer> {
        if let Some(pointer) = self.tree.remove(path) {
            if let Some(estimate) = self.redundant_data_bytes_estimate.as_mut() {
                *estimate += pointer.size as u128;
            }
            Some(pointer)
        } else {
            None
        }
    }

    pub fn rename_key(&mut self, old_path: &Path, new_path: Path) -> Result<(), LogFsError> {
        if old_path == &new_path {
            return if self.tree.contains_key(old_path) {
                Ok(())
            } else {
                Err(LogFsError::NotFound {
                    path: old_path.clone(),
                })
            };
        }
        if let Some(old) = self.tree.remove(old_path) {
            if let Some(replaced) = self.tree.insert(new_path, old)
                && let Some(estimate) = self.redundant_data_bytes_estimate.as_mut()
            {
                *estimate += replaced.size as u128;
            }
            Ok(())
        } else {
            Err(LogFsError::NotFound {
                path: old_path.clone(),
            })
        }
    }

    /// Get a reference to the state's redundant data bytes estimate.
    pub fn redundant_data_bytes_estimate(&self) -> Option<u128> {
        self.redundant_data_bytes_estimate
    }

    /// Record one committed user mutation. Checkpoint entries themselves are
    /// deliberately not counted.
    pub(crate) fn record_mutation(&mut self) {
        self.write_counter = self.write_counter.saturating_add(1);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
