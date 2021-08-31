use std::collections::BTreeMap;

use crate::LogFsError;

use super::Path;

pub type DataOffset = u64;

/// Stores the offset to a key.
///
/// Only used at runtime.
#[derive(Clone, Debug)]
pub struct KeyPointer {
    pub sequence_id: u64,
    pub offset: DataOffset,
    pub size: u64,
}

/// Runtime state of the db.
pub struct State {
    /// A tree mapping paths to key metadata.
    /// This allows quickly finding keys and their file system location.
    ///
    /// NOTE: all paths are kept in memory, which increases memory usage but
    /// allows for keeping the on-disk log structure very simple and enables
    /// fast key lookups.
    /// The memory usage overhead is mitigated a bit by using a [`BTreeMap`],
    /// which means that keys with the same prefix only consume extra memory
    /// for the unique segments.
    tree: BTreeMap<Path, KeyPointer>,

    /// Amount of bytes of redundant (deleted) file data that could be removed
    /// by re-writing the log.
    /// Does not include the space taken up by journal log messages, only the
    /// aggregated file size.
    redundant_data_bytes_estimate: u128,
}

impl State {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
            redundant_data_bytes_estimate: 0,
        }
    }

    pub fn get_key(&self, path: &[u8]) -> Option<&KeyPointer> {
        self.tree.get(path)
    }

    pub fn paths_range<R>(&self, range: R) -> Vec<Path>
    where
        R: std::ops::RangeBounds<Vec<u8>>,
    {
        self.tree.range(range).map(|x| x.0).cloned().collect()
    }

    pub fn paths_prefix(&self, prefix: &[u8]) -> Vec<Path> {
        self.tree
            .range(prefix.to_vec()..)
            .take_while(|(path, _v)| path.starts_with(prefix))
            .map(|x| x.0)
            .cloned()
            .collect()
    }

    pub fn add_key(&mut self, path: Path, pointer: KeyPointer) {
        self.tree.insert(path, pointer);
    }

    pub fn remove_key(&mut self, path: &[u8]) -> Option<KeyPointer> {
        if let Some(pointer) = self.tree.remove(path) {
            self.redundant_data_bytes_estimate += pointer.size as u128;
            Some(pointer)
        } else {
            None
        }
    }

    pub fn rename_key(&mut self, old_path: &Path, new_path: Path) -> Result<(), LogFsError> {
        if let Some(old) = self.tree.remove(old_path) {
            self.tree.insert(new_path, old);
            Ok(())
        } else {
            Err(LogFsError::NotFound {
                path: old_path.clone(),
            })
        }
    }

    /// Get a reference to the state's redundant data bytes estimate.
    pub fn redundant_data_bytes_estimate(&self) -> u128 {
        self.redundant_data_bytes_estimate
    }
}
