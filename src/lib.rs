mod error;
pub use self::error::LogFsError;

mod state;

mod journal;

mod crypto;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

type Path = Vec<u8>;

#[derive(Clone)]
pub struct LogFs {
    inner: Arc<Inner>,
}

struct Inner {
    crypto: Option<crypto::Crypto>,
    state: RwLock<state::State>,
    journal: journal::Journal,
}

type DataOffset = u64;

impl LogFs {
    // TODO: add open() without key and open_encrypted() with key.
    pub fn open(path: impl Into<PathBuf>, key: String) -> Result<Self, LogFsError> {
        let crypto = Some(crypto::Crypto::new(key));
        let mut state = state::State::new();
        let journal = journal::Journal::open(path.into(), &mut state, crypto.as_ref())?;

        Ok(Self {
            inner: Arc::new(Inner {
                crypto,
                state: RwLock::new(state),
                journal,
            }),
        })
    }

    /// Get the file system path.
    pub fn path(&self) -> std::path::PathBuf {
        self.inner.journal.path().to_path_buf()
    }

    /// Returns the approximate amount of bytes that could be saved when
    /// re-writing the log.
    pub fn redundant_data_estimate(&self) -> u128 {
        self.inner
            .state
            .read()
            .unwrap()
            .redundant_data_bytes_estimate()
    }

    /// Get a key.
    pub fn get(&self, path: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, LogFsError> {
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
        let data = self
            .inner
            .journal
            .read_data(self.inner.crypto.as_ref(), &pointer)?;
        Ok(Some(data))
    }

    /// Get all paths in the given range.
    pub fn paths_range<R>(&self, range: R) -> Result<Vec<Path>, LogFsError>
    where
        R: std::ops::RangeBounds<Vec<u8>>,
    {
        Ok(self.inner.state.read().unwrap().paths_range(range))
    }

    /// Get all paths with a given prefix.
    pub fn paths_prefix(&self, prefix: &[u8]) -> Result<Vec<Path>, LogFsError> {
        Ok(self.inner.state.read().unwrap().paths_prefix(prefix))
    }

    /// Insert a key.
    pub fn insert(&self, path: impl Into<Vec<u8>>, data: Vec<u8>) -> Result<(), LogFsError> {
        let path = path.into();
        let mut state = self.inner.state.write().unwrap();
        let pointer =
            self.inner
                .journal
                .write_insert(self.inner.crypto.as_ref(), path.clone(), data)?;
        state.add_key(path, pointer);
        Ok(())
    }

    /// Rename a key.
    pub fn rename(
        &self,
        old_key: impl Into<Vec<u8>>,
        new_key: impl Into<Vec<u8>>,
    ) -> Result<(), LogFsError> {
        let old_key = old_key.into();
        let new_key = new_key.into();
        let mut state = self.inner.state.write().unwrap();

        // Ensure key exists.
        if state.get_key(&old_key).is_none() {
            return Err(LogFsError::NotFound {
                path: old_key.into(),
            });
        }

        self.inner.journal.write_rename(
            self.inner.crypto.as_ref(),
            old_key.to_vec(),
            new_key.clone(),
        )?;

        // NOTE: unwrap can't fail, since key existence was checked above.
        state.rename_key(&old_key, new_key).unwrap();

        Ok(())
    }

    /// Remove a key.
    pub fn remove(&self, path: impl AsRef<[u8]>) -> Result<(), LogFsError> {
        let path = path.as_ref();

        let mut state = self.inner.state.write().unwrap();

        if let Some(_pointer) = state.remove_key(path) {
            self.inner
                .journal
                .write_remove(self.inner.crypto.as_ref(), vec![path.to_vec()])?;
        }

        Ok(())
    }

    /// Remove a whole key prefix.
    pub fn remove_prefix(&self, prefix: impl AsRef<[u8]>) -> Result<(), LogFsError> {
        let mut state = self.inner.state.write().unwrap();
        let paths = state.paths_prefix(prefix.as_ref());

        if !paths.is_empty() {
            self.inner
                .journal
                .write_remove(self.inner.crypto.as_ref(), paths.clone())?;
        }

        for path in paths {
            state.remove_key(&path);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PW: &'static str = "logfs";

    fn test_db(name: &str) -> LogFs {
        let tmp_dir = std::env::temp_dir().join("logfs_tests");
        if !tmp_dir.is_dir() {
            std::fs::create_dir_all(&tmp_dir).unwrap();
        }
        let path = tmp_dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        LogFs::open(&path, TEST_PW.into()).unwrap()
    }

    #[test]
    fn test_full_flow() {
        let log = test_db("full_flow");
        let path = log.path().clone();

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

        let log2 = LogFs::open(&path, TEST_PW.into()).unwrap();
        assert_eq!(log2.get(key1).unwrap(), Some(content1.clone()));
        assert_eq!(log2.get(key2).unwrap(), Some(content2.clone()));

        log2.remove(key1).unwrap();

        log2.insert(key3_a, content3.clone()).unwrap();
        assert_eq!(&log2.get(key3_a).unwrap().unwrap(), &content3);
        log2.rename(key3_a, key3_b).unwrap();
        assert_eq!(log2.get(key3_a).unwrap(), None);
        assert_eq!(&log2.get(key3_b).unwrap().unwrap(), &content3);


        std::mem::drop(log2);


        let log3 = LogFs::open(&path, TEST_PW.into()).unwrap();
        assert_eq!(log3.get(key1).unwrap(), None);
        assert_eq!(log3.get(key2).unwrap(), Some(content2.clone()));

        assert_eq!(log3.get(key3_a).unwrap(), None);
        assert_eq!(&log3.get(key3_b).unwrap().unwrap(), &content3);
    }

    #[test]
    fn test_iterate_range() -> Result<(), LogFsError> {
        let db = test_db("iterate_range");
        db.insert("a", vec![0])?;
        db.insert("b", vec![0])?;
        db.insert("c/1", vec![1])?;
        db.insert("c/2", vec![3])?;
        db.insert("d", vec![0])?;
        db.insert("e", vec![0])?;

        // Exclusive range.
        let mut keys = db.paths_range(b"b".to_vec()..b"d".to_vec())?;
        keys.sort();
        assert_eq!(keys, vec![b"b".to_vec(), b"c/1".to_vec(), b"c/2".to_vec(),]);

        // Inclusive range.
        let mut keys = db.paths_range(b"b".to_vec()..=b"d".to_vec())?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                b"b".to_vec(),
                b"c/1".to_vec(),
                b"c/2".to_vec(),
                b"d".to_vec(),
            ]
        );

        // All.
        let mut keys = db.paths_range(..)?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c/1".to_vec(),
                b"c/2".to_vec(),
                b"d".to_vec(),
                b"e".to_vec(),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_iterate_prefix() -> Result<(), LogFsError> {
        let db = test_db("iterate_prefix");
        db.insert("a", vec![0])?;
        db.insert("b", vec![0])?;
        db.insert("c", vec![1])?;
        db.insert("c/1", vec![1])?;
        db.insert("c/2", vec![3])?;
        db.insert("d", vec![0])?;
        db.insert("e", vec![0])?;

        let mut keys = db.paths_prefix(b"c")?;
        keys.sort();
        assert_eq!(keys, vec![b"c".to_vec(), b"c/1".to_vec(), b"c/2".to_vec(),]);

        let keys = db.paths_prefix(b"d")?;
        assert_eq!(keys, vec![b"d".to_vec(),]);

        // All.
        let mut keys = db.paths_prefix(b"")?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                b"a".to_vec(),
                b"b".to_vec(),
                b"c".to_vec(),
                b"c/1".to_vec(),
                b"c/2".to_vec(),
                b"d".to_vec(),
                b"e".to_vec(),
            ]
        );

        Ok(())
    }

    #[test]
    fn test_remove_multiple_paths() -> Result<(), LogFsError> {
        let db = test_db("remove_multiple_paths");
        db.insert("other", vec![0])?;
        db.insert("prefix", vec![0])?;
        db.insert("prefix/1", vec![1])?;
        db.insert("prefix/2", vec![2])?;
        db.insert("prefix/3", vec![3])?;
        db.insert("blub", vec![0])?;

        db.remove_prefix("prefix")?;

        let mut keys = db.paths_range(..)?;
        keys.sort();
        assert_eq!(keys, vec![b"blub".to_vec(), b"other".to_vec()]);

        Ok(())
    }
}
