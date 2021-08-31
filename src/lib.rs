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

    /// Returns the approximate amount of bytes that could be saved when
    /// re-writing the log.
    pub fn redundant_data_estimate(&self) -> u128 {
        self.inner
            .state
            .read()
            .unwrap()
            .redundant_data_bytes_estimate()
    }

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

    pub fn paths_range<R>(&self, range: R) -> Result<Vec<Path>, LogFsError>
    where
        R: std::ops::RangeBounds<Vec<u8>>,
    {
        Ok(self.inner.state.read().unwrap().paths_range(range))
    }

    pub fn paths_prefix(&self, prefix: &[u8]) -> Result<Vec<Path>, LogFsError> {
        Ok(self.inner.state.read().unwrap().paths_prefix(prefix))
    }

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

    #[test]
    fn test_full_flow() {
        let tmp_dir = std::env::temp_dir().join("logfs_tests");
        if !tmp_dir.is_dir() {
            std::fs::create_dir_all(&tmp_dir).unwrap();
        }
        let path = tmp_dir.join("full.data");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        let log = LogFs::open(&path, TEST_PW.into()).unwrap();

        let key1 = "a/b/c";
        let content1 = b"hello there".to_vec();

        log.insert(key1, content1.clone()).unwrap();
        assert_eq!(log.get(key1).unwrap(), Some(content1.clone()));

        let key2 = "x";
        let content2 = b"xyz".to_vec();
        log.insert(key2, content2.clone()).unwrap();
        assert_eq!(log.get(key2).unwrap(), Some(content2.clone()));

        std::mem::drop(log);

        let log2 = LogFs::open(&path, TEST_PW.into()).unwrap();
        assert_eq!(log2.get(key1).unwrap(), Some(content1.clone()));
        assert_eq!(log2.get(key2).unwrap(), Some(content2.clone()));

        log2.remove(key1).unwrap();
        std::mem::drop(log2);

        let log3 = LogFs::open(&path, TEST_PW.into()).unwrap();
        assert_eq!(log3.get(key1).unwrap(), None);
        assert_eq!(log3.get(key2).unwrap(), Some(content2.clone()));
    }
}
