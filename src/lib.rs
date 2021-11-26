mod error;
pub use self::error::LogFsError;

mod journal;
mod state;
use journal::{
    v2::{KeyChunkIter, StdKeyReader},
    SequenceId,
};
pub use journal::{Journal2, JournalStore};

mod crypto;
pub use crypto::CryptoConfig;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

type Path = String;

pub struct ConfigBuilder {
    config: LogConfig,
}

const DEFAULT_CHUNK_SIZE: u32 = 4_000_000;

impl ConfigBuilder {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            config: LogConfig {
                path: path.into(),
                allow_create: false,
                raw_mode: false,
                crypto: None,
                default_chunk_size: DEFAULT_CHUNK_SIZE,
            },
        }
    }

    pub fn raw_mode(mut self) -> Self {
        self.config.raw_mode = true;
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
    pub allow_create: bool,
    pub crypto: Option<crypto::CryptoConfig>,
    /// Data is chunked into separate slices, which allows incrementally reading
    /// large keys.
    /// This setting specifies the size of chunks in bytes.
    ///
    /// Note that keys can also be created with a custom chunk size.
    pub default_chunk_size: u32,
}

pub struct RepairConfig {
    pub dry_run: bool,
    pub start_sequence: Option<u64>,
    /// The path to which a recovered log should be written.
    pub recovery_path: Option<PathBuf>,
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
    state: Arc<RwLock<state::State>>,
    journal: J,
}

type DataOffset = u64;

impl<J: JournalStore> LogFs<J> {
    // TODO: add open() without key and open_encrypted() with key.
    pub fn open(mut config: LogConfig) -> Result<Self, LogFsError> {
        tracing::trace!(?config, "opening logfs");
        let crypto = config
            .crypto
            .take()
            .map(|c| Arc::new(crypto::Crypto::new(c)));
        let mut state = state::State::new();
        let path = config.path.clone();
        let journal = J::open(path.clone(), &mut state, crypto.clone(), &config)?;

        Ok(Self {
            path,
            inner: Arc::new(Inner {
                state: Arc::new(RwLock::new(state)),
                journal,
            }),
        })
    }

    pub fn repair(mut config: LogConfig, repair_config: RepairConfig) -> Result<(), LogFsError> {
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
    pub fn redundant_data_estimate(&self) -> u128 {
        self.inner
            .state
            .read()
            .unwrap()
            .redundant_data_bytes_estimate()
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

    /// Insert a key.
    pub fn insert(&self, path: impl Into<String>, data: Vec<u8>) -> Result<(), LogFsError> {
        let path = path.into();
        let mut state = self.inner.state.write().unwrap();
        let pointer = self.inner.journal.write_insert(path.clone(), data)?;
        state.add_key(path, pointer);
        Ok(())
    }

    pub fn insert_writer(
        &self,
        path: impl Into<String>,
    ) -> Result<journal::v2::KeyWriter, LogFsError> {
        self.inner
            .journal
            .insert_writer(path.into(), self.inner.state.clone())
    }

    /// Rename a key.
    pub fn rename(
        &self,
        old_key: impl Into<String>,
        new_key: impl Into<String>,
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

        self.inner
            .journal
            .write_rename(old_key.clone(), new_key.clone())?;

        // NOTE: unwrap can't fail, since key existence was checked above.
        state.rename_key(&old_key, new_key).unwrap();

        Ok(())
    }

    /// Remove a key.
    pub fn remove(&self, path: impl AsRef<str>) -> Result<(), LogFsError> {
        let path = path.as_ref();

        let mut state = self.inner.state.write().unwrap();

        if let Some(_pointer) = state.remove_key(path) {
            self.inner.journal.write_remove(vec![path.to_string()])?;
        }

        Ok(())
    }

    /// Remove a whole key prefix.
    pub fn remove_prefix(&self, prefix: impl AsRef<str>) -> Result<(), LogFsError> {
        let mut state = self.inner.state.write().unwrap();
        let paths = state.paths_prefix(prefix.as_ref());

        if !paths.is_empty() {
            self.inner.journal.write_remove(paths.clone())?;
        }

        for path in paths {
            state.remove_key(&path);
        }

        Ok(())
    }
}

impl LogFs<Journal2> {
    pub fn migrate(self) -> Result<(), LogFsError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        num::NonZeroU32,
    };

    use crate::journal::Journal2;

    use super::*;

    fn test_config(name: &str) -> LogConfig {
        LogConfig {
            path: temp_test_dir(name),
            raw_mode: false,
            allow_create: true,
            crypto: Some(CryptoConfig {
                key: "logfs".to_string().into(),
                salt: b"salt".to_vec().into(),
                iterations: NonZeroU32::new(1).unwrap(),
            }),
            // Set a very low chunk size to test chunking.
            default_chunk_size: 3,
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
}
