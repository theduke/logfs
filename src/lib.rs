use std::{
    collections::BTreeMap,
    io::{Read, Seek, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use ring::{aead, digest::SHA256_OUTPUT_LEN};
use sha2::Digest;

#[derive(Debug)]
pub enum LogFsError {
    Internal { message: String },
    Io(std::io::Error),
    Conversion(bincode::Error),
}

impl LogFsError {
    fn new(msg: impl Into<String>) -> Self {
        Self::Internal {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for LogFsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFsError::Internal { message } => {
                write!(f, "{}", message)
            }
            LogFsError::Io(err) => err.fmt(f),
            LogFsError::Conversion(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for LogFsError {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            LogFsError::Internal { .. } => None,
            LogFsError::Io(err) => Some(err),
            LogFsError::Conversion(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for LogFsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<bincode::Error> for LogFsError {
    fn from(err: bincode::Error) -> Self {
        Self::Conversion(err)
    }
}

type Path = Vec<u8>;

#[derive(serde::Serialize, serde::Deserialize)]
struct FileNode {
    path: Path,
    data_len: u64,
    hash: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[repr(u32)]
enum JournalAction {
    FileCreated(FileNode),
    FilesDeleted { paths: Vec<Path> },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalEntry {
    sequence_id: u64,
    action: JournalAction,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalEntryHeader {
    size: u32,
}

#[derive(Clone, Debug)]
struct NodePointer {
    sequence_id: u64,
    offset: u64,
    size: u64,
}

struct State {
    tree: BTreeMap<Path, NodePointer>,
    next_sequence: u64,
    file: std::io::BufWriter<std::fs::File>,
}

impl State {
    fn increment_sequence(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }
}

#[derive(Clone)]
pub struct LogFs {
    path: std::path::PathBuf,
    key: Arc<aead::LessSafeKey>,
    state: Arc<RwLock<State>>,
}

type DataOffset = u64;

impl LogFs {
    pub fn open(path: impl Into<PathBuf>, key: String) -> Result<Self, LogFsError> {
        let mut derived_key = [0u8; SHA256_OUTPUT_LEN];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA512,
            std::num::NonZeroU32::new(100_000).unwrap(),
            b"0000",
            key.as_bytes(),
            &mut derived_key,
        );

        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &derived_key)
            .map_err(|_| LogFsError::new("Invalid key"))?;
        let aead_key = aead::LessSafeKey::new(unbound_key);

        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let meta = f.metadata()?;

        let mut filebuf = std::io::BufReader::new(f);

        let mut tree: BTreeMap<Path, NodePointer> = Default::default();
        let mut next_sequence = 1;
        let file_len = meta.len();

        let mut buffer = Vec::new();
        loop {
            let offset = filebuf.stream_position()?;
            if offset >= file_len {
                break;
            }

            let (entry, data_offset) =
                Self::read_journal_entry(next_sequence, &mut filebuf, &mut buffer, &aead_key)?;
            match entry.action {
                JournalAction::FileCreated(f) => {
                    tree.insert(
                        f.path,
                        NodePointer {
                            sequence_id: entry.sequence_id,
                            offset: offset + data_offset,
                            size: f.data_len,
                        },
                    );
                    // Skip data.
                    filebuf.seek(std::io::SeekFrom::Current(
                        f.data_len as i64 + aead::CHACHA20_POLY1305.tag_len() as i64,
                    ))?;
                }
                JournalAction::FilesDeleted { paths } => {
                    for path in &paths {
                        tree.remove(path);
                    }
                }
            }

            next_sequence += 1;
        }

        assert_eq!(filebuf.buffer().len(), 0, "file buffer is empty");

        let file = std::io::BufWriter::new(filebuf.into_inner());

        Ok(Self {
            path,
            key: Arc::new(aead_key),
            state: Arc::new(RwLock::new(State {
                tree,
                next_sequence,
                file,
            })),
        })
    }

    fn read_journal_entry(
        sequence: u64,
        reader: &mut impl std::io::Read,
        mut buffer: &mut Vec<u8>,
        key: &aead::LessSafeKey,
    ) -> Result<(JournalEntry, DataOffset), LogFsError> {
        let mut header_data = [0u8; std::mem::size_of::<JournalEntryHeader>()];
        // Read journal entry header with size.
        reader.read_exact(&mut header_data)?;
        let header: JournalEntryHeader = bincode::deserialize(&header_data)?;

        // Read the journal entry.
        buffer.resize(header.size as usize, 0);
        reader.read_exact(buffer)?;

        // Decrypt.
        let nonce = Self::build_entry_nonce(sequence);

        let aad = aead::Aad::from(header_data);

        let entry_data = key
            .open_in_place(nonce, aad, &mut buffer)
            .map_err(|_| LogFsError::new("Could not decrypt journal entry"))?;

        let entry: JournalEntry = bincode::deserialize(&entry_data)?;

        assert_eq!(sequence, entry.sequence_id);
        let data_offset = (header.size as usize + std::mem::size_of::<JournalEntryHeader>()) as u64;
        Ok((entry, data_offset))
    }

    fn build_entry_nonce(sequence: u64) -> aead::Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&sequence.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        nonce
    }

    fn build_data_nonce(sequence: u64) -> aead::Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&sequence.to_le_bytes());
        nonce_bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
        nonce
    }

    fn write_entry(
        key: &aead::LessSafeKey,
        state: &mut State,
        entry: JournalEntry,
    ) -> Result<(), LogFsError> {
        let mut entry_data = bincode::serialize(&entry)?;

        let header = JournalEntryHeader {
            size: (entry_data.len() + aead::CHACHA20_POLY1305.tag_len()) as u32,
        };
        let header_data = bincode::serialize(&header)?;

        let nonce = Self::build_entry_nonce(entry.sequence_id);
        let aad = aead::Aad::from(&header_data);
        key.seal_in_place_append_tag(nonce, aad, &mut entry_data)
            .map_err(|_| LogFsError::new("Could not encrypt journal entry"))?;

        state.file.write_all(&header_data)?;
        state.file.write_all(&entry_data)?;
        Ok(())
    }

    pub fn insert(&self, path: impl Into<Vec<u8>>, mut data: Vec<u8>) -> Result<(), LogFsError> {
        let hash = sha2::Sha256::digest(&data);

        let path = path.into();
        let mut state = self.state.write().unwrap();
        let sequence_id = state.increment_sequence();
        let data_len = data.len() as u64;

        let entry = JournalEntry {
            sequence_id,
            action: JournalAction::FileCreated(FileNode {
                path: path.clone(),
                data_len,
                hash: hash.to_vec(),
            }),
        };
        Self::write_entry(&self.key, &mut state, entry)?;

        let data_nonce = Self::build_data_nonce(sequence_id);
        let aad = aead::Aad::from(&[]);
        self.key
            .seal_in_place_append_tag(data_nonce, aad, &mut data)
            .map_err(|_| LogFsError::new("Could not encrypt journal entry"))?;

        let data_offset = state.file.stream_position()?;
        state.file.write_all(&data)?;
        state.file.flush()?;

        state.tree.insert(
            path,
            NodePointer {
                sequence_id,
                size: data_len,
                offset: data_offset as u64,
            },
        );

        Ok(())
    }

    pub fn rename(&self, from: &[u8], to: impl Into<Vec<u8>>) -> Result<(), LogFsError> {
        // FIXME: make this (semi)atomic with a lock! Just a stub helper for now.
        let data = self
            .get(from)?
            .ok_or_else(|| LogFsError::new("Path not found"))?;
        self.insert(to, data)?;
        self.remove(from)?;

        Ok(())
    }

    pub fn get(&self, path: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, LogFsError> {
        let pointer = match self.state.read().unwrap().tree.get(path.as_ref()).cloned() {
            Some(data) => data,
            None => {
                return Ok(None);
            }
        };

        let mut f = std::fs::File::open(&self.path)?;
        f.seek(std::io::SeekFrom::Start(pointer.offset))?;
        let mut reader = std::io::BufReader::new(f);

        let mut buffer = Vec::new();
        let data_plus_tag_len = pointer.size as usize + aead::CHACHA20_POLY1305.tag_len();
        buffer.resize(data_plus_tag_len, 0);
        reader.read_exact(&mut buffer)?;

        let nonce = Self::build_data_nonce(pointer.sequence_id);
        let data = self
            .key
            .open_in_place(nonce, aead::Aad::from(&[]), &mut buffer)
            .map_err(|_| LogFsError::new("Could not decrypt data"))?;

        // FIXME: use original buffer.
        Ok(Some(data.to_vec()))
    }

    pub fn paths_range<R>(&self, range: R) -> Result<Vec<Path>, LogFsError>
    where
        R: std::ops::RangeBounds<Vec<u8>>,
    {
        let paths = self
            .state
            .read()
            .unwrap()
            .tree
            .range(range)
            .map(|x| x.0)
            .cloned()
            .collect();
        Ok(paths)
    }

    pub fn paths_prefix(&self, prefix: &[u8]) -> Result<Vec<Path>, LogFsError> {
        let paths = self
            .state
            .read()
            .unwrap()
            .tree
            .range(prefix.to_vec()..)
            .take_while(|(path, _v)| path.starts_with(prefix))
            .map(|x| x.0)
            .cloned()
            .collect();
        Ok(paths)
    }

    pub fn remove(&self, path: impl AsRef<[u8]>) -> Result<(), LogFsError> {
        let path = path.as_ref();

        let mut state = self.state.write().unwrap();

        let sequence_id = state.increment_sequence();
        let entry = JournalEntry {
            sequence_id,
            action: JournalAction::FilesDeleted {
                paths: vec![path.into()],
            },
        };
        Self::write_entry(&self.key, &mut state, entry)?;
        state.file.flush()?;

        Ok(())
    }

    pub fn remove_prefix(&self, prefix: impl AsRef<[u8]>) -> Result<(), LogFsError> {
        let paths = self.paths_prefix(prefix.as_ref())?;

        let mut state = self.state.write().unwrap();

        let sequence_id = state.increment_sequence();
        let entry = JournalEntry {
            sequence_id,
            action: JournalAction::FilesDeleted { paths },
        };
        Self::write_entry(&self.key, &mut state, entry)?;
        state.file.flush()?;

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
