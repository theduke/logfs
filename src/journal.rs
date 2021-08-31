use std::io::{Read, Seek};

use sha2::Digest;

use crate::{
    crypto::Crypto,
    state::{self, DataOffset, KeyPointer},
    LogFsError,
};

use super::Path;

pub type NextEntryOffset = usize;

/// Metadata for a key.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct KeyMeta {
    path: Path,
    data_len: u64,
    hash: Vec<u8>,
}

/// A file action in the log/journal.
///
/// Actions are written to files in a (de)serialized encoding.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[repr(u32)]
enum JournalAction {
    FileCreated(KeyMeta),
    FilesDeleted { paths: Vec<Path> },
    FileRenamed { old_path: Path, new_path: Path },
}

/// A single entry in the log/journal.
///
/// Entries are written to files in a serialized encoding.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct JournalEntry {
    sequence_id: u64,
    action: JournalAction,
}

/// The header data prefixed to each log entry.
#[derive(serde::Serialize, serde::Deserialize)]
struct JournalEntryHeader {
    /// The byte size of the [`JournalEntry`].
    /// NOTE: this only includes the entry metadata, not any key data.
    /// Hence [`u32`] is more than large enough.
    size: u32,
}

struct JournalState {
    /// The file used for writes.
    /// Only a single file descriptor is used for writes, which means concurrent
    /// writes are not possible.
    ///
    /// Seperate file descriptors are used for reading.
    ///
    /// NOTE: if the writer is `None`, an unrecoverable error was encountered
    /// during a write.
    /// This renders the journal tainted and unusable for additional writes.
    /// In that case all write operations will fail, and the user must restart
    /// the database.
    writer: Option<std::io::BufWriter<std::fs::File>>,
    sequence: u64,
}

pub struct Journal {
    path: std::path::PathBuf,
    state: std::sync::Mutex<JournalState>,
}

impl Journal {
    pub fn open(
        path: std::path::PathBuf,
        state: &mut crate::state::State,
        crypto: Option<&Crypto>,
    ) -> Result<Self, LogFsError> {
        if let Some(parent) = path.parent() {
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let meta = file.metadata()?;
        let file_size = meta.len();
        let mut reader = std::io::BufReader::new(file);

        let mut buffer = Vec::new();
        let mut sequence = 0;
        loop {
            let offset = reader.stream_position()?;
            if offset >= file_size {
                break;
            }

            sequence += 1;

            let (entry, data_offset, next_entry_offset) =
                Self::read_journal_entry(sequence, &mut reader, &mut buffer, crypto)?;

            match entry.action {
                JournalAction::FileCreated(f) => {
                    state.add_key(
                        f.path,
                        state::KeyPointer {
                            sequence_id: entry.sequence_id,
                            offset: offset + data_offset,
                            size: f.data_len,
                        },
                    );

                    // Skip data.
                    reader.seek(std::io::SeekFrom::Current(next_entry_offset as i64))?;
                }
                JournalAction::FilesDeleted { paths } => {
                    for path in &paths {
                        state.remove_key(&path);
                    }
                }
                JournalAction::FileRenamed { old_path, new_path } => {
                    // TODO: propagate error!
                    if let Err(_err) = state.rename_key(&old_path, new_path) {
                        tracing::trace!("Log entry tried to delete path that does not exist");
                    }
                }
            }
        }

        if reader.buffer().len() > 0 {
            return Err(LogFsError::new(
                "Unexpected additional data. Maybe the file was modified during bootstrap",
            ));
        }

        let file = reader.into_inner();

        // Make sure file wasn't modified in the meantime.
        if file.metadata()?.len() != file_size {
            return Err(LogFsError::new("File was modified during bootstrap"));
        }

        let j = Self {
            path,
            state: std::sync::Mutex::new(JournalState {
                writer: Some(std::io::BufWriter::new(file)),
                sequence,
            }),
        };

        Ok(j)
    }

    fn read_journal_entry(
        sequence: u64,
        reader: &mut (impl std::io::Read + std::io::Seek),
        buffer: &mut Vec<u8>,
        crypto: Option<&Crypto>,
    ) -> Result<(JournalEntry, DataOffset, NextEntryOffset), LogFsError> {
        let mut header_data = [0u8; std::mem::size_of::<JournalEntryHeader>()];
        // Read journal entry header with size.
        reader.read_exact(&mut header_data)?;
        let header: JournalEntryHeader = bincode::deserialize(&header_data)?;

        // Read the journal entry.
        buffer.resize(header.size as usize, 0);
        reader.read_exact(buffer)?;

        // Decrypt.
        let (entry_data, suffix_len) = if let Some(crypto) = crypto {
            crypto.decrypt_entry(sequence, &header_data, buffer)?
        } else {
            (buffer.as_slice(), 0)
        };

        let entry: JournalEntry = bincode::deserialize(entry_data)?;

        if sequence != entry.sequence_id {
            return Err(LogFsError::new(format!(
                "Corrupted log: log entry sequence number for sequence {}",
                sequence
            )));
        }

        let data_len = match &entry.action {
            JournalAction::FileCreated(meta) => meta.data_len,
            JournalAction::FilesDeleted { .. } => 0,
            JournalAction::FileRenamed { .. } => 0,
        };

        let data_offset = (header.size as usize + std::mem::size_of::<JournalEntryHeader>()) as u64;
        let next_entry_offset = data_len as usize + suffix_len;

        Ok((entry, data_offset, next_entry_offset))
    }

    fn write_journal_action(
        &self,
        crypto_opt: Option<&Crypto>,
        action: JournalAction,
        data: Option<Vec<u8>>,
    ) -> Result<(JournalEntry, DataOffset), LogFsError> {
        let mut state = self.state.lock().unwrap();

        let next_sequence = state.sequence + 1;
        let writer = state.writer.as_mut().ok_or_else(|| LogFsError::Tainted)?;

        let entry = JournalEntry {
            sequence_id: next_sequence,
            action,
        };
        let mut entry_data = bincode::serialize(&entry)?;

        // Compute byte length of entity.
        // Note that crypto might need some additional bytes.
        let size = (entry_data.len()
            + crypto_opt
                .map(|c| c.extra_payload_len())
                .unwrap_or_default() as usize) as u32;
        // Construct header.
        let header = JournalEntryHeader { size };
        let header_data = bincode::serialize(&header)?;

        // Encrypt if required.
        if let Some(crypto) = crypto_opt {
            crypto.encrypt_entry(next_sequence, &header_data, &mut entry_data)?
        }

        let final_data = if let Some(mut data) = data {
            if let Some(crypto) = crypto_opt {
                crypto.encrypt_data(next_sequence, 1, &mut data)?;
                Some(data)
            } else {
                Some(data)
            }
        } else {
            None
        };

        let res = Self::try_write_entry(
            writer,
            &header_data,
            &entry_data,
            final_data.as_ref().map(|x| x.as_slice()),
        );
        let data_offset = match res {
            Ok(d) => d,
            Err(_err) => {
                // An error ocurred during writing.
                // No information exists on how much was written.
                // BufWriter does not yet offer a good way to retrieve the
                // underlying file, so for now we just taint the journal.
                // FIXME: do smarter error recovery.
                state.writer = None;
                return Err(LogFsError::Tainted);
            }
        };
        state.sequence = next_sequence;
        Ok((entry, data_offset))
    }

    fn try_write_entry(
        writer: &mut (impl std::io::Write + std::io::Seek),
        header: &[u8],
        entry: &[u8],
        data: Option<&[u8]>,
    ) -> Result<DataOffset, std::io::Error> {
        writer.write_all(header)?;
        writer.write_all(entry)?;
        let data_offset = writer.stream_position()?;
        if let Some(data) = data {
            // TODO: use write_all_vectored?
            writer.write_all(data)?;
        }
        writer.flush()?;
        Ok(data_offset)
    }

    pub fn write_insert(
        &self,
        crypto_opt: Option<&Crypto>,
        path: Path,
        data: Vec<u8>,
    ) -> Result<KeyPointer, LogFsError> {
        let hash = sha2::Sha256::digest(&data);
        let action = JournalAction::FileCreated(KeyMeta {
            path: path.clone(),
            data_len: data.len() as u64,
            hash: hash.to_vec(),
        });

        let size = data.len() as u64;
        let (entry, data_offset) = self.write_journal_action(crypto_opt, action, Some(data))?;

        Ok(KeyPointer {
            sequence_id: entry.sequence_id,
            offset: data_offset,
            size,
        })
    }

    pub fn write_rename(
        &self,
        crypto_opt: Option<&Crypto>,
        old_path: Path,
        new_path: Path,
    ) -> Result<(), LogFsError> {
        let action = JournalAction::FileRenamed { old_path, new_path };
        self.write_journal_action(crypto_opt, action, None)?;
        Ok(())
    }

    pub fn write_remove(
        &self,
        crypto_opt: Option<&Crypto>,
        paths: Vec<Path>,
    ) -> Result<(), LogFsError> {
        let action = JournalAction::FilesDeleted { paths };
        self.write_journal_action(crypto_opt, action, None)?;
        Ok(())
    }

    pub fn read_data(
        &self,
        crypto_opt: Option<&Crypto>,
        pointer: &KeyPointer,
    ) -> Result<Vec<u8>, LogFsError> {
        let mut f = std::fs::File::open(&self.path)?;
        f.seek(std::io::SeekFrom::Start(pointer.offset))?;
        let mut reader = std::io::BufReader::new(f);

        let mut buffer = Vec::new();
        let full_data_len = pointer.size as usize
            + crypto_opt
                .map(|c| c.extra_payload_len())
                .unwrap_or_default() as usize;
        buffer.resize(full_data_len, 0);
        reader.read_exact(&mut buffer)?;

        if let Some(crypto) = crypto_opt {
            buffer = crypto.decrypt_data(pointer.sequence_id, 1, buffer)?;
        }
        Ok(buffer)
    }

    /// Get a reference to the journal's path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}
