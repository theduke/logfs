pub mod read;
mod repair;
pub mod write;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    io::{self, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use sha2::Digest;

use crate::{
    KeyLock, LogConfig, LogFsError, Path,
    crypto::Crypto,
    state::{KeyPointer, SharedTree},
};

use self::{
    data::{EntryPointer, Offset},
    write::LogWriter,
};

use super::{RepairConfig, SequenceId};

pub(crate) mod data;
pub use data::Superblock;

#[derive(Debug)]
struct PersistedEntry {
    entry: data::JournalEntry,
    /// The offset where the entry data starts.
    file_data_offset: data::Offset,
    crypto_domain: Option<u64>,
    log_identity: Option<[u8; 16]>,
}

impl PersistedEntry {
    // fn to_key_pointer(&self, crypto: Option<&Crypto>) -> KeyPointer {
    //     KeyPointer {
    //         sequence_id: self.entry.header.sequence_id.as_u64(),
    //         file_offset: self.file_data_offset,
    //         size: self.entry.action.payload_len(crypto),
    //         chunk_size: match &self.entry.action {
    //             data::JournalAction::KeyInsert(ins) => ins.meta.chunk_size,
    //             data::JournalAction::KeyRename(_) => None,
    //             data::JournalAction::KeyDelete(_) => None,
    //             data::JournalAction::IndexWrite(_) => None,
    //         },
    //     }
    // }
}

pub struct Journal2 {
    path: std::path::PathBuf,
    _tainted: write::TaintedFlag,
    crypto: Option<Arc<Crypto>>,
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

/// Try to find a valid entry header at an arbitrary position in a buffer.
/// Useful for recovery of corrupted logs.
fn find_entry_header_in_slice(
    crypto: Option<&Crypto>,
    sequence: SequenceId,
    data: &[u8],
    buffer_file_offset: u64,
    base_offset: u64,
) -> Option<(data::JournalEntryHeader, Offset)> {
    let header_len = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto.map(|c| c.extra_payload_len() as usize).unwrap_or(0);
    if data.len() < header_len {
        return None;
    }
    if let Some(crypto) = crypto {
        for index in 0..=(data.len() - header_len) {
            if index % 100_000 == 0 {
                tracing::trace!(chunk_index=%index, "trying to find entry");
            }
            let mut slice = data[index..index + header_len].to_vec();
            let decrypted =
                match crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, &mut slice) {
                    Ok(d) => d,
                    Err(_) => {
                        continue;
                    }
                };

            match bincode::deserialize::<data::JournalEntryHeader>(decrypted) {
                Ok(header)
                    if header.sequence_id == sequence
                        && !header
                            .flags
                            .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
                        && header.offset
                            == buffer_file_offset
                                .checked_add(index as u64)?
                                .checked_sub(base_offset)? =>
                {
                    return Some((header, index as u64));
                }
                Err(_) => continue,
                _ => continue,
            }
        }
        None
    } else {
        for index in 0..=(data.len() - header_len) {
            let slice = &data[index..index + header_len];
            if let Ok(header) = bincode::deserialize::<data::JournalEntryHeader>(slice)
                && header.sequence_id == sequence
                && !header
                    .flags
                    .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
                && header.offset
                    == buffer_file_offset
                        .checked_add(index as u64)?
                        .checked_sub(base_offset)?
            {
                return Some((header, index as u64));
            }
        }
        None
    }
}

fn find_v3_entry_header_in_slice(
    crypto: Option<&Crypto>,
    identity: [u8; 16],
    sequence: SequenceId,
    bytes: &[u8],
    buffer_file_offset: u64,
    base_offset: u64,
) -> Option<(data::JournalEntryHeader, Offset, u64)> {
    let encrypted_header_len = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto
            .map(|value| value.extra_payload_len() as usize)
            .unwrap_or(V3_PLAIN_METADATA_CHECKSUM_LEN);
    let candidate_len = 8usize.checked_add(encrypted_header_len)?;
    if bytes.len() < candidate_len {
        return None;
    }
    for index in 0..=bytes.len() - candidate_len {
        let domain = u64::from_le_bytes(bytes[index..index + 8].try_into().ok()?);
        let mut header_bytes = bytes[index + 8..index + candidate_len].to_vec();
        let aad = v3_aad(identity, domain, ENTRY_HEADER_CHUNK);
        let clear = if let Some(crypto) = crypto {
            match crypto.decrypt_data_ref_with_aad(
                domain,
                ENTRY_HEADER_CHUNK,
                &aad,
                &mut header_bytes,
            ) {
                Ok(clear) => clear,
                Err(_) => continue,
            }
        } else {
            match verify_plain_metadata_checksum(&header_bytes, &aad) {
                Ok(clear) => clear,
                Err(_) => continue,
            }
        };
        if let Ok(header) = bincode::deserialize::<data::JournalEntryHeader>(clear)
            && header.sequence_id == sequence
            && !header
                .flags
                .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
            && header.offset
                == buffer_file_offset
                    .checked_add(index as u64)?
                    .checked_sub(base_offset)?
        {
            return Some((header, index as u64, domain));
        }
    }
    None
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

fn read_entry_header(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    sequence: SequenceId,
) -> Result<data::JournalEntryHeader, LogFsError> {
    let size = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto.map(|c| c.extra_payload_len() as usize).unwrap_or(0);
    buffer.resize(size, 0);

    // Read into buffer.
    reader.read_exact(buffer)?;

    // Decrypt.
    let data = if let Some(crypto) = &crypto {
        crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, buffer)?
    } else {
        buffer
    };

    let header: data::JournalEntryHeader = bincode::deserialize(data)?;
    Ok(header)
}

fn read_entry_action(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    header: &data::JournalEntryHeader,
) -> Result<data::JournalAction, LogFsError> {
    let action_size = header.action_size as usize;
    if action_size > MAX_ACTION_BYTES {
        return Err(LogFsError::new_internal(
            "Journal action exceeds resource limit",
        ));
    }
    buffer.resize(action_size, 0);

    // Read into buffer.
    reader.read_exact(buffer)?;

    // Decrypt.

    let action_data = if let Some(crypto) = &crypto {
        crypto.decrypt_data_ref(header.sequence_id.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
    } else {
        buffer
    };

    let action: data::JournalAction = deserialize_bounded(action_data, MAX_ACTION_BYTES)?;
    Ok(action)
}

fn read_entry(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    sequence: SequenceId,
) -> Result<data::JournalEntry, LogFsError> {
    let header = read_entry_header(reader, buffer, crypto, sequence)?;
    let action = read_entry_action(reader, buffer, crypto, &header)?;

    Ok(data::JournalEntry { header, action })
}

fn read_v3_entry(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    identity: [u8; 16],
    sequence: SequenceId,
) -> Result<(data::JournalEntry, u64), LogFsError> {
    let mut domain_bytes = [0u8; 8];
    reader.read_exact(&mut domain_bytes)?;
    let domain = u64::from_le_bytes(domain_bytes);
    let header_size = data::JournalEntryHeader::SERIALIZED_LEN
        + crypto
            .map(|value| value.extra_payload_len() as usize)
            .unwrap_or(V3_PLAIN_METADATA_CHECKSUM_LEN);
    buffer.resize(header_size, 0);
    reader.read_exact(buffer)?;
    let header_aad = v3_aad(identity, domain, ENTRY_HEADER_CHUNK);
    let header_bytes = if let Some(crypto) = crypto {
        crypto.decrypt_data_ref_with_aad(domain, ENTRY_HEADER_CHUNK, &header_aad, buffer)?
    } else {
        verify_plain_metadata_checksum(buffer, &header_aad)?
    };
    let header: data::JournalEntryHeader = bincode::deserialize(header_bytes)?;
    if header.sequence_id != sequence {
        return Err(LogFsError::new_internal(
            "Recovered v3 entry has an unexpected sequence",
        ));
    }
    let action = read_entry_action_with_domain(reader, buffer, crypto, &header, domain, identity)?;
    Ok((data::JournalEntry { header, action }, domain))
}

fn read_entry_action_with_domain(
    reader: &mut impl io::Read,
    buffer: &mut Vec<u8>,
    crypto: Option<&Crypto>,
    header: &data::JournalEntryHeader,
    domain: u64,
    identity: [u8; 16],
) -> Result<data::JournalAction, LogFsError> {
    let action_size = header.action_size as usize;
    if action_size > MAX_ACTION_BYTES {
        return Err(LogFsError::new_internal(
            "Journal action exceeds resource limit",
        ));
    }
    buffer.resize(action_size, 0);
    reader.read_exact(buffer)?;
    let aad = v3_aad(identity, domain, ENTRY_ACTION_CHUNK);
    let bytes = if let Some(crypto) = crypto {
        crypto.decrypt_data_ref_with_aad(domain, ENTRY_ACTION_CHUNK, &aad, buffer)?
    } else {
        verify_plain_metadata_checksum(buffer, &aad)?
    };
    deserialize_bounded(bytes, MAX_ACTION_BYTES)
}

const MAX_CHECKPOINT_DECODED_BYTES: usize = 512 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 512 * 1024 * 1024;

fn deserialize_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, LogFsError> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(limit as u64)
        .deserialize(bytes)?)
}

fn validate_restored_pointer<R: io::Read + io::Seek>(
    reader: &read::LogReader<R>,
    checkpoint: EntryPointer,
    sequence: SequenceId,
    file_offset: u64,
    size: u64,
    chunk_size: Option<u32>,
    crypto_domain: Option<u64>,
) -> Result<(), LogFsError> {
    if sequence >= checkpoint.sequence {
        return Err(LogFsError::new_internal(
            "Checkpoint key sequence is not older than its checkpoint",
        ));
    }
    if chunk_size == Some(0) {
        return Err(LogFsError::new_internal(
            "Checkpoint contains a zero chunk size",
        ));
    }
    let chunks = if size == 0 && crypto_domain.is_none() {
        0
    } else if let Some(chunk) = chunk_size {
        let count = size.div_ceil(chunk as u64);
        count.max(1)
    } else {
        1
    };
    if chunks > (u32::MAX - ENTRY_FIRST_DATA_CHUNK + 1) as u64 {
        return Err(LogFsError::new_internal(
            "Checkpoint chunk count exceeds format limits",
        ));
    }
    let padding = reader.crypto_padding();
    let occupied = size
        .checked_add(
            padding
                .checked_mul(chunks)
                .ok_or_else(|| LogFsError::new_internal("Checkpoint payload size overflow"))?,
        )
        .ok_or_else(|| LogFsError::new_internal("Checkpoint payload size overflow"))?;
    let payload_end = file_offset
        .checked_add(occupied)
        .ok_or_else(|| LogFsError::new_internal("Checkpoint payload offset overflow"))?;
    let first_data = reader
        .base_offset()
        .checked_add(if reader.v3_identity().is_some() {
            v3_entry_start(reader.base_offset())?
        } else {
            data::Superblock::HEADER_SIZE
        })
        .ok_or_else(|| LogFsError::new_internal("Checkpoint region offset overflow"))?;
    let checkpoint_absolute = reader
        .base_offset()
        .checked_add(checkpoint.offset)
        .ok_or_else(|| LogFsError::new_internal("Checkpoint entry offset overflow"))?;
    if file_offset < first_data
        || file_offset >= checkpoint_absolute
        || payload_end > reader.committed_end()?
    {
        return Err(LogFsError::new_internal(
            "Checkpoint value pointer is outside committed history",
        ));
    }
    Ok(())
}

fn restore_index<R: io::Read + io::Seek>(
    reader: &mut read::LogReader<R>,
    pointer: EntryPointer,
) -> Result<BTreeMap<Path, KeyPointer>, LogFsError> {
    struct BoundedVecWriter {
        bytes: Vec<u8>,
        max_len: usize,
    }
    impl io::Write for BoundedVecWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) > self.max_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "checkpoint expands beyond committed log bounds",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut tree = BTreeMap::<Path, KeyPointer>::new();
    let max_decoded_len = usize::try_from(reader.committed_region_len())
        .unwrap_or(usize::MAX)
        .min(MAX_CHECKPOINT_DECODED_BYTES);

    tracing::trace!(
        sequence=%pointer.sequence.as_u64(),
        offset=%pointer.offset,
        "restoring index"
    );

    let mut prev_pointer = Some(pointer);
    let mut buffer = Vec::new();
    let mut visited = BTreeSet::new();

    while let Some(pointer) = prev_pointer {
        if !visited.insert((pointer.sequence.as_u64(), pointer.offset)) {
            return Err(LogFsError::new_internal("Checkpoint parent cycle detected"));
        }
        reader.seek_to_pointer(pointer)?;

        let (entry, data) = reader.next_entry(Some(&mut buffer))?;
        match entry.entry.action {
            data::JournalAction::IndexWrite(header) => {
                let actual_hash: [u8; 32] = sha2::Sha256::digest(data).into();
                if actual_hash != header.hash.0 {
                    return Err(LogFsError::new_internal("Checkpoint payload hash mismatch"));
                }
                let data = if let Some(compression) = header.compression {
                    match compression {
                        data::CompressionFormat::Brotli => {
                            let mut data: &[u8] = data;
                            let mut buffer = BoundedVecWriter {
                                bytes: Vec::new(),
                                max_len: max_decoded_len,
                            };
                            brotli::BrotliDecompress(&mut data, &mut buffer)?;
                            Cow::Owned(buffer.bytes)
                        }
                    }
                } else {
                    Cow::Borrowed(data)
                };

                let data: data::KeyIndex = deserialize_bounded(&data, max_decoded_len)?;
                if let Some(parent) = data.parent_entry
                    && (parent.offset >= pointer.offset || parent.sequence >= pointer.sequence)
                {
                    return Err(LogFsError::new_internal(
                        "Checkpoint parent pointer is not strictly backward",
                    ));
                }
                prev_pointer = data.parent_entry;

                let mut snapshot_keys = BTreeSet::new();
                for item in data.keys {
                    if !snapshot_keys.insert(item.key.clone()) {
                        return Err(LogFsError::new_internal(
                            "Checkpoint contains duplicate keys",
                        ));
                    }
                    validate_restored_pointer(
                        reader,
                        pointer,
                        item.sequence_id,
                        item.file_offset,
                        item.size,
                        item.chunk_size,
                        None,
                    )?;
                    // Note: ignore already existing keys, since they would
                    // already contain newer data from a previous entry.
                    tree.entry(item.key).or_insert_with(|| KeyPointer {
                        sequence_id: item.sequence_id.as_u64(),
                        file_offset: item.file_offset,
                        size: item.size,
                        chunk_size: item.chunk_size,
                        hash: None,
                        crypto_domain: None,
                        log_identity: None,
                    });
                }
            }
            data::JournalAction::IndexWriteV3(header) => {
                let actual_hash: [u8; 32] = sha2::Sha256::digest(data).into();
                if actual_hash != header.hash.0 {
                    return Err(LogFsError::new_internal("Checkpoint payload hash mismatch"));
                }
                let decoded = if let Some(data::CompressionFormat::Brotli) = header.compression {
                    let mut input: &[u8] = data;
                    let mut output = BoundedVecWriter {
                        bytes: Vec::new(),
                        max_len: max_decoded_len,
                    };
                    brotli::BrotliDecompress(&mut input, &mut output)?;
                    Cow::Owned(output.bytes)
                } else {
                    Cow::Borrowed(data)
                };
                let index: data::KeyIndexV3 = deserialize_bounded(&decoded, max_decoded_len)?;
                prev_pointer = None;
                for item in index.keys {
                    validate_restored_pointer(
                        reader,
                        pointer,
                        item.sequence_id,
                        item.file_offset,
                        item.size,
                        item.chunk_size,
                        item.crypto_domain,
                    )?;
                    if item.crypto_domain.is_none() {
                        return Err(LogFsError::new_internal(
                            "V3 checkpoint key is missing its nonce domain",
                        ));
                    }
                    if tree
                        .insert(
                            item.key,
                            KeyPointer {
                                sequence_id: item.sequence_id.as_u64(),
                                file_offset: item.file_offset,
                                size: item.size,
                                chunk_size: item.chunk_size,
                                hash: item.hash.map(|hash| hash.0),
                                crypto_domain: item.crypto_domain,
                                log_identity: reader.v3_identity(),
                            },
                        )
                        .is_some()
                    {
                        return Err(LogFsError::new_internal(
                            "V3 checkpoint contains duplicate keys",
                        ));
                    }
                }
            }
            _ => {
                return Err(LogFsError::new_internal(
                    "Invalid index pointer: log entry is not an index",
                ));
            }
        }
    }

    tracing::debug!(key_count=%tree.len(), "index restored");

    Ok(tree)
}

impl Journal2 {
    pub fn open(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
    ) -> Result<Self, LogFsError> {
        Self::open_with_region(path, tree, crypto, config, None)
    }

    pub(crate) fn open_with_region(
        path: std::path::PathBuf,
        tree: SharedTree,
        crypto: Option<Arc<Crypto>>,
        config: &LogConfig,
        region_len: Option<u64>,
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

        let meta_opt = match path.metadata() {
            Ok(m) => Some(m),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err.into()),
        };

        let tainted = write::TaintedFlag::new();
        let durable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut writer = if let Some(meta) = meta_opt {
            if path.is_dir() {
                return Err(LogFsError::new_internal("Database path is a directory"));
            }

            let is_block_device = {
                // TODO: support other OSes?
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

            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(!config.readonly);
            let mut file = options.open(&path)?;
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

            if let Some(offset) = config.offset {
                if meta.len() < offset && !is_block_device {
                    return Err(LogFsError::new_internal(
                        "config specified byte offset, but the specified file is smaller  then the offset",
                    ));
                }

                file.seek(io::SeekFrom::Start(offset))?;
            }

            if meta.len() == config.offset.unwrap_or_default() && !is_block_device {
                // File is exactly at the offset - treat as new file.
                if !config.allow_create {
                    return Err(LogFsError::new_internal(
                        "File is empty at the specified offset - but allow_create is false",
                    ));
                }

                LogWriter::create_new(
                    crypto.clone(),
                    tainted.clone(),
                    file,
                    config.offset.unwrap_or_default(),
                    durable.clone(),
                    region_len,
                )?
            } else {
                let mut state = tree.write().unwrap();

                Self::open_existing(
                    file,
                    &mut state,
                    &crypto,
                    config.offset.unwrap_or_default(),
                    &tainted,
                    durable.clone(),
                    region_len,
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
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)?;
            if let Some(offset) = config.offset {
                file.set_len(offset)?;
            }
            fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
                LogFsError::new_internal(format!("Could not acquire exclusive log lock: {error}"))
            })?;

            LogWriter::create_new(
                crypto.clone(),
                tainted.clone(),
                file,
                config.offset.unwrap_or_default(),
                durable.clone(),
                region_len,
            )?
        };
        if !config.readonly {
            writer.begin_write_session()?;
        }

        // Clone the already-opened object and use positional reads. This stays
        // attached to the same object if its pathname is renamed or replaced,
        // without sharing a logical seek cursor with readers or the writer.
        let backing = Arc::new(read::BackingFile::new(writer.backing_clone()?));

        let j = Self {
            state: Arc::new(State {
                writer: std::sync::Mutex::new(WriterState::Available(Some(Box::new(writer)))),
                writer_condvar: std::sync::Condvar::new(),
                tainted: tainted.clone(),
            }),
            _tainted: tainted,
            crypto,
            path,
            default_chunk_size: config.default_chunk_size,
            readonly: config.readonly,
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
        region_len: Option<u64>,
    ) -> Result<LogWriter, LogFsError> {
        let meta = file.metadata()?;
        let file_size = meta.len();

        debug_assert_eq!(file.stream_position().unwrap(), base_offset);

        let mut reader =
            read::LogReader::new_start(file, base_offset, crypto.as_ref().map(|x| &**x));
        let superblock = reader.read_superblocks()?;
        if region_len.is_some_and(|length| superblock.block.tail_offset > length) {
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
            region_len,
        )?;
        Ok(writer)
    }

    /* fn open_and_truncate_file(
        path: &std::path::Path,
        new_length: u64,
    ) -> Result<std::fs::File, std::io::Error> {
        let f = std::fs::OpenOptions::new()
            .create(false)
            .read(true)
            .write(true)
            .open(path)?;
        f.set_len(new_length)?;
        Ok(f)
    } */

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
            crypto_domain: entry.crypto_domain,
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
            pointer,
            self.backing.clone(),
            true,
        )?;
        reader.read_all()?;
        Ok(pointer.hash.is_some())
    }

    fn reader(&self, pointer: &KeyPointer) -> Result<read::StdKeyReader, LogFsError> {
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
            pointer,
            self.backing.clone(),
            self.verify_reads.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        Ok(read::StdKeyReader::new(reader))
    }

    fn chunk_iter(&self, pointer: &KeyPointer) -> Result<read::KeyChunkIter, LogFsError> {
        let reader = read::KeyDataReader::new_shared(
            self.crypto.clone(),
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
                    crypto_domain: entry.crypto_domain,
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

const ENTRY_HEADER_CHUNK: data::ChunkIndex = 0;
const ENTRY_ACTION_CHUNK: data::ChunkIndex = 1;
const ENTRY_FIRST_DATA_CHUNK: data::ChunkIndex = 2;

#[derive(Debug)]
struct IndexedSuperBlock {
    block: data::Superblock,
    index: usize,
    format: RootFormat,
}

#[derive(Clone, Debug)]
enum RootFormat {
    LegacyV2,
    V3 {
        identity: [u8; 16],
        generation: u64,
        last_nonce_domain: u64,
    },
}

const V3_ROOT_MAGIC: [u8; 8] = *b"LOGFS3R\0";
const V3_ROOT_SLOT_SIZE: u64 = 4096;
const V3_ROOT_COUNT: u64 = 2;
pub(crate) const V3_HEADER_SIZE: u64 = V3_ROOT_SLOT_SIZE * V3_ROOT_COUNT;
const V3_ROOT_RECORD_LEN: usize = V3_ROOT_SLOT_SIZE as usize;
const V3_ROOT_MAGIC_COPY_OFFSET: usize = V3_ROOT_RECORD_LEN - V3_ROOT_MAGIC.len();
const V3_ROOT_PREFIX_LEN: usize = 60;
const V3_ROOT_FLAG_ENCRYPTED: u8 = 1;
const V3_PLAIN_METADATA_CHECKSUM_LEN: usize = 32;

fn v3_aad(identity: [u8; 16], domain: u64, chunk: data::ChunkIndex) -> [u8; 28] {
    let mut aad = [0u8; 28];
    aad[..16].copy_from_slice(&identity);
    aad[16..24].copy_from_slice(&domain.to_le_bytes());
    aad[24..].copy_from_slice(&chunk.to_le_bytes());
    aad
}

fn append_plain_metadata_checksum(bytes: &mut Vec<u8>, aad: &[u8]) {
    let mut hasher = sha2::Sha256::new();
    hasher.update(aad);
    hasher.update(&*bytes);
    bytes.extend_from_slice(&hasher.finalize());
}

fn verify_plain_metadata_checksum<'a>(bytes: &'a [u8], aad: &[u8]) -> Result<&'a [u8], LogFsError> {
    let data_len = bytes
        .len()
        .checked_sub(V3_PLAIN_METADATA_CHECKSUM_LEN)
        .ok_or_else(|| LogFsError::new_internal("Truncated v3 metadata checksum"))?;
    let (data, expected) = bytes.split_at(data_len);
    let mut hasher = sha2::Sha256::new();
    hasher.update(aad);
    hasher.update(data);
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(LogFsError::new_internal("V3 metadata checksum mismatch"));
    }
    Ok(data)
}

fn v3_alignment_padding(base_offset: u64) -> u64 {
    (V3_ROOT_SLOT_SIZE - base_offset % V3_ROOT_SLOT_SIZE) % V3_ROOT_SLOT_SIZE
}

fn v3_entry_start(base_offset: u64) -> Result<u64, LogFsError> {
    v3_alignment_padding(base_offset)
        .checked_add(V3_HEADER_SIZE)
        .ok_or_else(|| LogFsError::new_internal("V3 root area offset overflow"))
}

impl RootFormat {
    fn entry_start(&self, base_offset: u64) -> Result<u64, LogFsError> {
        match self {
            Self::LegacyV2 => Ok(data::Superblock::HEADER_SIZE),
            Self::V3 { .. } => v3_entry_start(base_offset),
        }
    }

    fn root_offset(&self, base_offset: u64, index: usize) -> Result<u64, LogFsError> {
        let index = u64::try_from(index)
            .map_err(|_| LogFsError::new_internal("Root slot index overflow"))?;
        match self {
            Self::LegacyV2 => index
                .checked_mul(data::Superblock::SERIALIZED_LEN)
                .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow")),
            Self::V3 { .. } => v3_alignment_padding(base_offset)
                .checked_add(
                    index
                        .checked_mul(V3_ROOT_SLOT_SIZE)
                        .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow"))?,
                )
                .ok_or_else(|| LogFsError::new_internal("Root slot offset overflow")),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct V3RootPayload {
    block: data::Superblock,
    last_nonce_domain: u64,
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
