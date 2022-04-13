use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    sync::Arc,
};

use crate::{crypto::Crypto, journal::SequenceId, state::KeyPointer, LogFsError};

use super::{
    data, IndexedSuperBlock, PersistedEntry, ENTRY_ACTION_CHUNK, ENTRY_FIRST_DATA_CHUNK,
    ENTRY_HEADER_CHUNK,
};

pub struct LogReader<'a, R> {
    offset: u64,
    // TODO: should be private!
    pub next_sequence: SequenceId,
    crypto: Option<&'a Crypto>,
    buffer: Vec<u8>,
    // TODO: should be private!
    pub reader: BufReader<R>,
}

impl<'a, R: std::io::Read + std::io::Seek> LogReader<'a, R> {
    pub fn new_start(reader: R, crypto: Option<&'a Crypto>) -> Self {
        Self {
            offset: 0,
            next_sequence: SequenceId::first(),
            crypto,
            buffer: Vec::new(),
            reader: BufReader::new(reader),
        }
    }

    pub(super) fn read_superblocks(&mut self) -> Result<IndexedSuperBlock, LogFsError> {
        let mut best_block: Option<IndexedSuperBlock> = None;

        let mut buf = Vec::new();
        for index in 0..data::Superblock::HEADER_COUNT {
            buf.resize(data::Superblock::SERIALIZED_LEN as usize, 0);
            self.reader.read_exact(&mut buf)?;

            if let Some(crypto) = self.crypto.as_ref() {
                buf = match crypto.decrypt_data(0, index as u32, std::mem::take(&mut buf)) {
                    Ok(b) => b,
                    Err(_err) => {
                        continue;
                    }
                };
            }

            match bincode::deserialize::<data::Superblock>(&buf) {
                Ok(block) => {
                    best_block = if let Some(old_block) = best_block {
                        if block.active_sequence > old_block.block.active_sequence {
                            Some(IndexedSuperBlock {
                                index: index as usize,
                                block,
                            })
                        } else {
                            Some(old_block)
                        }
                    } else {
                        Some(IndexedSuperBlock {
                            block,
                            index: index as usize,
                        })
                    };
                }
                Err(_err) => {}
            }
        }

        let block =
            best_block.ok_or_else(|| LogFsError::new_internal("Could not find a superblock"))?;
        self.offset = self.reader.stream_position()?;
        debug_assert_eq!(self.offset, data::Superblock::HEADER_SIZE);

        Ok(block)
    }

    /* fn skip_superblocks(&mut self) -> Result<(), LogFsError> {
        self.reader.seek_relative(
            data::Superblock::HEADER_COUNT as i64 * data::Superblock::SERIALIZED_LEN as i64,
        )?;
        Ok(())
    } */

    pub(super) fn next_entry(&mut self) -> Result<PersistedEntry, LogFsError> {
        let chunk_padding = self.crypto.map(|c| c.extra_payload_len()).unwrap_or(0) as usize;
        let start_offset = self.offset;
        let buffer = &mut self.buffer;
        let sequence = self.next_sequence;

        debug_assert_eq!(self.reader.stream_position()?, start_offset);

        let header_size = data::JournalEntryHeader::SERIALIZED_LEN + chunk_padding;

        // Read journal entry header.
        buffer.resize(header_size, 0);

        self.reader.read_exact(buffer)?;

        let header_data = if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_HEADER_CHUNK, buffer)?
        } else {
            &buffer
        };
        let header: data::JournalEntryHeader = bincode::deserialize(&header_data)?;
        tracing::trace!(?header, "read entry header");

        if sequence != header.sequence_id {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry sequence number for sequence {:?}",
                sequence,
            )));
        }
        if start_offset != header.offset {
            return Err(LogFsError::new_internal(format!(
                "Corrupted log: log entry offset does not match actual offset for sequence {:?}",
                self.next_sequence
            )));
        }

        // Read the journal action.

        // Make sure the buffer can hold the data.
        let action_size = header.action_size as usize;
        buffer.resize(action_size, 0);
        // Read into buffer.
        self.reader.read_exact(buffer)?;

        // Decrypt.

        let action_data = if let Some(crypto) = &self.crypto {
            crypto.decrypt_data_ref(sequence.as_u64(), ENTRY_ACTION_CHUNK, buffer)?
        } else {
            &buffer
        };

        let action: data::JournalAction = bincode::deserialize(action_data)?;
        let data_len = action.payload_len(self.crypto.clone());
        self.reader.seek(SeekFrom::Current(data_len as i64))?;

        let data_offset = start_offset + header_size as u64 + action_size as u64;
        let next_entry_offset = data_offset + data_len;
        self.offset = next_entry_offset;
        self.next_sequence = self.next_sequence.try_increment()?;

        assert_eq!(self.offset, self.reader.stream_position()?);

        Ok(PersistedEntry {
            entry: data::JournalEntry { header, action },
            file_data_offset: data_offset,
        })
    }
}

pub struct KeyDataReader {
    crypto: Option<Arc<Crypto>>,
    reader: BufReader<std::fs::File>,
    sequence: SequenceId,
    chunk_size: usize,
    total_size: u64,
    last_chunk_index: data::ChunkIndex,
    last_chunk_size: usize,

    next_chunk: data::ChunkIndex,
}

impl KeyDataReader {
    pub fn new(
        crypto: Option<Arc<Crypto>>,
        pointer: &KeyPointer,
        mut file: std::fs::File,
    ) -> Result<Self, LogFsError> {
        file.seek(SeekFrom::Start(pointer.file_offset))?;
        let reader = BufReader::new(file);
        let chunk_count = pointer
            .chunk_size
            .map(|chunk_size| data::compute_chunk_count(pointer.size, chunk_size))
            .unwrap_or(1);

        let last_chunk_index = chunk_count - 1 + ENTRY_FIRST_DATA_CHUNK;
        let last_chunk_size = pointer
            .chunk_size
            .map(|s| pointer.size - (s as u64 * (chunk_count as u64 - 1)))
            .unwrap_or(pointer.size) as usize;

        Ok(Self {
            crypto,
            reader,
            sequence: SequenceId::from_u64(pointer.sequence_id),
            chunk_size: pointer
                .chunk_size
                .map(|x| x as usize)
                .unwrap_or(pointer.size as usize),
            total_size: pointer.size,
            last_chunk_index,
            last_chunk_size,
            next_chunk: ENTRY_FIRST_DATA_CHUNK,
        })
    }

    pub fn read_all(mut self) -> Result<(Vec<u8>, std::fs::File), LogFsError> {
        let mut data = Vec::with_capacity(self.total_size as usize);

        while self.next_chunk < self.last_chunk_index {
            data.extend(self.read_next_chunk(Vec::with_capacity(self.chunk_size))?);
        }

        data.extend(self.read_next_chunk(Vec::with_capacity(self.last_chunk_size))?);

        Ok((data, self.reader.into_inner()))
    }

    fn read_next_chunk(&mut self, mut buffer: Vec<u8>) -> Result<Vec<u8>, LogFsError> {
        debug_assert!(self.next_chunk >= ENTRY_FIRST_DATA_CHUNK);
        assert!(self.next_chunk <= self.last_chunk_index as u32);

        let chunk = self.next_chunk;
        let is_last = chunk == self.last_chunk_index;

        let size = if is_last {
            if self.last_chunk_index == ENTRY_FIRST_DATA_CHUNK {
                self.chunk_size
            } else {
                (self.total_size
                    - (self.last_chunk_index - ENTRY_FIRST_DATA_CHUNK) as u64
                        * self.chunk_size as u64) as usize
            }
        } else {
            self.chunk_size
        };

        let padding = self
            .crypto
            .as_ref()
            .map(|c| c.extra_payload_len() as usize)
            .unwrap_or_default();

        let size = size + padding;
        buffer.resize(size, 0);
        self.reader.read_exact(&mut buffer)?;

        let data = if let Some(crypto) = self.crypto.as_ref() {
            crypto.decrypt_data(self.sequence.as_u64(), chunk, buffer)?
        } else {
            buffer
        };

        self.next_chunk = self.next_chunk + 1;

        Ok(data)
    }

    fn skip_chunks(&mut self, count: u32) -> Result<(), LogFsError> {
        let target_chunk = self.next_chunk + count;
        if target_chunk > self.last_chunk_index {
            return Err(LogFsError::new_internal("Chunk index out of range"));
        }

        let padding = self
            .crypto
            .as_ref()
            .map(|c| c.extra_payload_len() as usize)
            .unwrap_or_default();

        let bytes_to_skip = count as u64 * (self.chunk_size as u64 + padding as u64);
        self.reader
            .seek(std::io::SeekFrom::Current(bytes_to_skip as i64))?;
        self.next_chunk = target_chunk;

        Ok(())
    }

    fn is_finished(&self) -> bool {
        self.next_chunk > self.last_chunk_index
    }

    /* fn close(self) -> std::fs::File {
        self.reader.into_inner()
    } */
}

pub struct StdKeyReader {
    reader: Option<KeyDataReader>,
    buffer: Vec<u8>,
    buffer_offset: usize,
}

impl StdKeyReader {
    pub fn new(reader: KeyDataReader) -> Self {
        Self {
            reader: Some(reader),
            buffer: Vec::new(),
            buffer_offset: 0,
        }
    }
}

impl std::io::Read for StdKeyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.buffer.is_empty() {
            let remaining_in_buffer = self.buffer.len() - self.buffer_offset;

            let to_write = std::cmp::min(buf.len(), remaining_in_buffer);
            buf[0..to_write]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + to_write]);

            if to_write >= remaining_in_buffer {
                self.buffer.clear();
            } else {
                self.buffer_offset += to_write;
            }
            eprintln!("read {to_write} from std reader");
            return Ok(to_write);
        }

        let mut reader = if let Some(reader) = self.reader.take() {
            reader
        } else {
            return Ok(0);
        };

        let res = reader.read_next_chunk(std::mem::take(&mut self.buffer));

        match res {
            Ok(new_buffer) => {
                self.buffer = new_buffer;
                self.buffer_offset = 0;
                self.reader = if reader.next_chunk <= reader.last_chunk_index {
                    Some(reader)
                } else {
                    None
                };

                self.read(buf)
            }
            Err(err) => {
                self.reader = Some(reader);
                Err(err.into_io())
            }
        }
        // FIXME: write tests!
    }
}

pub struct KeyChunkIter {
    reader: KeyDataReader,
    /// Buffer for partial chunks.
    /// Required when Self::seek targets a partial chunk.
    partial_buffer: Option<Vec<u8>>,
}

impl KeyChunkIter {
    pub fn new(reader: KeyDataReader) -> Self {
        Self {
            reader,
            partial_buffer: None,
        }
    }

    pub fn skip_bytes(&mut self, offset: u64) -> Result<(), LogFsError> {
        let to_skip = u32::try_from(offset as u64 / self.reader.chunk_size as u64)
            .map_err(|_| LogFsError::new_internal("Seek out of bounds"))?;
        self.reader.skip_chunks(to_skip)?;

        let partial = (offset % self.reader.chunk_size as u64) as usize;
        if partial > 0 {
            // Partial chunk read.
            // Need to read and buffer the next chunk.
            let mut data = self.reader.read_next_chunk(Vec::new())?;
            data.drain(..partial);
            debug_assert!(!data.is_empty());
            self.partial_buffer = Some(data);
        }
        Ok(())
    }
}

impl Iterator for KeyChunkIter {
    type Item = Result<Vec<u8>, LogFsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(partial) = self.partial_buffer.take() {
            Some(Ok(partial))
        } else if self.reader.is_finished() {
            None
        } else {
            Some(self.reader.read_next_chunk(Vec::new()))
        }
    }
}
