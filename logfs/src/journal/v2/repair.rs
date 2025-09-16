use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    sync::{Arc, RwLock},
};

use crate::{
    Journal2, LogConfig, LogFsError, crypto::Crypto, journal::SequenceId, state::KeyPointer,
};

use super::{
    RepairConfig, data, determine_file_size, find_entry_header_in_slice, read, read_entry,
};

pub fn repair(
    log_config: &LogConfig,
    crypto: Option<Arc<Crypto>>,
    config: RepairConfig,
) -> Result<(), LogFsError> {
    // TODO: tracing here instead of eprintln!

    let mut f = std::fs::File::open(&log_config.path)?;
    let file_size = determine_file_size(&mut f)?;

    let mut file_offset = config.skip_bytes.unwrap_or_default();

    f.seek(SeekFrom::Start(file_offset))?;
    let mut reader = BufReader::new(f);

    // let _superblock = match reader.read_superblocks() {
    //     Ok(s) => Some(s),
    //     Err(error) => {
    //         tracing::warn!(?error, "could not read superblocks");
    //         None
    //     }
    // };

    let sequence = config.start_sequence.unwrap_or(SequenceId::from_u64(1));

    let mut buffer = Vec::new();

    let mut entry_and_offset = None;
    loop {
        let chunk_len = std::cmp::min(100_000, file_size - file_offset);
        if chunk_len == 0 {
            break;
        }
        let file_progress = format!("{}%", (file_offset / file_size) * 100);
        tracing::trace!(?sequence, %file_offset, %file_progress, "searching for log entry");
        buffer.resize(chunk_len as usize, 0);
        reader.read_exact(&mut buffer)?;

        if let Some((header, buffer_offset)) =
            find_entry_header_in_slice(crypto.as_ref().map(|c| &**c), sequence, &buffer)
        {
            entry_and_offset = Some((header, file_offset + buffer_offset));
            break;
        }

        file_offset += chunk_len;
    }

    let (header, offset) = entry_and_offset
        .ok_or_else(|| LogFsError::new_internal("Could not find log entries in data"))?;

    tracing::trace!(?header, offset, "found entry header");

    reader.seek(SeekFrom::Start(offset))?;

    let crypto_ref = crypto.as_ref().map(|c| &**c);

    let mut buffer = Vec::new();
    let mut sequence = header.sequence_id;
    let mut state = crate::state::State::new();

    loop {
        let entry = match read_entry(&mut reader, &mut buffer, crypto_ref.clone(), sequence) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(?error, "could not read entry. stopping read recovery");
                break;
            }
        };

        let data_offset = reader.stream_position()?;

        let payload_len = entry.action.payload_len(crypto_ref.clone());
        if let Err(error) = reader.seek(SeekFrom::Current(payload_len as i64)) {
            tracing::warn!(
                ?entry,
                ?error,
                "entry is missing payload. stopping read recovery"
            );
            break;
        }

        tracing::trace!(?entry, "recovered entry");

        match entry.action {
            data::JournalAction::KeyInsert(k) => {
                let meta = k.meta;
                state.add_key(
                    meta.path,
                    KeyPointer {
                        sequence_id: entry.header.sequence_id.as_u64(),
                        file_offset: data_offset,
                        size: meta.size,
                        chunk_size: meta.chunk_size,
                    },
                );
            }
            data::JournalAction::KeyRename(r) => {
                for rename in r.renames {
                    state.rename_key(&rename.old_key, rename.new_key).unwrap();
                }
            }
            data::JournalAction::KeyDelete(d) => {
                for path in d.deleted_keys {
                    state.remove_key(&path);
                }
            }
            data::JournalAction::IndexWrite(_) => {}
            data::JournalAction::Batch(batch) => {
                for rename in batch.renames {
                    if let Err(_err) = state.rename_key(&rename.old_key, rename.new_key) {
                        tracing::trace!("Log entry tried to rename a key that does not exist");
                    }
                }

                for deleted_key in &batch.deleted_keys {
                    if state.remove_key(deleted_key).is_none() {
                        tracing::trace!("Log entry tried to delete a key that does not exist");
                    }
                }
            }
        };

        // TODO: handle error
        sequence = sequence.try_increment()?;
    }

    if state.tree.is_empty() {
        return Err(LogFsError::new_internal("Could not recovery any data"));
    }

    tracing::info!(key_count = state.tree.len(), "recovered keys");

    let target_path = match config.recovery_path {
        Some(p) => p,
        None => {
            tracing::info!("Stopping recovery. Specify recovery path to persist.");
            return Ok(());
        }
    };

    let new_state = Arc::new(RwLock::new(crate::state::State::new()));
    let new_config = LogConfig {
        allow_create: true,
        ..log_config.clone()
    };
    let j = Journal2::open(target_path, new_state.clone(), crypto.clone(), &new_config)?;

    let mut file = reader.into_inner();
    for (key, pointer) in state.tree {
        tracing::trace!(?key, "restoring key");
        let reader = read::KeyDataReader::new(crypto.clone(), &pointer, file)?;
        // TODO: partial writes to allow recovering large files / safe memory.
        let (data, f) = reader.read_all()?;

        j.write_insert(
            key.clone(),
            data,
            pointer.chunk_size.unwrap_or(log_config.default_chunk_size),
        )?;
        file = f;

        tracing::debug!(?key, "key restored");
    }

    tracing::info!("recovery complete");

    // match reader.read_superblocks() {
    //     Ok(b) => {
    //         tracing::info!(superblock=?b, "found superblock");
    //     }
    //     Err(error) => {
    //         tracing::warn!(?error, "could not read superblocks");
    //     }
    // }

    // reader.reader.seek(SeekFrom::Start(0))?;
    // reader.offset = 0;
    // // reader.skip_superblocks()?;

    // tracing::info!("searching for log entries");

    // let mut entry = None;
    // let mut count = 0;

    // let mut offset = reader.reader.stream_position()?;

    // let sequence = config.start_sequence.unwrap_or(SequenceId::from_u64(1));
    // tracing::info!(target_sequence=?sequence, "Trying to find start entry");
    // reader.next_sequence = sequence;
    // loop {
    //     reader.reader.seek(SeekFrom::Start(offset))?;
    //     reader.offset = offset;

    //     match reader.next_entry() {
    //         Ok(e) => {
    //             if e.entry.header.sequence_id == sequence {
    //                 entry = Some(e);
    //                 tracing::info!(?sequence, "Found desired start entry");
    //                 break;
    //             } else {
    //                 tracing::warn!(entry=?e, "Found entry, but not with the desired sequence");
    //             }
    //         }
    //         Err(error) => {
    //             if !error.to_string().contains("not decrypt") {
    //                 tracing::trace!(%error, "could not read entry");
    //             }
    //         }
    //     }
    //     offset += 1;

    //     if offset % 10000 == 0 {
    //         tracing::trace!(
    //             target_sequence=?sequence,
    //             current_offset=%offset,
    //             "still trying to find start entry"
    //         );
    //     }
    // }

    // loop {
    //     match reader.next_entry() {
    //         Ok(e) => {
    //             entry = Some(e);
    //             count += 1;
    //         }
    //         Err(error) => {
    //             tracing::warn!(?error, count = count + 1, "Could not read entry");
    //             break;
    //         }
    //     }
    // }

    // let last_entry = entry
    //     .ok_or_else(|| LogFsError::new_internal("Could not find any restorable entries"))?;

    // tracing::info!(
    //     entry_count=count,
    //     sequence_id=?last_entry.entry.header.sequence_id,
    //     "Found entries that can be restored"
    // );

    // if config.dry_run {
    //     return Ok(());
    // }

    // let tainted = TaintedFlag::new();

    // let reader_pos = reader.reader.stream_position()?;
    // let mut file = reader.reader.into_inner();
    // file.seek(SeekFrom::Start(reader_pos))?;

    // let superblock = IndexedSuperBlock {
    //     block: data::Superblock {
    //         format_version: data::LogFormatVersion::V2,
    //         flags: data::SuperblockFlags::empty(),
    //         tail_offset: reader_pos,
    //         last_index_entry: None,
    //         active_sequence: last_entry.entry.header.sequence_id.as_u64(),
    //     },
    //     index: 1,
    // };
    // let mut writer = LogWriter::open(crypto.clone(), tainted.clone(), file, superblock)?;
    // writer.write_next_superblock()?;

    // tracing::info!(
    //     entry_count=count,
    //     sequence_id=?last_entry.entry.header.sequence_id,
    //     "Restored superblock"
    // );

    Ok(())
}
