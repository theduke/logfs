use std::{
    io::{BufReader, Read, Seek, SeekFrom},
    sync::{Arc, RwLock},
};

use crate::{
    Journal2, JournalStore, LogConfig, LogFsError, crypto::Crypto, journal::SequenceId,
    state::KeyPointer,
};

use super::{
    RepairConfig, data, determine_file_size, find_entry_header_in_slice,
    find_v3_entry_header_in_slice, read, read_entry, read_v3_entry,
};

pub fn repair(
    log_config: &LogConfig,
    crypto: Option<Arc<Crypto>>,
    config: RepairConfig,
) -> Result<(), LogFsError> {
    // TODO: tracing here instead of eprintln!

    let mut f = std::fs::File::open(&log_config.path)?;
    fs2::FileExt::try_lock_shared(&f).map_err(|error| {
        LogFsError::new_internal(format!("Could not acquire shared source lock: {error}"))
    })?;
    let file_size = determine_file_size(&mut f)?;
    let probe_offset = log_config.offset.unwrap_or_default();
    let root = read::LogReader::new_start(f.try_clone()?, probe_offset, crypto.as_deref())
        .read_superblocks()?;
    let (is_v3, v3_identity, derived_v3_crypto) = match &root.format {
        super::RootFormat::LegacyV2 => (false, None, None),
        super::RootFormat::V3 {
            identity,
            log_secret,
            ..
        } => (
            true,
            Some(*identity),
            crypto
                .as_ref()
                .map(|_| crate::crypto::V3Crypto::new(log_secret)),
        ),
    };
    let required_v3_identity =
        || v3_identity.ok_or_else(|| LogFsError::new_internal("V3 repair is missing its identity"));

    let mut file_offset = config.skip_bytes.unwrap_or_default();
    if file_offset > file_size {
        return Err(LogFsError::new_internal(
            "Repair start offset is beyond EOF",
        ));
    }

    f.seek(SeekFrom::Start(file_offset))?;
    let mut reader = BufReader::new(f);

    let sequence = config.start_sequence.unwrap_or(SequenceId::from_u64(1));

    let mut buffer = Vec::new();

    let mut entry_and_offset = None;
    loop {
        let chunk_len = std::cmp::min(100_000, file_size.saturating_sub(file_offset));
        if chunk_len == 0 {
            break;
        }
        let file_progress = format!(
            "{}%",
            file_offset
                .saturating_mul(100)
                .checked_div(file_size)
                .unwrap_or(100)
        );
        tracing::trace!(?sequence, %file_offset, %file_progress, "searching for log entry");
        buffer.resize(chunk_len as usize, 0);
        reader.read_exact(&mut buffer)?;

        if is_v3 {
            if let Some((header, buffer_offset, domain)) = find_v3_entry_header_in_slice(
                crypto.as_deref(),
                derived_v3_crypto.as_ref(),
                required_v3_identity()?,
                sequence,
                &buffer,
                file_offset,
                probe_offset,
            ) {
                entry_and_offset = Some((header, file_offset + buffer_offset, Some(domain)));
                break;
            }
        } else if let Some((header, buffer_offset)) = find_entry_header_in_slice(
            crypto.as_deref(),
            sequence,
            &buffer,
            file_offset,
            probe_offset,
        ) {
            entry_and_offset = Some((header, file_offset + buffer_offset, None));
            break;
        }

        let overlap = if is_v3 {
            24 + data::JournalEntryHeader::SERIALIZED_LEN as u64
                + crypto
                    .as_ref()
                    .map(|value| value.extra_payload_len())
                    .unwrap_or(super::V3_PLAIN_METADATA_CHECKSUM_LEN as u64)
                - 1
        } else {
            data::JournalEntryHeader::SERIALIZED_LEN as u64
                + crypto
                    .as_ref()
                    .map(|value| value.extra_payload_len())
                    .unwrap_or(0)
                - 1
        };
        file_offset += chunk_len.saturating_sub(overlap).max(1);
        reader.seek(SeekFrom::Start(file_offset))?;
    }

    let (header, offset, _first_domain) = entry_and_offset
        .ok_or_else(|| LogFsError::new_internal("Could not find log entries in data"))?;

    tracing::trace!(?header, offset, "found entry header");

    reader.seek(SeekFrom::Start(offset))?;

    let crypto_ref = crypto.as_deref();

    let mut buffer = Vec::new();
    let mut sequence = header.sequence_id;
    let mut state = crate::state::State::new();

    loop {
        let recovered_offset = reader.stream_position()?;
        let recovered = if is_v3 {
            read_v3_entry(
                &mut reader,
                &mut buffer,
                crypto_ref,
                derived_v3_crypto.as_ref(),
                required_v3_identity()?,
                sequence,
            )
            .map(|(entry, domain)| (entry, Some(domain)))
        } else {
            read_entry(&mut reader, &mut buffer, crypto_ref, sequence).map(|entry| (entry, None))
        };
        let (entry, entry_nonce) = match recovered {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(?error, "could not read entry. stopping read recovery");
                break;
            }
        };

        if entry.header.sequence_id != sequence
            || entry.header.offset
                != recovered_offset.checked_sub(probe_offset).ok_or_else(|| {
                    LogFsError::new_internal("Recovered entry precedes log region")
                })?
            || entry
                .header
                .flags
                .contains(data::JournalEntryHeaderFlags::INCOMPLETE)
        {
            tracing::warn!(
                ?entry,
                "recovered entry has invalid framing; stopping recovery"
            );
            break;
        }

        let data_offset = reader.stream_position()?;

        let payload_len = if let data::JournalAction::KeyInsert(insert) = &entry.action {
            if insert.meta.chunk_size == Some(0) && insert.meta.size != 0 {
                tracing::warn!(?entry, "recovered entry has a zero chunk size");
                break;
            }
            let chunks = if !is_v3 && insert.meta.size == 0 {
                0
            } else if let Some(chunk_size) = insert.meta.chunk_size {
                insert.meta.size.div_ceil(chunk_size.max(1) as u64).max(1)
            } else {
                1
            };
            if chunks > (u32::MAX - super::ENTRY_FIRST_DATA_CHUNK + 1) as u64 {
                tracing::warn!(?entry, "recovered entry has too many chunks");
                break;
            }
            let Some(padding) = crypto_ref
                .map(|crypto| crypto.extra_payload_len())
                .unwrap_or(0)
                .checked_mul(chunks)
            else {
                tracing::warn!(?entry, "recovered payload length overflow");
                break;
            };
            let Some(payload_len) = insert.meta.size.checked_add(padding) else {
                tracing::warn!(?entry, "recovered payload length overflow");
                break;
            };
            payload_len
        } else {
            entry.action.payload_len(crypto_ref)
        };
        let payload_end = data_offset
            .checked_add(payload_len)
            .ok_or_else(|| LogFsError::new_internal("Recovered payload length overflow"))?;
        if payload_end > file_size {
            tracing::warn!(
                ?entry,
                "entry payload extends beyond EOF; stopping recovery"
            );
            break;
        }
        if let Err(error) = reader.seek(SeekFrom::Start(payload_end)) {
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
                        hash: Some(meta.hash.0),
                        entry_nonce,
                        log_identity: v3_identity,
                    },
                );
            }
            data::JournalAction::KeyRename(r) => {
                for rename in r.renames {
                    if let Err(error) = state.rename_key(&rename.old_key, rename.new_key) {
                        tracing::warn!(?error, "skipping recovered rename with missing source");
                    }
                }
            }
            data::JournalAction::KeyDelete(d) => {
                for path in d.deleted_keys {
                    state.remove_key(&path);
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
        };

        // TODO: handle error
        sequence = sequence.try_increment()?;
    }

    if state.tree.is_empty() {
        return Err(LogFsError::new_internal("Could not recovery any data"));
    }

    tracing::info!(key_count = state.tree.len(), "recovered keys");

    if config.dry_run {
        tracing::info!("dry-run complete; no output was written");
        return Ok(());
    }

    let target_path = match config.recovery_path {
        Some(p) => p,
        None => {
            tracing::info!("Stopping recovery. Specify recovery path to persist.");
            return Ok(());
        }
    };
    if std::fs::canonicalize(&log_config.path).ok()
        == target_path.parent().and_then(|parent| {
            std::fs::canonicalize(parent)
                .ok()
                .map(|parent| parent.join(target_path.file_name().unwrap_or_default()))
        })
    {
        return Err(LogFsError::new_internal(
            "Recovery destination aliases the source",
        ));
    }

    let new_state = Arc::new(RwLock::new(crate::state::State::new()));
    let new_config = LogConfig {
        path: target_path.clone(),
        offset: None,
        raw_mode: false,
        allow_create: true,
        readonly: false,
        ..log_config.clone()
    };
    let j = Journal2::create_new_exclusive(
        target_path.clone(),
        new_state.clone(),
        crypto.clone(),
        &new_config,
        None,
        false,
    )?;
    JournalStore::set_durable(&j, true)?;
    JournalStore::sync(&j)?;
    crate::sync_parent_directory(&target_path)?;

    let file = reader.into_inner();
    for (key, pointer) in state.tree {
        tracing::trace!(?key, "restoring key");
        let mut source = read::StdKeyReader::new(read::KeyDataReader::new_verified(
            crypto.clone(),
            derived_v3_crypto.clone().map(Arc::new),
            &pointer,
            file.try_clone()?,
        )?);
        let mut destination = j.repair_insert_writer(key.clone(), new_state.clone())?;
        if let Err(error) = std::io::copy(&mut source, &mut destination) {
            destination.abort()?;
            return Err(error.into());
        }
        destination.finish()?;
        tracing::debug!(?key, "key restored");
    }

    JournalStore::write_index(
        &j,
        &new_state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tree,
        true,
    )?;
    JournalStore::sync(&j)?;
    let expected_count = new_state
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .tree
        .len();
    drop(j);

    let verify_state = Arc::new(RwLock::new(crate::state::State::new()));
    let verify_config = LogConfig {
        path: target_path.clone(),
        allow_create: false,
        readonly: true,
        ..new_config
    };
    let verified = Journal2::open(target_path, verify_state.clone(), crypto, &verify_config)?;
    if verify_state
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .tree
        .len()
        != expected_count
    {
        return Err(LogFsError::new_internal(
            "Recovery output verification found a key-count mismatch",
        ));
    }
    for pointer in verify_state
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .tree
        .values()
    {
        if !verified.verify_data(pointer)? {
            return Err(LogFsError::new_internal(
                "Recovery output is missing a whole-value hash",
            ));
        }
    }

    tracing::info!("recovery complete");

    Ok(())
}
