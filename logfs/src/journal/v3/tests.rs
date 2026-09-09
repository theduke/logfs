use super::*;
use crate::journal::SequenceId;
use crate::{ConfigBuilder, CryptoConfig, CryptoProfile, LogFs, LogOpenOptions};
use std::io::{Seek, SeekFrom, Write};

fn config(dir: &tempfile::TempDir, name: &str, encrypted: bool) -> LogConfig {
    let mut config = ConfigBuilder::new(dir.path().join(name))
        .allow_create()
        .default_chunk_size(16)
        .full_index_write_interval(0)
        .build();
    config.partial_index_write_interval = 0;
    if encrypted {
        config.crypto = Some(CryptoConfig {
            key: "v3 regression password".to_owned().into(),
            salt: vec![1; 16].into(),
            iterations: std::num::NonZeroU32::new(1).unwrap(),
            profile: CryptoProfile::LowMemory,
        });
    }
    config
}

fn repair(config: LogConfig, destination: Option<std::path::PathBuf>) -> Result<(), LogFsError> {
    LogFs::<Journal2>::repair(
        config,
        crate::RepairConfig {
            dry_run: destination.is_none(),
            start_sequence: None,
            recovery_path: destination,
            skip_bytes: None,
        },
    )
}

#[test]
fn explicit_salvage_recovers_either_damaged_root_and_preserves_source() {
    for encrypted in [false, true] {
        for slot in 0..2 {
            let dir = tempfile::tempdir().unwrap();
            let cfg = config(&dir, "source", encrypted);
            let db = LogFs::<Journal2>::open(cfg.clone()).unwrap();
            db.insert("kept", vec![42; 37]).unwrap();
            db.insert("empty", vec![]).unwrap();
            drop(db);
            let mut bytes = std::fs::read(&cfg.path).unwrap();
            bytes[slot * 4096 + 1024] ^= 1;
            std::fs::write(&cfg.path, &bytes).unwrap();
            assert!(LogFs::<Journal2>::open(cfg.clone()).is_err());

            let target = dir.path().join("recovered");
            repair(cfg.clone(), Some(target.clone())).unwrap();
            assert_eq!(std::fs::read(&cfg.path).unwrap(), bytes);
            let recovered = LogFs::<Journal2>::open(LogConfig {
                path: target,
                ..cfg.clone()
            })
            .unwrap();
            assert_eq!(recovered.get("kept").unwrap(), Some(vec![42; 37]));
            assert_eq!(recovered.get("empty").unwrap(), Some(vec![]));
            assert_eq!(recovered.scrub().unwrap().keys_verified, 2);
            drop(recovered);

            if encrypted {
                let mut wrong = cfg.clone();
                wrong.crypto.as_mut().unwrap().key = "wrong".to_owned().into();
                assert!(repair(wrong, None).is_err());
            }
            bytes[(1 - slot) * 4096 + 1024] ^= 1;
            std::fs::write(&cfg.path, bytes).unwrap();
            assert!(repair(cfg, None).is_err());
        }
    }
}

#[test]
fn explicit_salvage_exports_intact_prefix_when_committed_tail_is_truncated() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir, "source", encrypted);
        let db = LogFs::<Journal2>::open(cfg.clone()).unwrap();
        db.insert("kept", vec![7; 19]).unwrap();
        db.insert("truncated", vec![8; 37]).unwrap();
        let tail = db.superblock().unwrap().tail_offset;
        drop(db);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cfg.path)
            .unwrap()
            .set_len(tail - 1)
            .unwrap();
        assert!(LogFs::<Journal2>::open(cfg.clone()).is_err());
        let target = dir.path().join("recovered");
        repair(cfg.clone(), Some(target.clone())).unwrap();
        let recovered = LogFs::<Journal2>::open(LogConfig {
            path: target,
            ..cfg
        })
        .unwrap();
        assert_eq!(recovered.get("kept").unwrap(), Some(vec![7; 19]));
        assert_eq!(recovered.get("truncated").unwrap(), None);
    }
}

#[test]
fn repair_finds_headers_on_both_sides_of_scan_buffer_boundary() {
    for encrypted in [false, true] {
        let header = frame_header_len(encrypted) as i64;
        // Include the first straddling start, the old overlap gap, and both
        // sides of the next buffer. The region itself is deliberately nonzero.
        for delta in [-header + 1, -80, -1, 0, 1] {
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = config(&dir, "source", encrypted);
            cfg.offset = Some((100_000 + delta) as u64 - V3_HEADER_SIZE);
            let db = LogFs::<Journal2>::open(cfg.clone()).unwrap();
            db.insert("found", vec![9; 20]).unwrap();
            drop(db);
            repair(cfg, None)
                .unwrap_or_else(|error| panic!("encrypted={encrypted}, delta={delta}: {error}"));
        }
    }
}

#[test]
fn bounded_insert_exact_fit_one_byte_short_and_rejection_is_nonmutating() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let reference = LogFs::<Journal2>::open(config(&dir, "reference", encrypted)).unwrap();
        reference.insert("key", vec![1; 37]).unwrap();
        // Measure emitted bytes independently of the preflight calculation.
        let required = reference.superblock().unwrap().tail_offset;
        drop(reference);
        for short in [false, true] {
            let mut cfg = config(&dir, if short { "short" } else { "exact" }, encrypted);
            cfg.offset = Some(17);
            std::fs::write(&cfg.path, [0x5a; 17]).unwrap();
            let region_len = required - u64::from(short);
            let options = LogOpenOptions {
                region_len: Some(region_len),
                ..Default::default()
            };
            let db = LogFs::<Journal2>::open_with_options(cfg.clone(), options).unwrap();
            // Surrounding bytes exist before the mutation under test.
            let mut backing = std::fs::OpenOptions::new()
                .write(true)
                .open(&cfg.path)
                .unwrap();
            backing.seek(SeekFrom::Start(17 + region_len)).unwrap();
            backing.write_all(b"suffix").unwrap();
            let before = std::fs::read(&cfg.path).unwrap();
            if short {
                assert!(db.insert("key", vec![1; 37]).is_err());
                assert_eq!(db.superblock().unwrap().tail_offset, V3_HEADER_SIZE);
                assert_eq!(std::fs::read(&cfg.path).unwrap(), before);
                db.insert("key", vec![2; 1]).unwrap();
            } else {
                db.insert("key", vec![1; 37]).unwrap();
                assert_eq!(db.superblock().unwrap().tail_offset, region_len);
            }
            drop(db);
            let after = std::fs::read(&cfg.path).unwrap();
            assert_eq!(&after[..17], &[0x5a; 17]);
            assert_eq!(&after[(17 + region_len) as usize..], b"suffix");
            let reopened = LogFs::<Journal2>::open_with_options(cfg, options).unwrap();
            assert_eq!(
                reopened.get("key").unwrap(),
                Some(if short { vec![2; 1] } else { vec![1; 37] })
            );
        }
    }
}

#[test]
fn action_limit_agrees_for_regular_streaming_and_replay_paths() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir, "source", encrypted);
        limits::with_test_limits(64, 1024, || {
            let db = LogFs::<Journal2>::open(cfg.clone()).unwrap();
            let before = std::fs::read(&cfg.path).unwrap();
            // An insert action with Some(chunk_size) is 57 + key UTF-8 bytes.
            assert!(db.insert("12345678", vec![3; 17]).is_err());
            assert!(db.insert_writer("12345678").is_err());
            assert_eq!(std::fs::read(&cfg.path).unwrap(), before);
            db.insert("1234567", vec![3; 17]).unwrap();
            let mut writer = db.insert_writer("7654321").unwrap();
            writer.write_all(&[4]).unwrap();
            writer.finish().unwrap();
            drop(db);
            let reopened = LogFs::<Journal2>::open(cfg.clone()).unwrap();
            assert_eq!(reopened.get("1234567").unwrap(), Some(vec![3; 17]));
            assert_eq!(reopened.get("7654321").unwrap(), Some(vec![4]));
            drop(reopened);
            repair(cfg.clone(), None).unwrap();
        });
        limits::with_test_limits(63, 1024, || {
            assert!(LogFs::<Journal2>::open(cfg.clone()).is_err());
            assert!(repair(cfg.clone(), None).is_err());
        });
    }
}

#[test]
fn checkpoint_limit_includes_plaintext_budget_plus_separate_tag() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir, "source", encrypted);
        let db = LogFs::<Journal2>::open(cfg.clone()).unwrap();
        db.insert("k", vec![1]).unwrap();
        let snapshot = {
            let state = db.inner.state.read().unwrap();
            index::serialize_snapshot(&state.tree, encrypted).unwrap()
        };
        let limit = snapshot.len() as u64;
        // The borrowed serializer must preserve the original owned wire layout.
        let owned: index::KeyIndexV3 = crate::encoding::deserialize(&snapshot).unwrap();
        assert_eq!(crate::encoding::serialize(&owned).unwrap(), snapshot);
        let before = std::fs::read(&cfg.path).unwrap();
        limits::with_test_limits(1024, limit - 1, || assert!(db.checkpoint().is_err()));
        assert_eq!(std::fs::read(&cfg.path).unwrap(), before);
        limits::with_test_limits(1024, limit, || db.checkpoint().unwrap());
        let pointer = db.superblock().unwrap().last_index_entry.unwrap();
        let crypto = cfg.crypto.clone().map(Crypto::new);
        let mut reader =
            read::LogReader::new_start(std::fs::File::open(&cfg.path).unwrap(), 0, crypto.as_ref());
        reader.read_superblocks().unwrap();
        // Test restoration directly: successful reopen alone could hide a
        // checkpoint rejection behind full replay fallback.
        limits::with_test_limits(1024, limit, || {
            assert_eq!(restore_index(&mut reader, pointer).unwrap().len(), 1);
        });
        limits::with_test_limits(1024, limit - 1, || {
            assert!(restore_index(&mut reader, pointer).is_err());
        });
    }
}

#[test]
fn production_limit_arithmetic_accepts_exact_budget_and_rejects_one_over() {
    for limit in [limits::action(), limits::checkpoint()] {
        assert_eq!(limit.plaintext, 512 * 1024 * 1024);
        for padding in [0, 16, 32] {
            let encoded = limit.encoded_len(limit.plaintext, padding).unwrap();
            assert_eq!(encoded, limit.plaintext + padding);
            limit.check_encoded(encoded, padding).unwrap();
            assert!(limit.encoded_len(limit.plaintext + 1, padding).is_err());
            assert!(limit.check_encoded(encoded + 1, padding).is_err());
            if padding != 0 {
                assert!(limit.check_encoded(padding - 1, padding).is_err());
            }
        }
    }
    assert_eq!(frame_header_len(true), 296);
    assert_eq!(frame_header_len(false), 312);
    assert!(frame_len(0, u64::MAX, false).is_err());
}

#[test]
fn bounded_stream_reservation_rejects_without_taint_or_writes() {
    for encrypted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(&dir, "source", encrypted);
        let db = LogFs::<Journal2>::open_with_options(
            cfg.clone(),
            LogOpenOptions {
                region_len: Some(V3_HEADER_SIZE + 500),
                ..Default::default()
            },
        )
        .unwrap();
        let before = std::fs::read(&cfg.path).unwrap();
        assert!(db.insert_writer("x".repeat(500)).is_err());
        assert_eq!(std::fs::read(&cfg.path).unwrap(), before);
        let mut stream = db.insert_writer("ok").unwrap();
        stream.write_all(b"value").unwrap();
        stream.finish().unwrap();
        drop(db);
        let reopened = LogFs::<Journal2>::open(cfg).unwrap();
        assert_eq!(reopened.get("ok").unwrap(), Some(b"value".to_vec()));
    }
}

#[test]
fn frozen_wire_discriminants_and_layouts() {
    use data::*;
    // These are ordinal u32 discriminants, not the Rust repr(u32) values.
    for (version, ordinal) in [
        (LogFormatVersion::V1, 0u32),
        (LogFormatVersion::V2, 1),
        (LogFormatVersion::V3, 2),
    ] {
        assert_eq!(
            crate::encoding::serialize(&version).unwrap(),
            ordinal.to_le_bytes()
        );
    }
    for (profile, ordinal) in [
        (CryptoProfile::Standard, 0u32),
        (CryptoProfile::LowMemory, 1),
    ] {
        assert_eq!(
            crate::encoding::serialize(&profile).unwrap(),
            ordinal.to_le_bytes()
        );
    }
    assert_eq!(
        crate::encoding::serialize(&CompressionFormat::Brotli).unwrap(),
        [0; 4]
    );
    let index_action = || ActionIndexWrite {
        size: 0,
        hash: Sha256Hash([0; 32]),
        compression: None,
    };
    let actions = [
        JournalAction::KeyInsert(ActionKeyInsert {
            meta: KeyMeta {
                size: 0,
                chunk_size: None,
                hash: Sha256Hash([0; 32]),
                path: String::new(),
            },
        }),
        JournalAction::KeyRename(ActionKeyRename { renames: vec![] }),
        JournalAction::KeyDelete(ActionKeyDelete {
            deleted_keys: vec![],
        }),
        JournalAction::IndexWrite(index_action()),
        JournalAction::Batch(ActionBatch {
            renames: vec![],
            deleted_keys: vec![],
        }),
        JournalAction::IndexWriteV3(index_action()),
    ];
    for (ordinal, (action, length)) in actions
        .into_iter()
        .zip([53, 12, 12, 45, 20, 45])
        .enumerate()
    {
        let mut expected = vec![0; length];
        expected[..4].copy_from_slice(&(ordinal as u32).to_le_bytes());
        assert_eq!(crate::encoding::serialize(&action).unwrap(), expected);
    }
    let frame = V3FrameHeader {
        header: JournalEntryHeader {
            offset: 8192,
            sequence_id: SequenceId::first(),
            action_size: 77,
            flags: JournalEntryHeaderFlags::empty(),
        },
        previous_history: [0x11; 32],
        history: [0x22; 32],
    };
    let mut expected_frame = Vec::new();
    expected_frame.extend_from_slice(&8192u64.to_le_bytes());
    expected_frame.extend_from_slice(&1u64.to_le_bytes());
    expected_frame.extend_from_slice(&77u32.to_le_bytes());
    expected_frame.extend_from_slice(&0u32.to_le_bytes());
    expected_frame.extend_from_slice(&[0x11; 32]);
    expected_frame.extend_from_slice(&[0x22; 32]);
    assert_eq!(crate::encoding::serialize(&frame).unwrap(), expected_frame);
    assert_eq!(expected_frame.len(), 88);

    let payload = root::V3RootPayload {
        magic: V3_INNER_MAGIC,
        version: 3,
        profile: CryptoProfile::LowMemory,
        identity: [0x33; 16],
        slot: 0,
        generation: 2,
        block: Superblock {
            format_version: LogFormatVersion::V3,
            flags: SuperblockFlags::empty(),
            active_sequence: 0,
            tail_offset: 8192,
            last_index_entry: None,
        },
        log_secret: [0x44; 32],
        root_salts: [[0x55; 16], [0x66; 16]],
        history: [0; 32],
        checkpoint_history: [0; 32],
    };
    let mut expected = b"LOGFS-OPAQUE-V3\0".to_vec();
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&[0x33; 16]);
    expected.push(0);
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&8192u64.to_le_bytes());
    expected.push(0);
    expected.extend_from_slice(&[0x44; 32]);
    expected.extend_from_slice(&[0x55; 16]);
    expected.extend_from_slice(&[0x66; 16]);
    expected.extend_from_slice(&[0; 64]);
    assert_eq!(crate::encoding::serialize(&payload).unwrap(), expected);
    assert_eq!(expected.len(), 202);
}
