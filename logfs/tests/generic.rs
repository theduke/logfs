use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use logfs::{
    Batch, ConfigBuilder, Crypto, JournalRepairConfig, JournalStore, KeyChunkIter, KeyLock,
    KeyPointer, KeyWriter, LogConfig, LogFs, LogFsError, SharedTree, StdKeyReader, Superblock,
};

struct DownstreamStore;

impl JournalStore for DownstreamStore {
    fn open(
        _path: PathBuf,
        _tree: SharedTree,
        _crypto: Option<Arc<Crypto>>,
        _config: &LogConfig,
    ) -> Result<Self, LogFsError> {
        Ok(Self)
    }

    fn repair(
        _config: &LogConfig,
        _crypto: Option<Arc<Crypto>>,
        _repair: JournalRepairConfig,
    ) -> Result<(), LogFsError> {
        Ok(())
    }

    fn write_batch(&self, _batch: Batch) -> Result<(), LogFsError> {
        unimplemented!()
    }
    fn write_insert(&self, _path: String, _data: Vec<u8>) -> Result<KeyPointer, LogFsError> {
        unimplemented!()
    }
    fn insert_writer(
        &self,
        _path: String,
        _tree: SharedTree,
        _lock: KeyLock,
    ) -> Result<KeyWriter, LogFsError> {
        unimplemented!()
    }
    fn write_rename(&self, _old: String, _new: String) -> Result<(), LogFsError> {
        unimplemented!()
    }
    fn write_remove(&self, _paths: Vec<String>) -> Result<(), LogFsError> {
        unimplemented!()
    }
    fn write_index(
        &self,
        _tree: &BTreeMap<String, KeyPointer>,
        _full: bool,
    ) -> Result<(), LogFsError> {
        unimplemented!()
    }
    fn read_data(&self, _pointer: &KeyPointer) -> Result<Vec<u8>, LogFsError> {
        unimplemented!()
    }
    fn reader(&self, _pointer: &KeyPointer) -> Result<StdKeyReader, LogFsError> {
        unimplemented!()
    }
    fn read_chunks(&self, _pointer: &KeyPointer) -> Result<KeyChunkIter, LogFsError> {
        unimplemented!()
    }
    fn size_log(&self) -> Result<u64, LogFsError> {
        unimplemented!()
    }
    fn supberlock(&self) -> Result<Superblock, LogFsError> {
        unimplemented!()
    }
}

#[test]
fn downstream_config_literal_and_journal_store_still_compile() {
    let config = LogConfig {
        path: PathBuf::from("unused"),
        raw_mode: false,
        offset: None,
        allow_create: false,
        crypto: None,
        default_chunk_size: 4096,
        partial_index_write_interval: 0,
        full_index_write_interval: 0,
        readonly: true,
    };
    let _log = LogFs::<DownstreamStore>::open(config).expect("open downstream store");
}

/// Regression test for a deadlock issue.
///
/// Makes sure that subsequent writes complete.
#[test]
fn superblock_leaves_writer_available() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let log_path = tempdir.path().join("logfs.journal");

    let log = ConfigBuilder::new(&log_path)
        .allow_create()
        .open()
        .expect("open log");

    log.insert("initial", b"data".to_vec())
        .expect("initial insert");
    log.superblock().expect("read superblock");

    let (tx, rx) = mpsc::channel();
    let log_clone = log.clone();
    let handle = thread::spawn(move || {
        log_clone
            .insert("after", b"more".to_vec())
            .expect("insert after superblock");
        tx.send(()).expect("signal completion");
    });

    if let Err(err) = rx.recv_timeout(Duration::from_secs(1)) {
        panic!("insert after superblock did not finish: {err:?}");
    }

    handle.join().expect("writer thread");
}
