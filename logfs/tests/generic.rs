use std::{sync::mpsc, thread, time::Duration};

use logfs::ConfigBuilder;

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
