use std::time::Instant;

use logfs::{ConfigBuilder, ReadIntegrity};

fn main() {
    let directory = tempfile::tempdir().expect("create benchmark directory");
    let path = directory.path().join("benchmark.logfs");
    let log = ConfigBuilder::new(&path)
        .allow_create()
        .full_index_write_interval(0)
        .open()
        .expect("open benchmark log");

    let small_started = Instant::now();
    for index in 0..10_000 {
        log.insert(format!("small/{index:05}"), vec![index as u8; 128])
            .expect("write small value");
    }
    let small_elapsed = small_started.elapsed();

    let large = vec![0x5a; 32 * 1024 * 1024];
    let large_started = Instant::now();
    log.insert("large", large).expect("write large value");
    let large_write_elapsed = large_started.elapsed();

    let checkpoint_started = Instant::now();
    log.checkpoint().expect("write checkpoint");
    let checkpoint_elapsed = checkpoint_started.elapsed();

    log.set_read_integrity(ReadIntegrity::VerifyHash);
    let read_started = Instant::now();
    let bytes = log.get("large").expect("read large value").expect("value");
    let read_elapsed = read_started.elapsed();

    println!(
        "small_writes=10000 small_ms={} large_bytes={} large_write_ms={} checkpoint_ms={} verified_read_ms={}",
        small_elapsed.as_millis(),
        bytes.len(),
        large_write_elapsed.as_millis(),
        checkpoint_elapsed.as_millis(),
        read_elapsed.as_millis(),
    );
}
