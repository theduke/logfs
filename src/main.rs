use std::{
    io::{Read, Write},
    num::NonZeroU32,
};

use logfs::{CryptoConfig, KeyMeta, LogConfig};

use clap::Parser;

#[derive(clap::Subcommand, Clone)]
enum Subcommand {
    List {
        #[clap(short, long)]
        offset: Option<usize>,
        #[clap(short, long)]
        max: Option<usize>,
    },
    Get {
        key: String,
    },
    Search {
        text: String,
        #[clap(long)]
        keys_only: bool,
        #[clap(long)]
        delete: bool,
    },
    Set {
        key: String,
        /// The value to set for the key.
        /// Use '-' for stdin.
        value: String,
    },
    Delete {
        #[clap(short, long)]
        prefix: bool,
        keys: Vec<String>,
    },
    /// Replace a matching text with the given replacement in all keys that start with the given prefix.
    TextMatchReplace {
        #[clap(long)]
        key_prefix: String,
        match_text: String,
        replacement: String,
    },
    /// Compat the log into a new location.
    Compact {
        #[clap(long)]
        new_path: String,
        #[clap(long)]
        new_key: String,
        #[clap(long)]
        new_salt: String,
        #[clap(long)]
        new_key_iterations: u32,
        new_offset: Option<u64>,
    },
    Migrate {
        // Commented out because there currently is only one log version in the
        // codebase.
        // #[clap(long)]
        // new_path: Option<String>,
        // #[clap(long)]
        // new_key: Option<String>,
        // #[clap(long)]
        // new_salt: Option<String>,
        // #[clap(long)]
        // new_iterations: Option<u32>,
    },
    Repair {
        #[clap(long)]
        overwrite: bool,
        #[clap(long)]
        start_sequence: Option<u64>,
        #[clap(long)]
        skip_bytes: Option<u64>,
        #[clap(long)]
        recovery_path: Option<String>,
    },
}

#[derive(clap::Parser, Clone)]
struct Options {
    #[clap(short, long)]
    path: String,
    #[clap(long)]
    create: bool,
    /// Enables raw mode, which allows using raw block devices without a filesystem.
    #[clap(long)]
    raw: bool,
    /// Byte offset in the target  file. DB starts at the given offset.
    #[clap(long)]
    offset: Option<u64>,

    #[clap(short, long)]
    key: Option<String>,
    #[clap(long)]
    salt: Option<String>,
    #[clap(long)]
    key_iterations: Option<u32>,

    #[clap(long)]
    version: Option<u32>,

    #[clap(subcommand)]
    cmd: Subcommand,
}

impl Options {
    fn build_config(&self) -> logfs::LogConfig {
        logfs::LogConfig {
            offset: self.offset,
            path: self.path.clone().into(),
            raw_mode: self.raw,
            allow_create: self.create,
            crypto: self.key.as_ref().map(|key| logfs::CryptoConfig {
                key: zeroize::Zeroizing::new(key.to_string()),
                salt: self
                    .salt
                    .as_ref()
                    .map(|s| zeroize::Zeroizing::new(s.clone().into_bytes()))
                    .unwrap_or(zeroize::Zeroizing::new(b"logfs".to_vec())),
                iterations: self
                    .key_iterations
                    .as_ref()
                    .map(|v| NonZeroU32::new(*v).unwrap())
                    .unwrap_or(NonZeroU32::new(100_000).unwrap()),
            }),
            default_chunk_size: 4_000_000,
            partial_index_write_interval: 100,
            full_index_write_interval: 10_000,
        }
    }
}

fn pretty_value(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_string(),
        Err(_) => format!("{:x?}", value),
    }
}

fn run<J: logfs::JournalStore>(opt: Options) -> Result<(), logfs::LogFsError> {
    match opt.cmd.clone() {
        Subcommand::List { offset, max } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();

            for path in db.paths_offset(offset.unwrap_or_default(), max.unwrap_or(1000))? {
                write!(&mut lock, "{}\n", path).unwrap();
            }

            Ok(())
        }
        Subcommand::Get { key } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            match db.get(&key) {
                Ok(Some(value)) => {
                    println!("{}", pretty_value(&value));
                    Ok(())
                }
                Ok(None) => {
                    eprintln!("Key '{}' not found", key);
                    std::process::exit(1);
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Subcommand::Search {
            text,
            keys_only,
            delete,
        } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            for key in db.paths_range(..)? {
                let meta = db.get_meta(&key)?.unwrap();
                if meta.size > 100_000 {
                    continue;
                }
                let content = db.get(&key)?.unwrap();
                let s = String::from_utf8_lossy(&content);

                if key.contains(&text) || s.contains(&text) {
                    if delete {
                        db.remove(&key)?;
                        eprintln!("Deleted: {key}");
                    }
                    if keys_only {
                        print!("{key}\n");
                    } else {
                        eprintln!("Match {key}:\n{s}\n\n");
                    }
                }
            }

            Ok(())
        }
        Subcommand::Set { key, value } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            if value == "-" {
                let mut buffer = Vec::new();
                std::io::stdin().read_to_end(&mut buffer)?;
                db.insert(key, buffer)
            } else {
                db.insert(key, value.into_bytes())
            }
        }
        Subcommand::Delete { prefix, keys } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            if prefix {
                for key in keys {
                    eprintln!("Deleting keys with prefix '{key}'...");
                    db.remove_prefix(&key)?;
                }
            } else {
                for key in keys {
                    if db.get(&key).is_ok() {
                        db.remove(&key)?;
                        eprintln!("Key '{}' deleted", key);
                    } else {
                        eprintln!("Error: Key '{}' does not exist", key);
                        std::process::exit(1);
                    }
                }
            }

            eprintln!("Complete!");

            Ok(())
        }
        Subcommand::Migrate { .. } => {
            eprintln!("Nothing to migrate");
            Ok(())
        }
        Subcommand::Repair {
            overwrite,
            start_sequence,
            recovery_path,
            skip_bytes,
        } => {
            std::env::set_var("RUST_LOG", "logfs=trace");
            tracing_subscriber::fmt::init();

            let config = opt.build_config();
            let dry_run = !overwrite;
            let r = logfs::RepairConfig {
                dry_run,
                start_sequence,
                recovery_path: recovery_path.map(std::path::PathBuf::from),
                skip_bytes,
            };
            logfs::LogFs::<logfs::Journal2>::repair(config, r)
        }
        Subcommand::Compact {
            new_path,
            new_key,
            new_salt,
            new_key_iterations,
            new_offset,
        } => {
            eprintln!("Opening old database...");
            let old_db = logfs::LogFs::<J>::open(opt.build_config())?;

            eprintln!("Creating new database...");

            let sequence = old_db.superblock()?.active_sequence;

            let new_config = LogConfig {
                path: new_path.into(),
                raw_mode: false,
                offset: new_offset,
                allow_create: true,
                crypto: Some(CryptoConfig {
                    key: new_key.into(),
                    salt: new_salt.into_bytes().into(),
                    iterations: NonZeroU32::new(new_key_iterations)
                        .expect("iterations must be > 0"),
                }),
                default_chunk_size: 4_000_000,
                // There is no point in writing intermediate indexes, so set the
                // intervals to the current sequence count.
                partial_index_write_interval: sequence,
                full_index_write_interval: sequence,
            };

            let new_db =
                logfs::LogFs::<J>::open(new_config).expect("Could not open new database...");
            let all_keys = old_db.paths_range(..).expect("Could not obtain old keys");

            let keys_plus_size: Vec<(String, KeyMeta)> = all_keys
                .into_iter()
                .map(|key| {
                    let meta = old_db.get_meta(&key).unwrap().unwrap();
                    (key, meta)
                })
                .collect();

            let total_size: u64 = keys_plus_size.iter().map(|(_, m)| m.size).sum();
            let total_count = keys_plus_size.len();

            eprintln!(
                "copying {} keys with a total size of {}",
                total_count, total_size
            );

            let mut finished_size = 0.0;
            let total_size = total_size as f64;
            for (index, (key, meta)) in keys_plus_size.into_iter().enumerate() {
                eprintln!(
                    "count: {}/{} total_size_pct: {} - {}",
                    index + 1,
                    total_count,
                    ((finished_size / total_size) * 10000.0).round() / 100.0,
                    key
                );

                // Keys smaller than 100mb: just load them into memory
                if meta.size < 100_000_000 {
                    let value = old_db.get(&key).unwrap().unwrap();
                    new_db.insert(key, value).unwrap();
                } else {
                    let mut reader = old_db.get_reader(&key).unwrap();
                    let mut writer = new_db.insert_writer(&key).unwrap();
                    std::io::copy(&mut reader, &mut writer).unwrap();
                }

                finished_size += meta.size as f64;
            }

            eprintln!("Complete!");

            Ok(())
        }
        Subcommand::TextMatchReplace {
            key_prefix,
            match_text,
            replacement,
        } => {
            eprintln!("Opening database...");
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            eprintln!(
                "Replacing '{match_text}' with '{replacement}' in keys starting with '{key_prefix}"
            );
            let mut count = 0;
            for key in db.paths_prefix(&key_prefix)? {
                let content = db.get(&key)?.unwrap();

                if let Ok(s) = String::from_utf8(content) {
                    if s.contains(&match_text) {
                        let new = s.replace(&match_text, &replacement);
                        eprintln!("Replacing in key '{key}'");
                        db.insert(key, new.into_bytes())?;
                        count += 1;
                    }
                }
            }

            eprintln!("Replaced '{match_text}' with '{replacement}' in {count} objects");
            Ok(())
        }
    }
}

fn main() -> Result<(), logfs::LogFsError> {
    let opt = Options::from_args();

    tracing_subscriber::fmt::init();

    let version = opt.version.unwrap_or(2);
    if version == 2 {
        run::<logfs::Journal2>(opt)
    } else {
        panic!("Unsupported version {}", version);
    }
}
