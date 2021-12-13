use std::{
    io::{Read, Write},
    num::NonZeroU32,
};

use structopt::StructOpt;

#[derive(StructOpt, Clone)]
enum Subcommand {
    List {
        #[structopt(short, long)]
        offset: Option<usize>,
        #[structopt(short, long)]
        max: Option<usize>,
    },
    Get {
        key: String,
    },
    Search {
        text: String,
        #[structopt(long)]
        keys_only: bool,
        #[structopt(long)]
        delete: bool,
    },
    Set {
        key: String,
        /// The value to set for the key.
        /// Use '-' for stdin.
        value: String,
    },
    Delete {
        keys: Vec<String>,
    },
    Migrate {
        // Commented out because there currently is only one log version in the
    // codebase.
    // #[structopt(long)]
    // new_path: Option<String>,
    // #[structopt(long)]
    // new_key: Option<String>,
    // #[structopt(long)]
    // new_salt: Option<String>,
    // #[structopt(long)]
    // new_iterations: Option<u32>,
    },
    Repair {
        #[structopt(long)]
        overwrite: bool,
        #[structopt(long)]
        start_sequence: Option<u64>,
        #[structopt(long)]
        skip_bytes: Option<u64>,
        #[structopt(long)]
        recovery_path: Option<String>,
    },
}

#[derive(StructOpt, Clone)]
struct Options {
    #[structopt(short, long)]
    path: String,
    #[structopt(long)]
    create: bool,
    /// Enables raw mode, which allows using raw block devices without a filesystem.
    #[structopt(long)]
    raw: bool,
    #[structopt(short, long)]
    key: Option<String>,
    #[structopt(long)]
    salt: Option<String>,
    #[structopt(long)]
    key_iterations: Option<u32>,

    #[structopt(long)]
    version: Option<u32>,

    #[structopt(subcommand)]
    cmd: Subcommand,
}

impl Options {
    fn build_config(&self) -> logfs::LogConfig {
        logfs::LogConfig {
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

                if s.contains(&text) {
                    if delete {
                        db.remove(&key)?;
                        eprintln!("Deleted: {key}\n");
                    }
                    if keys_only {
                        print!("{key} ");
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
        Subcommand::Delete { keys } => {
            let db = logfs::LogFs::<J>::open(opt.build_config())?;

            for key in keys {
                if db.get(&key).is_ok() {
                    db.remove(&key)?;
                    eprintln!("Key '{}' deleted", key);
                } else {
                    eprintln!("Error: Key '{}' does not exist", key);
                    std::process::exit(1);
                }
            }

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
    }
}

fn main() -> Result<(), logfs::LogFsError> {
    let opt = Options::from_args();

    let version = opt.version.unwrap_or(2);
    if version == 2 {
        run::<logfs::Journal2>(opt)
    } else {
        panic!("Unsupported version {}", version);
    }
}
