use std::{
    io::{Read, Write},
    num::NonZeroU32,
};

use structopt::StructOpt;

#[derive(StructOpt)]
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
    Set {
        key: String,
        /// The value to set for the key.
        /// Use '-' for stdin.
        value: String,
    },
    Delete {
        key: String,
    },
    Migrate {
        #[structopt(long)]
        new_path: Option<String>,
        #[structopt(long)]
        new_key: Option<String>,
        #[structopt(long)]
        new_salt: Option<String>,
        #[structopt(long)]
        new_iterations: Option<u32>,
    },
}

#[derive(StructOpt)]
struct Options {
    #[structopt(short, long)]
    path: String,
    #[structopt(long)]
    create: bool,
    #[structopt(long)]
    raw: bool,
    #[structopt(short, long)]
    key: Option<String>,
    #[structopt(long)]
    salt: Option<String>,
    #[structopt(long)]
    key_iterations: Option<u32>,

    #[structopt(long)]
    version: u32,

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
    let db = logfs::LogFs::<J>::open(opt.build_config())?;

    match opt.cmd {
        Subcommand::List { offset, max } => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();

            for path in db.paths_offset(offset.unwrap_or_default(), max.unwrap_or(1000))? {
                write!(&mut lock, "{}\n", path).unwrap();
            }

            Ok(())
        }
        Subcommand::Get { key } => match db.get(&key) {
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
        },
        Subcommand::Set { key, value } => {
            if value == "-" {
                let mut buffer = Vec::new();
                std::io::stdin().read_to_end(&mut buffer)?;
                db.insert(key, buffer)
            } else {
                db.insert(key, value.into_bytes())
            }
        }
        Subcommand::Delete { key } => {
            if db.get(&key).is_ok() {
                db.remove(&key)?;
                eprintln!("Key '{}' deleted", key);
            } else {
                eprintln!("Error: Key '{}' does not exist", key);
                std::process::exit(1);
            }
            Ok(())
        }
        Subcommand::Migrate { .. } => {
            unimplemented!()
        }
    }
}

fn main() -> Result<(), logfs::LogFsError> {
    let opt = Options::from_args();

    if let Subcommand::Migrate { .. } = &opt.cmd {
        if opt.version == 2 {
            eprintln!("Nothing to migrate");
            Ok(())
        } else {
            panic!("Unsupported version {}", opt.version);
        }
    } else {
        if opt.version == 1 {
            run::<logfs::Journal2>(opt)
        } else if opt.version == 2 {
            run::<logfs::Journal2>(opt)
        } else {
            panic!("Unsupported version {}", opt.version);
        }
    }
}
