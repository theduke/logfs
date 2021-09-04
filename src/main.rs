use std::io::Read;
use std::io::Write;

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
}

#[derive(StructOpt)]
struct Options {
    #[structopt(short, long)]
    path: String,
    #[structopt(short, long)]
    key: String,

    #[structopt(subcommand)]
    cmd: Subcommand,
}

fn pretty_value(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_string(),
        Err(_) => format!("{:x?}", value),
    }
}

fn run(opt: Options) -> Result<(), logfs::LogFsError> {
    let db = logfs::LogFs::open(opt.path, opt.key)?;

    match opt.cmd {
        Subcommand::List{ offset: _, max: _ } => {

            let stdout = std::io::stdout();
            let mut lock = stdout.lock();

            for path in db.paths_range(..)? {
                write!(&mut lock, "{}\n", pretty_value(&path)).unwrap();
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
    }
}

fn main() -> Result<(), logfs::LogFsError> {
    let opt = Options::from_args();
    run(opt)
}
