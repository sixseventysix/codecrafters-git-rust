use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use flate2::read::ZlibDecoder;

fn main() {
    if let Err(err) = run() {
        eprintln!("fatal: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("no command provided");
    }

    match args[1].as_str() {
        "init" => {
            init_repo()?;
            println!("Initialized git directory");
        }
        "cat-file" => {
            if args.len() < 4 || args[2].as_str() != "-p" {
                bail!("usage: cat-file -p <hash>");
            }
            cat_file_print(&args[3])?;
        }
        other => {
            println!("unknown command: {}", other);
        }
    }

    Ok(())
}

fn init_repo() -> Result<()> {
    create_dir_if_missing(".git").context("creating .git directory")?;
    create_dir_if_missing(".git/objects").context("creating .git/objects directory")?;
    create_dir_if_missing(".git/refs").context("creating .git/refs directory")?;
    fs::write(".git/HEAD", "ref: refs/heads/main\n").context("writing .git/HEAD")?;
    Ok(())
}

fn cat_file_print(object_hash: &str) -> Result<()> {
    if object_hash.len() < 3 {
        bail!("object hash must be at least 3 characters");
    }

    let (dir, file) = object_hash.split_at(2);
    let mut path = PathBuf::from(".git/objects");
    path.push(dir);
    path.push(file);

    let file =
        File::open(&path).with_context(|| format!("opening object file at {}", path.display()))?;
    let mut decoder = ZlibDecoder::new(file);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .with_context(|| format!("decompressing object {}", object_hash))?;

    let null_index = decompressed
        .iter()
        .position(|&byte| byte == 0)
        .context("invalid blob: missing header")?;

    let content = &decompressed[null_index + 1..];
    let mut stdout = io::stdout();
    stdout
        .write_all(content)
        .with_context(|| format!("writing blob {} to stdout", object_hash))?;
    stdout.flush().context("flushing stdout")?;
    Ok(())
}

fn create_dir_if_missing(path: &str) -> Result<()> {
    match fs::create_dir(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err.into()),
    }
}
