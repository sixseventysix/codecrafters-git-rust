use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};

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
        "hash-object" => {
            if args.len() < 3 {
                bail!("usage: hash-object [-w] <path>");
            }

            let mut arg_index = 2;
            let mut write = false;
            if args[arg_index].as_str() == "-w" {
                write = true;
                arg_index += 1;
            }

            if arg_index >= args.len() {
                bail!("usage: hash-object [-w] <path>");
            }

            let object_path = &args[arg_index];
            let hash = hash_object(object_path, write)?;
            println!("{hash}");
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

    let file = File::open(&path)
        .with_context(|| format!("opening object file at {}", path.display()))?;
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

fn hash_object(path: &str, write: bool) -> Result<String> {
    let file_contents = fs::read(path).with_context(|| format!("reading {path}"))?;

    let header = format!("blob {}\0", file_contents.len());
    let mut object_data = Vec::with_capacity(header.len() + file_contents.len());
    object_data.extend_from_slice(header.as_bytes());
    object_data.extend_from_slice(&file_contents);

    let mut hasher = Sha1::new();
    hasher.update(&object_data);
    let hash_bytes = hasher.finalize();
    let hash = bytes_to_hex(&hash_bytes);

    if write {
        write_object(&hash, &object_data)?;
    }

    Ok(hash)
}

fn write_object(object_hash: &str, data: &[u8]) -> Result<()> {
    if object_hash.len() < 3 {
        bail!("object hash must be at least 3 characters");
    }

    let (dir, file) = object_hash.split_at(2);
    let mut dir_path = PathBuf::from(".git/objects");
    dir_path.push(dir);
    fs::create_dir_all(&dir_path)
        .with_context(|| format!("creating object directory {}", dir_path.display()))?;

    let mut object_path = dir_path;
    object_path.push(file);

    if object_path.exists() {
        return Ok(());
    }

    let file = File::create(&object_path)
        .with_context(|| format!("creating object file {}", object_path.display()))?;
    let mut encoder = ZlibEncoder::new(file, Compression::default());
    encoder
        .write_all(data)
        .with_context(|| format!("compressing object {}", object_hash))?;
    let _ = encoder
        .finish()
        .with_context(|| format!("finalizing object {}", object_hash))?;
    Ok(())
}

fn create_dir_if_missing(path: &str) -> Result<()> {
    match fs::create_dir(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
