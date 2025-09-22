use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};

#[derive(Parser)]
#[command(name = "codecrafters-git", version, about = "Codecrafters Git implementation", disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    #[command(name = "cat-file")]
    CatFile {
        #[arg(short = 'p')]
        pretty: bool,
        #[arg(value_name = "HASH")]
        hash: String,
    },
    #[command(name = "hash-object")]
    HashObject {
        #[arg(short = 'w')]
        write: bool,
        #[arg(value_name = "PATH")]
        path: String,
    },
    #[command(name = "ls-tree")]
    LsTree {
        #[arg(long = "name-only")]
        name_only: bool,
        #[arg(value_name = "HASH")]
        hash: String,
    },
}

struct TreeEntry {
    mode: String,
    name: String,
    hash: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("fatal: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            init_repo()?;
            println!("Initialized git directory");
        }
        Commands::CatFile { pretty, hash } => {
            if !pretty {
                bail!("usage: cat-file -p <hash>");
            }
            cat_file_print(&hash)?;
        }
        Commands::HashObject { write, path } => {
            let hash = hash_object(&path, write)?;
            println!("{hash}");
        }
        Commands::LsTree { name_only, hash } => {
            ls_tree(&hash, name_only)?;
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
    let data = read_object_bytes(object_hash)?;
    let (object_type, _, content) = parse_object(&data)?;
    if object_type != "blob" {
        bail!("object {object_hash} is not a blob");
    }

    let mut stdout = io::stdout();
    stdout
        .write_all(content)
        .with_context(|| format!("writing blob {object_hash} to stdout"))?;
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

fn ls_tree(object_hash: &str, name_only: bool) -> Result<()> {
    let data = read_object_bytes(object_hash)?;
    let (object_type, _, body) = parse_object(&data)?;
    if object_type != "tree" {
        bail!("object {object_hash} is not a tree");
    }

    let entries = parse_tree_entries(body)?;

    for entry in entries {
        if name_only {
            println!("{}", entry.name);
        } else {
            let object_type = if entry.mode == "40000" { "tree" } else { "blob" };
            let mode = if entry.mode.len() < 6 {
                format!("{:0>6}", entry.mode)
            } else {
                entry.mode.clone()
            };
            println!("{mode} {object_type} {}\t{}", entry.hash, entry.name);
        }
    }

    Ok(())
}

fn parse_tree_entries(body: &[u8]) -> Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        let mode_end = body[cursor..]
            .iter()
            .position(|&b| b == b' ')
            .context("tree entry missing space after mode")?;
        let mode_bytes = &body[cursor..cursor + mode_end];
        let mode = std::str::from_utf8(mode_bytes)
            .context("tree entry mode is not valid UTF-8")?
            .to_string();
        cursor += mode_end + 1; // skip space

        let name_end = body[cursor..]
            .iter()
            .position(|&b| b == 0)
            .context("tree entry missing null terminator after name")?;
        let name_bytes = &body[cursor..cursor + name_end];
        let name = std::str::from_utf8(name_bytes)
            .context("tree entry name is not valid UTF-8")?
            .to_string();
        cursor += name_end + 1; // skip null terminator

        if cursor + 20 > body.len() {
            bail!("tree entry for {name} is truncated");
        }
        let sha_bytes = &body[cursor..cursor + 20];
        cursor += 20;

        entries.push(TreeEntry {
            mode,
            name,
            hash: bytes_to_hex(sha_bytes),
        });
    }

    Ok(entries)
}

fn read_object_bytes(object_hash: &str) -> Result<Vec<u8>> {
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
    Ok(decompressed)
}

fn parse_object<'a>(data: &'a [u8]) -> Result<(&'a str, usize, &'a [u8])> {
    let header_end = data
        .iter()
        .position(|&byte| byte == 0)
        .context("object missing header terminator")?;
    let header = std::str::from_utf8(&data[..header_end])
        .context("object header is not valid UTF-8")?;
    let mut parts = header.split(' ');
    let object_type = parts
        .next()
        .context("object header missing type")?;
    let size_str = parts
        .next()
        .context("object header missing size")?;
    let size: usize = size_str
        .parse()
        .with_context(|| format!("invalid object size: {size_str}"))?;

    let body = &data[header_end + 1..];
    if body.len() != size {
        bail!("object body size ({}) does not match header ({size})", body.len());
    }

    Ok((object_type, size, body))
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
