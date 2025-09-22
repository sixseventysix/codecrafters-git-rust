use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
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
    #[command(name = "write-tree")]
    WriteTree,
    #[command(name = "commit-tree")]
    CommitTree {
        #[arg(value_name = "TREE_SHA")]
        tree: String,
        #[arg(short = 'p', value_name = "PARENT_SHA")]
        parent: String,
        #[arg(short = 'm', value_name = "MESSAGE")]
        message: String,
    },
}

struct TreeEntry {
    mode: String,
    name: String,
    hash: String,
}

const DEFAULT_AUTHOR_NAME: &str = "_default";
const DEFAULT_AUTHOR_EMAIL: &str = "default@something.com";
const DEFAULT_TIMEZONE: &str = "+0000";

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
        Commands::WriteTree => {
            let hash = write_workdir_tree()?;
            println!("{hash}");
        }
        Commands::CommitTree {
            tree,
            parent,
            message,
        } => {
            let hash = commit_tree(&tree, &parent, &message)?;
            println!("{hash}");
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

    let (object_data, hash) = build_object_data("blob", &file_contents);

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

fn write_workdir_tree() -> Result<String> {
    let cwd = std::env::current_dir().context("determining current directory")?;
    write_tree_recursive(&cwd)
}

fn commit_tree(tree: &str, parent: &str, message: &str) -> Result<String> {
    ensure_valid_sha(tree, "tree")?;
    ensure_valid_sha(parent, "parent")?;
    if message.contains('\n') {
        bail!("commit message must be a single line");
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX epoch")?
        .as_secs();

    let mut content = String::new();
    content.push_str(&format!("tree {tree}\n"));
    content.push_str(&format!("parent {parent}\n"));
    let signature = format!(
        "{} <{}> {} {}\n",
        DEFAULT_AUTHOR_NAME, DEFAULT_AUTHOR_EMAIL, timestamp, DEFAULT_TIMEZONE
    );
    content.push_str("author ");
    content.push_str(&signature);
    content.push_str("committer ");
    content.push_str(&signature);
    content.push('\n');
    content.push_str(message);
    content.push('\n');

    let content_bytes = content.into_bytes();
    let (object_data, hash) = build_object_data("commit", &content_bytes);
    write_object(&hash, &object_data)?;
    Ok(hash)
}

fn write_tree_recursive(dir: &Path) -> Result<String> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let dir_display = dir.display().to_string();
    for entry in fs::read_dir(dir)
        .with_context(|| format!("reading directory {dir_display}"))?
    {
        let entry = entry.with_context(|| format!("reading entry in {dir_display}"))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name
            .to_str()
            .ok_or_else(|| anyhow!("file name in {} is not valid UTF-8", dir_display))?
            .to_owned();

        if name == ".git" {
            continue;
        }

        let metadata = entry
            .metadata()
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if metadata.is_dir() {
            let hash = write_tree_recursive(&path)?;
            entries.push(TreeEntry {
                mode: "40000".to_string(),
                name,
                hash,
            });
        } else if metadata.is_file() {
            let hash = write_blob(&path)?;
            entries.push(TreeEntry {
                mode: "100644".to_string(),
                name,
                hash,
            });
        }
    }

    entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let mut body = Vec::new();
    for entry in &entries {
        body.extend_from_slice(entry.mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(entry.name.as_bytes());
        body.push(0);
        let sha_bytes = hex_to_bytes(&entry.hash)?;
        body.extend_from_slice(&sha_bytes);
    }

    let (object_data, hash) = build_object_data("tree", &body);
    write_object(&hash, &object_data)?;
    Ok(hash)
}

fn write_blob(path: &Path) -> Result<String> {
    let file_contents = fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let (object_data, hash) = build_object_data("blob", &file_contents);
    write_object(&hash, &object_data)?;
    Ok(hash)
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

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        bail!("hex string has odd length");
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = (chunk[0] as char)
            .to_digit(16)
            .with_context(|| format!("invalid hex digit '{}'", chunk[0] as char))?;
        let low = (chunk[1] as char)
            .to_digit(16)
            .with_context(|| format!("invalid hex digit '{}'", chunk[1] as char))?;
        bytes.push(((high << 4) | low) as u8);
    }

    Ok(bytes)
}

fn build_object_data(object_type: &str, content: &[u8]) -> (Vec<u8>, String) {
    let header = format!("{object_type} {}\0", content.len());
    let mut object_data = Vec::with_capacity(header.len() + content.len());
    object_data.extend_from_slice(header.as_bytes());
    object_data.extend_from_slice(content);

    let mut hasher = Sha1::new();
    hasher.update(&object_data);
    let hash_bytes = hasher.finalize();
    let hash = bytes_to_hex(&hash_bytes);

    (object_data, hash)
}

fn ensure_valid_sha(sha: &str, context: &str) -> Result<()> {
    if sha.len() != 40 {
        bail!("{context} hash must be 40 hex characters");
    }

    hex_to_bytes(sha).with_context(|| format!("invalid {context} hash"))?;
    Ok(())
}
