#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use omnisstream::{Manifest, PartStore, Reader};

#[derive(Debug, Parser)]
#[command(name = "omnisstream")]
struct Cli {
    /// Repository root (used for digest-addressed parts via `repo/parts/`).
    #[arg(long, global = true)]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reconstruct object bytes (requires `compression=none`).
    Cat { manifest: PathBuf },

    /// Verify stored payload bytes against manifest hashes.
    Verify { manifest: PathBuf },

    /// Read an object byte range (requires `compression=none`).
    Range {
        manifest: PathBuf,
        offset: u64,
        len: u64,
    },

    /// Print a stable, human-readable manifest summary.
    Inspect { manifest: PathBuf },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,omnisstream=info".to_string()),
        )
        .init();

    let cli = Cli::parse();
    let repo_root = cli.repo.clone();

    match cli.command {
        Command::Cat { manifest } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(repo_root.as_deref(), manifest, &manifest_path)?;
            let mut stdout = std::io::stdout().lock();
            reader.cat(&mut stdout)?;
        }
        Command::Verify { manifest } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(repo_root.as_deref(), manifest, &manifest_path)?;
            let summary = reader.verify()?;
            eprintln!("ok: parts={} bytes={}", summary.parts, summary.bytes);
        }
        Command::Range {
            manifest,
            offset,
            len,
        } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(repo_root.as_deref(), manifest, &manifest_path)?;
            let mut stdout = std::io::stdout().lock();
            reader.range(offset, len, &mut stdout)?;
        }
        Command::Inspect { manifest } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            print!("{}", manifest.inspect());
        }
    }

    Ok(())
}

fn load_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let bytes = std::fs::read(path)?;
    Ok(Manifest::from_pb_bytes(&bytes)?)
}

fn reader_for_manifest(
    repo_root: Option<&Path>,
    manifest: Manifest,
    manifest_path: &Path,
) -> anyhow::Result<Reader> {
    let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut reader = Reader::new(manifest, base_dir);

    if reader.manifest().needs_part_store() {
        let repo = repo_root.unwrap_or_else(|| Path::new("."));
        let part_store = PartStore::new(repo.join("parts"))?;
        reader = reader.with_part_store(part_store);
    }

    Ok(reader)
}
