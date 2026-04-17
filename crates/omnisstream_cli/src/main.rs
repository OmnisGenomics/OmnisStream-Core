#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use rayon::prelude::*;

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
    /// Reconstruct object bytes from a manifest file.
    Cat { manifest: PathBuf },

    /// Reconstruct object bytes for an object id (resolves `repo/objects/<id>/latest`).
    CatObject { object_id: String },

    /// Reconstruct object bytes for an object id into a file.
    GetObject {
        object_id: String,
        out: PathBuf,

        /// Worker threads for part-parallel reconstruction (default: logical cores).
        #[arg(long)]
        jobs: Option<usize>,
    },

    /// Verify stored payload bytes against manifest hashes.
    Verify { manifest: PathBuf },

    /// Verify stored payload bytes for an object id.
    VerifyObject { object_id: String },

    /// Read an object byte range from a manifest file.
    Range {
        manifest: PathBuf,
        offset: u64,
        len: u64,
    },

    /// Read an object byte range for an object id.
    RangeObject {
        object_id: String,
        offset: u64,
        len: u64,
    },

    /// Print a stable, human-readable manifest summary.
    Inspect { manifest: PathBuf },

    /// Print a stable, human-readable manifest summary for an object id.
    InspectObject { object_id: String },

    /// Garbage-collect unreferenced parts (mark-and-sweep).
    ///
    /// Defaults to a dry run; pass `--force` to delete.
    Gc {
        /// Actually delete orphaned parts.
        #[arg(long)]
        force: bool,

        /// Print orphan part ids (one per line).
        #[arg(long)]
        print_ids: bool,
    },

    /// Print build + spec metadata.
    Version,
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
        Command::CatObject { object_id } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let manifest_path = resolve_object_manifest_path(repo_root, &object_id)?;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(Some(repo_root), manifest, &manifest_path)?;
            let mut stdout = std::io::stdout().lock();
            reader.cat(&mut stdout)?;
        }
        Command::GetObject {
            object_id,
            out,
            jobs,
        } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let manifest_path = resolve_object_manifest_path(repo_root, &object_id)?;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(Some(repo_root), manifest, &manifest_path)?;
            write_object_parallel(&reader, &out, jobs)?;
        }
        Command::Verify { manifest } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(repo_root.as_deref(), manifest, &manifest_path)?;
            let summary = reader.verify()?;
            eprintln!("ok: parts={} bytes={}", summary.parts, summary.bytes);
        }
        Command::VerifyObject { object_id } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let manifest_path = resolve_object_manifest_path(repo_root, &object_id)?;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(Some(repo_root), manifest, &manifest_path)?;
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
        Command::RangeObject {
            object_id,
            offset,
            len,
        } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let manifest_path = resolve_object_manifest_path(repo_root, &object_id)?;
            let manifest = load_manifest(&manifest_path)?;
            let reader = reader_for_manifest(Some(repo_root), manifest, &manifest_path)?;
            let mut stdout = std::io::stdout().lock();
            reader.range(offset, len, &mut stdout)?;
        }
        Command::Inspect { manifest } => {
            let manifest_path = manifest;
            let manifest = load_manifest(&manifest_path)?;
            print!("{}", manifest.inspect());
        }
        Command::InspectObject { object_id } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let manifest_path = resolve_object_manifest_path(repo_root, &object_id)?;
            let manifest = load_manifest(&manifest_path)?;
            print!("{}", manifest.inspect());
        }
        Command::Gc { force, print_ids } => {
            let repo_root = repo_root.as_deref().unwrap_or_else(|| Path::new("."));
            let stats = run_gc(repo_root, force, print_ids)?;
            eprintln!(
                "gc: referenced_parts={} total_parts={} orphan_parts={} orphan_bytes={} deleted_parts={} deleted_bytes={}",
                stats.referenced_parts,
                stats.total_parts,
                stats.orphan_parts,
                stats.orphan_bytes,
                stats.deleted_parts,
                stats.deleted_bytes
            );
            if !force {
                eprintln!("gc: dry-run (pass --force to delete)");
            }
        }
        Command::Version => {
            print_version();
        }
    }

    Ok(())
}

fn load_manifest(path: &Path) -> anyhow::Result<Manifest> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading manifest {}", path.display()))?;
    Manifest::from_pb_bytes(&bytes).with_context(|| format!("decoding manifest {}", path.display()))
}

struct OffsetWriter {
    file: Arc<File>,
    pos: u64,
}

impl OffsetWriter {
    fn new(file: Arc<File>, start: u64) -> Self {
        Self { file, pos: start }
    }
}

#[cfg(unix)]
impl Write for OffsetWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt as _;

        self.file.write_all_at(buf, self.pos)?;
        self.pos = self.pos.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl Write for OffsetWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt as _;

        let mut total = 0_usize;
        while total < buf.len() {
            let n = self.file.seek_write(&buf[total..], self.pos)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write buffered data",
                ));
            }
            self.pos = self.pos.saturating_add(n as u64);
            total = total.saturating_add(n);
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
impl Write for OffsetWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "offset writes are not supported on this platform",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_object_parallel(
    reader: &Reader,
    out_path: &Path,
    jobs: Option<usize>,
) -> anyhow::Result<()> {
    let manifest = reader.manifest();
    manifest.validate_basic()?;

    let parts: Vec<_> = manifest.part_spans().collect();
    if parts.is_empty() {
        anyhow::bail!("manifest has no parts");
    }

    let obj_len = manifest.object_length();
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let out = File::create(out_path).with_context(|| format!("creating {}", out_path.display()))?;
    out.set_len(obj_len)
        .with_context(|| format!("sizing {}", out_path.display()))?;
    let out = Arc::new(out);

    let default_jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let jobs = jobs.unwrap_or(default_jobs).max(1).min(parts.len().max(1));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("building worker pool")?;

    pool.install(|| {
        parts.par_iter().try_for_each(|p| -> anyhow::Result<()> {
            let mut w = OffsetWriter::new(Arc::clone(&out), p.offset);
            reader.range(p.offset, p.length, &mut w)?;
            Ok(())
        })
    })?;

    Ok(())
}

fn resolve_object_manifest_path(repo_root: &Path, object_id: &str) -> anyhow::Result<PathBuf> {
    use std::path::Component;

    if object_id.trim().is_empty() {
        anyhow::bail!("object_id must be non-empty");
    }

    let object_rel = Path::new(object_id);
    if object_rel.is_absolute()
        || object_rel.components().any(|c| {
            matches!(
                c,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::CurDir
                    | Component::ParentDir
            )
        })
    {
        anyhow::bail!("object_id must be a relative path without '.' or '..' segments");
    }

    let object_dir = repo_root.join("objects").join(object_rel);
    if !object_dir.is_dir() {
        anyhow::bail!("object not found: {}", object_dir.display());
    }

    let latest_path = object_dir.join("latest");
    let object_version = if latest_path.is_file() {
        std::fs::read_to_string(&latest_path)
            .with_context(|| format!("reading {}", latest_path.display()))?
            .trim()
            .to_string()
    } else {
        let versions_dir = object_dir.join("versions");
        let mut best: Option<String> = None;
        for ent in std::fs::read_dir(&versions_dir)
            .with_context(|| format!("reading {}", versions_dir.display()))?
        {
            let ent = ent?;
            let ft = ent.file_type()?;
            if !ft.is_dir() {
                continue;
            }
            let name = ent.file_name();
            let name = name.to_string_lossy();
            let candidate = name.trim().to_string();
            if candidate.is_empty() {
                continue;
            }
            if best.as_ref().is_none_or(|b| candidate > *b) {
                best = Some(candidate);
            }
        }
        best.ok_or_else(|| anyhow::anyhow!("no versions found under {}", versions_dir.display()))?
    };

    if object_version.trim().is_empty() {
        anyhow::bail!(
            "invalid latest version (empty) for object {}",
            object_dir.display()
        );
    }

    if Path::new(&object_version)
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        anyhow::bail!("invalid object version: {object_version:?}");
    }

    let manifest_path = object_dir
        .join("versions")
        .join(&object_version)
        .join("manifest.pb");
    if !manifest_path.is_file() {
        anyhow::bail!(
            "manifest not found for object {object_id:?} version {object_version:?}: {}",
            manifest_path.display()
        );
    }

    Ok(manifest_path)
}

#[derive(Debug, Clone)]
struct PartFile {
    id: String,
    path: PathBuf,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct GcStats {
    total_parts: u64,
    referenced_parts: u64,
    orphan_parts: u64,
    orphan_bytes: u64,
    deleted_parts: u64,
    deleted_bytes: u64,
}

fn find_manifest_paths(objects_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !objects_root.is_dir() {
        return Ok(out);
    }

    let mut stack = vec![objects_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for ent in std::fs::read_dir(&dir)? {
            let ent = ent?;
            let ft = ent.file_type()?;
            if ft.is_dir() {
                stack.push(ent.path());
                continue;
            }
            if ft.is_file() && ent.file_name() == "manifest.pb" {
                out.push(ent.path());
            }
        }
    }
    Ok(out)
}

fn collect_referenced_part_ids(
    repo_root: &Path,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let objects_root = repo_root.join("objects");
    let manifests = find_manifest_paths(&objects_root)
        .with_context(|| format!("scanning {}", objects_root.display()))?;

    let sets: anyhow::Result<Vec<Vec<String>>> = manifests
        .par_iter()
        .map(|p| -> anyhow::Result<Vec<String>> {
            let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            let manifest = Manifest::from_pb_bytes(&bytes)
                .with_context(|| format!("parsing {}", p.display()))?;
            Ok(manifest.part_store_digests_hex()?)
        })
        .collect();

    let mut out = std::collections::HashSet::new();
    for ids in sets? {
        out.extend(ids);
    }
    Ok(out)
}

fn list_part_files(parts_root: &Path) -> io::Result<Vec<PartFile>> {
    let mut out = Vec::new();
    if !parts_root.is_dir() {
        return Ok(out);
    }

    let mut stack = vec![parts_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for ent in std::fs::read_dir(&dir)? {
            let ent = ent?;
            let ft = ent.file_type()?;
            let path = ent.path();
            if ft.is_dir() {
                if ent.file_name() == "_tmp" {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue;
            }

            let id = ent.file_name().to_string_lossy().to_string();
            // PartStore ids are lowercase hex blake3 digests (64 chars).
            if !is_canonical_part_id(&id) {
                continue;
            }

            let bytes = ent.metadata()?.len();
            out.push(PartFile { id, path, bytes });
        }
    }

    Ok(out)
}

fn is_canonical_part_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn run_gc(repo_root: &Path, force: bool, print_ids: bool) -> anyhow::Result<GcStats> {
    let referenced = collect_referenced_part_ids(repo_root)?;
    let parts_root = repo_root.join("parts");
    let parts = list_part_files(&parts_root)
        .with_context(|| format!("scanning {}", parts_root.display()))?;

    let total_parts = parts.len() as u64;
    let referenced_parts = referenced.len() as u64;

    let orphans: Vec<_> = parts
        .into_iter()
        .filter(|p| !referenced.contains(&p.id))
        .collect();
    let orphan_parts = orphans.len() as u64;
    let orphan_bytes = orphans.iter().map(|p| p.bytes).sum();

    if print_ids {
        for p in &orphans {
            println!("{}", p.id);
        }
    }

    let mut deleted_parts = 0_u64;
    let mut deleted_bytes = 0_u64;

    if force {
        orphans.par_iter().try_for_each(|p| -> io::Result<()> {
            match std::fs::remove_file(&p.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        })?;

        deleted_parts = orphan_parts;
        deleted_bytes = orphan_bytes;

        // Best-effort cleanup: remove empty fanout directories.
        let mut dirs: Vec<_> = orphans
            .iter()
            .filter_map(|p| p.path.parent().map(|d| d.to_path_buf()))
            .collect();
        dirs.sort();
        dirs.dedup();
        for dir in dirs {
            let _ = std::fs::remove_dir(&dir);
        }
    }

    Ok(GcStats {
        total_parts,
        referenced_parts,
        orphan_parts,
        orphan_bytes,
        deleted_parts,
        deleted_bytes,
    })
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

fn print_version() {
    const SPEC_PIN: &str = include_str!("../../../SPEC_PIN.txt");

    let version = env!("CARGO_PKG_VERSION");
    let git_commit = option_env!("OMNISSTREAM_GIT_COMMIT").unwrap_or("unknown");
    let spec_pin = SPEC_PIN.trim();
    let manifest_schema = omnisstream::SUPPORTED_MANIFEST_SCHEMA;

    println!("omnisstream {version}");
    println!("git_commit {git_commit}");
    println!("spec_pin {spec_pin}");
    println!("manifest_schema {manifest_schema}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_object_manifest_path_uses_latest() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();

        let input = dir.path().join("input.bin");
        let input_bytes = b"hello omnisstream";
        std::fs::write(&input, input_bytes).unwrap();

        let res = omnisstream::ingest_file(&repo_root, &input, 5).unwrap();
        let resolved = resolve_object_manifest_path(&repo_root, &res.object_id).unwrap();
        assert_eq!(resolved, res.manifest_path);

        let manifest = load_manifest(&resolved).unwrap();
        let reader = reader_for_manifest(Some(&repo_root), manifest, &resolved).unwrap();
        let mut out = Vec::new();
        reader.cat(&mut out).unwrap();
        assert_eq!(out, input_bytes);
    }

    #[test]
    fn resolve_object_manifest_path_rejects_absolute_ids() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();

        let err = resolve_object_manifest_path(&repo_root, "/etc/passwd").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("relative path"), "{msg}");
    }

    #[test]
    fn load_manifest_missing_file_error_includes_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.pb");

        let err = load_manifest(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("reading manifest"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn load_manifest_decode_error_includes_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pb");
        std::fs::write(&path, [0x0a_u8, 0xff]).unwrap();

        let err = load_manifest(&path).unwrap_err();
        let msg = format!("{err:#}");

        assert!(msg.contains("decoding manifest"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn get_object_writes_expected_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();

        let input = dir.path().join("input.bin");
        let input_bytes = vec![0_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        std::fs::write(&input, &input_bytes).unwrap();

        let res = omnisstream::ingest_file(&repo_root, &input, 3).unwrap();
        let manifest = load_manifest(&res.manifest_path).unwrap();
        let reader = reader_for_manifest(Some(&repo_root), manifest, &res.manifest_path).unwrap();

        let out = dir.path().join("out.bin");
        write_object_parallel(&reader, &out, Some(2)).unwrap();

        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, input_bytes);
    }

    #[test]
    fn list_part_files_ignores_noncanonical_part_ids() {
        let dir = tempfile::tempdir().unwrap();
        let parts_root = dir.path().join("parts");
        std::fs::create_dir_all(parts_root.join("aa").join("bb")).unwrap();

        let canonical = "a".repeat(64);
        let uppercase = "A".repeat(64);
        let invalid = format!("{}g", "a".repeat(63));

        std::fs::write(parts_root.join("aa").join("bb").join(&canonical), b"ok").unwrap();
        std::fs::write(parts_root.join("aa").join("bb").join(uppercase), b"skip").unwrap();
        std::fs::write(parts_root.join("aa").join("bb").join(invalid), b"skip").unwrap();

        let files = list_part_files(&parts_root).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, canonical);
        assert_eq!(files[0].bytes, 2);
    }

    #[test]
    fn gc_deletes_orphan_parts() {
        fn part_path(repo_root: &Path, id: &str) -> PathBuf {
            assert!(id.len() >= 4);
            repo_root
                .join("parts")
                .join(&id[0..2])
                .join(&id[2..4])
                .join(id)
        }

        let dir = tempfile::tempdir().unwrap();
        let repo_root = dir.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();

        let input1 = dir.path().join("a.bin");
        let input2 = dir.path().join("b.bin");
        std::fs::write(&input1, b"aaaaa-11111-zzzzz").unwrap();
        std::fs::write(&input2, b"bbbbb-22222-yyyyy").unwrap();

        let res1 = omnisstream::ingest_file(&repo_root, &input1, 5).unwrap();
        let res2 = omnisstream::ingest_file(&repo_root, &input2, 5).unwrap();

        let m1 = load_manifest(&res1.manifest_path).unwrap();
        let m2 = load_manifest(&res2.manifest_path).unwrap();
        let d1 = m1.part_store_digests_hex().unwrap();
        let d2 = m2.part_store_digests_hex().unwrap();

        // Simulate deleting object a.bin (leaving its parts orphaned).
        std::fs::remove_dir_all(repo_root.join("objects").join(&res1.object_id)).unwrap();

        let dry = run_gc(&repo_root, false, false).unwrap();
        assert!(dry.orphan_parts > 0);
        assert_eq!(dry.deleted_parts, 0);

        let stats = run_gc(&repo_root, true, false).unwrap();
        assert_eq!(stats.deleted_parts, dry.orphan_parts);

        // Parts for b.bin must still be present.
        for id in &d2 {
            let path = part_path(&repo_root, id);
            assert!(
                path.is_file(),
                "expected part to remain: {}",
                path.display()
            );
        }

        // Any part unique to a.bin should be gone.
        let referenced: std::collections::HashSet<_> = d2.into_iter().collect();
        for id in d1 {
            if referenced.contains(&id) {
                continue;
            }
            let path = part_path(&repo_root, &id);
            assert!(!path.exists(), "expected part deleted: {}", path.display());
        }

        // And we can still reconstruct b.bin.
        let manifest = load_manifest(&res2.manifest_path).unwrap();
        let reader = reader_for_manifest(Some(&repo_root), manifest, &res2.manifest_path).unwrap();
        let mut out = Vec::new();
        reader.cat(&mut out).unwrap();
        assert_eq!(out, b"bbbbb-22222-yyyyy");
    }
}
