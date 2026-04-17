use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use crate::fs_util::{atomic_write_bytes, atomic_write_string, ensure_dir};
use crate::hashing::{blake3_256_bytes, crc32c_bytes, Blake3Digest, Crc32c};
use crate::ingest_backend::PreadBackend;
use crate::manifest::Manifest;
use crate::object_version::{compute_object_version, ObjectVersionEntry};
use crate::part_store::PartStore;
use crate::pb::omnisstream::v1 as pbv1;
use omnisstream_backend_api::IngestBackend;

#[cfg(feature = "compression")]
use std::io::Write;

#[cfg(feature = "compression")]
use crate::compression::CompressionConfig;

#[derive(Clone, Debug)]
pub(crate) struct Repository {
    root: PathBuf,
    part_store: PartStore,
}

impl Repository {
    pub(crate) fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = ensure_dir(root.as_ref())?;
        let part_store = PartStore::new(root.join("parts"))?;
        Ok(Self { root, part_store })
    }

    pub fn ingest_file(
        &self,
        path: impl AsRef<Path>,
        part_size: u64,
    ) -> Result<IngestResult, IngestError> {
        ingest_file_impl(self, path.as_ref(), part_size)
    }
}

#[derive(Debug)]
pub struct IngestResult {
    pub object_id: String,
    pub object_version: String,
    pub manifest_path: PathBuf,
    pub manifest: Manifest,
}

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("part_size must be > 0")]
    InvalidPartSize,

    #[error("input file is empty")]
    EmptyFile,

    #[error("file too large / too many parts")]
    TooManyParts,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    ManifestValidation(#[from] crate::manifest::ManifestValidationError),
}

#[derive(Clone, Copy, Debug)]
struct PartResult {
    part_index: usize,
    part_number: u32,
    offset: u64,
    length: u64,
    stored_length: u64,
    compression: i32,
    crc32c: Crc32c,
    blake3_256: Blake3Digest,
}

fn ingest_file_impl(
    repo: &Repository,
    path: &Path,
    part_size: u64,
) -> Result<IngestResult, IngestError> {
    if part_size == 0 {
        return Err(IngestError::InvalidPartSize);
    }

    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Err(IngestError::EmptyFile);
    }

    let backend = PreadBackend::new(file);
    ingest_file_with_backend(repo, path, file_len, part_size, backend)
}

pub(crate) fn ingest_file_with_backend<B: IngestBackend>(
    repo: &Repository,
    path: &Path,
    file_len: u64,
    part_size: u64,
    backend: B,
) -> Result<IngestResult, IngestError> {
    let object_id = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "object".to_string());

    let num_parts_u64 = file_len.div_ceil(part_size);
    let num_parts: usize = num_parts_u64
        .try_into()
        .map_err(|_| IngestError::TooManyParts)?;

    if num_parts == 0 {
        return Err(IngestError::EmptyFile);
    }
    if num_parts > u32::MAX as usize {
        return Err(IngestError::TooManyParts);
    }

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(num_parts)
        .max(1);

    #[cfg(feature = "compression")]
    let compression = crate::compression::compression_config();

    let (tx, rx) = std::sync::mpsc::channel::<Result<PartResult, IngestError>>();
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let backend = backend.clone();
        let part_store = repo.part_store.clone();
        #[cfg(feature = "compression")]
        let worker_compression = compression;

        let start = worker_idx * num_parts / workers;
        let end = (worker_idx + 1) * num_parts / workers;

        handles.push(thread::spawn(move || {
            for part_index in start..end {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let offset = (part_index as u64).saturating_mul(part_size);
                let len = part_size.min(file_len.saturating_sub(offset));

                let Some(part_number) = u32::try_from(part_index + 1).ok() else {
                    stop.store(true, Ordering::Relaxed);
                    let _ = tx.send(Err(IngestError::TooManyParts));
                    break;
                };

                #[cfg(feature = "compression")]
                let res = ingest_one_part(
                    &backend,
                    &part_store,
                    part_index,
                    part_number,
                    offset,
                    len,
                    worker_compression,
                );
                #[cfg(not(feature = "compression"))]
                let res =
                    ingest_one_part(&backend, &part_store, part_index, part_number, offset, len);
                if res.is_err() {
                    stop.store(true, Ordering::Relaxed);
                }
                let _ = tx.send(res);
            }
        }));
    }
    drop(tx);

    let mut results: Vec<Option<PartResult>> = vec![None; num_parts];
    let mut first_err: Option<IngestError> = None;
    for msg in rx {
        match msg {
            Ok(r) => {
                results[r.part_index] = Some(r);
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    for h in handles {
        let _ = h.join();
    }

    if let Some(e) = first_err {
        return Err(e);
    }

    let mut version_entries = Vec::with_capacity(num_parts);
    let mut parts_pb = Vec::with_capacity(num_parts);

    for slot in results.iter_mut() {
        let r = slot
            .take()
            .ok_or_else(|| io::Error::other("missing part result from worker"))?;
        version_entries.push(ObjectVersionEntry {
            part_number: r.part_number,
            length: r.length,
            blake3_256: r.blake3_256,
        });

        let hashes = vec![
            pbv1::HashDigest {
                alg: pbv1::HashAlgorithm::Blake3256 as i32,
                digest: r.blake3_256.as_bytes().to_vec(),
            },
            pbv1::HashDigest {
                alg: pbv1::HashAlgorithm::Crc32c as i32,
                digest: r.crc32c.to_be_bytes().to_vec(),
            },
        ];

        parts_pb.push(pbv1::PartMeta {
            part_number: r.part_number,
            offset: r.offset,
            length: r.length,
            stored_length: r.stored_length,
            compression: r.compression,
            hashes,
            relative_path: String::new(),
            tags: Default::default(),
            extensions: Default::default(),
        });
    }

    let object_version = compute_object_version(&version_entries);
    let object_version_hex = object_version.to_hex();

    let manifest_pb = pbv1::ObjectManifest {
        manifest_version: "0.1.0".to_string(),
        object_id: object_id.clone(),
        object_length: file_len,
        parts: parts_pb,
        upload_session: None,
        commit: Some(pbv1::CommitMeta {
            commit_id: object_version_hex.clone(),
            committed_unix_ms: 0,
        }),
        tags: Default::default(),
        extensions: Default::default(),
    };
    let manifest = Manifest::new(manifest_pb);
    manifest.validate_basic()?;

    let manifest_bytes = manifest.to_pb_bytes();
    let (manifest_path, latest_path) = object_paths(&repo.root, &object_id, &object_version_hex);
    atomic_write_bytes(&manifest_path, &manifest_bytes)?;
    atomic_write_string(&latest_path, &object_version_hex)?;

    Ok(IngestResult {
        object_id,
        object_version: object_version_hex,
        manifest_path,
        manifest,
    })
}

fn ingest_one_part(
    backend: &impl IngestBackend,
    part_store: &PartStore,
    part_index: usize,
    part_number: u32,
    offset: u64,
    len: u64,
    #[cfg(feature = "compression")] compression: Option<CompressionConfig>,
) -> Result<PartResult, IngestError> {
    let mut buf = vec![0_u8; len as usize];
    backend.read_exact_at(offset, &mut buf)?;

    #[cfg(feature = "compression")]
    let (stored, compression_alg) = {
        let mut stored = buf;
        let mut compression_alg = pbv1::CompressionAlgorithm::None as i32;
        if let Some(cfg) = compression {
            if let Some(compressed) = compress_zstd_seekable(&stored, cfg)? {
                stored = compressed;
                compression_alg = pbv1::CompressionAlgorithm::ZstdSeekable as i32;
            }
        }
        (stored, compression_alg)
    };

    #[cfg(not(feature = "compression"))]
    let (stored, compression_alg) = (buf, pbv1::CompressionAlgorithm::None as i32);

    let crc32c = crc32c_bytes(&stored);
    let blake3_256 = blake3_256_bytes(&stored);

    part_store.put_bytes_with_digest(blake3_256, &stored)?;

    Ok(PartResult {
        part_index,
        part_number,
        offset,
        length: len,
        stored_length: stored.len() as u64,
        compression: compression_alg,
        crc32c,
        blake3_256,
    })
}

#[cfg(feature = "compression")]
fn compress_zstd_seekable(
    bytes: &[u8],
    cfg: CompressionConfig,
) -> Result<Option<Vec<u8>>, IngestError> {
    const MIN_COMPRESSION_RATIO_NUM: usize = 95;
    const MIN_COMPRESSION_RATIO_DEN: usize = 100;
    const SAMPLE_BYTES: usize = 64 * 1024;

    #[derive(Debug)]
    struct LimitExceeded;

    impl std::fmt::Display for LimitExceeded {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "compression exceeded size limit")
        }
    }

    impl std::error::Error for LimitExceeded {}

    #[derive(Debug, Default)]
    struct LimitedVecWriter {
        buf: Vec<u8>,
        limit: usize,
    }

    impl LimitedVecWriter {
        fn with_limit(limit: usize) -> Self {
            Self {
                buf: Vec::new(),
                limit,
            }
        }

        fn into_inner(self) -> Vec<u8> {
            self.buf
        }
    }

    impl Write for LimitedVecWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.buf.len().saturating_add(buf.len()) > self.limit {
                return Err(std::io::Error::other(LimitExceeded));
            }
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn is_limit_exceeded(e: &std::io::Error) -> bool {
        e.get_ref().is_some_and(|inner| inner.is::<LimitExceeded>())
    }

    if bytes.is_empty() {
        return Ok(None);
    }

    // Skip compression unless we get a meaningful size win. This avoids spending
    // CPU on near-incompressible inputs and helps limit range-read regressions
    // where the on-disk bytes are bigger but accessed in smaller chunks.
    let limit = bytes.len().saturating_mul(MIN_COMPRESSION_RATIO_NUM) / MIN_COMPRESSION_RATIO_DEN;
    if limit == 0 {
        return Ok(None);
    }

    // Fast reject: if a representative sample isn't compressing well, skip
    // the full compression attempt (saves substantial CPU on incompressible
    // payloads).
    if bytes.len() > SAMPLE_BYTES {
        let sample_len = SAMPLE_BYTES.min(bytes.len());
        let sample_limit =
            sample_len.saturating_mul(MIN_COMPRESSION_RATIO_NUM) / MIN_COMPRESSION_RATIO_DEN;
        if sample_limit == 0 {
            return Ok(None);
        }

        let mut sample_out = LimitedVecWriter::with_limit(sample_limit);
        let mut w = zstd_framed::ZstdWriter::builder(&mut sample_out)
            // Use a fast compression setting for the probe: we're only
            // attempting to detect obviously incompressible inputs.
            .with_compression_level(1)
            .with_seek_table(cfg.zstd_seekable_max_frame_size)
            .build()?;
        if let Err(e) = w.write_all(&bytes[..sample_len]) {
            if is_limit_exceeded(&e) {
                return Ok(None);
            }
            return Err(IngestError::Io(e));
        }
        if let Err(e) = w.shutdown() {
            if is_limit_exceeded(&e) {
                return Ok(None);
            }
            return Err(IngestError::Io(e));
        }
        drop(w);
        drop(sample_out);
    }

    let mut out = LimitedVecWriter::with_limit(limit);
    let mut w = zstd_framed::ZstdWriter::builder(&mut out)
        .with_compression_level(cfg.zstd_seekable_level)
        .with_seek_table(cfg.zstd_seekable_max_frame_size)
        .build()?;

    if let Err(e) = w.write_all(bytes) {
        if is_limit_exceeded(&e) {
            return Ok(None);
        }
        return Err(IngestError::Io(e));
    }
    if let Err(e) = w.shutdown() {
        if is_limit_exceeded(&e) {
            return Ok(None);
        }
        return Err(IngestError::Io(e));
    }
    drop(w);

    let out = out.into_inner();
    if out.len() < bytes.len() {
        Ok(Some(out))
    } else {
        Ok(None)
    }
}

fn object_paths(root: &Path, object_id: &str, object_version: &str) -> (PathBuf, PathBuf) {
    let object_dir = root.join("objects").join(object_id);
    let version_dir = object_dir.join("versions").join(object_version);
    let manifest_path = version_dir.join("manifest.pb");
    let latest_path = object_dir.join("latest");
    (manifest_path, latest_path)
}

#[cfg(test)]
mod tests {
    use crate::ingest_backend::MemBackend;

    use super::*;

    #[cfg(feature = "compression")]
    static COMPRESSION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn ingest_is_deterministic_for_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::open(dir.path().join("repo")).unwrap();

        let input_path = dir.path().join("input.bin");
        std::fs::write(&input_path, b"hello world, this is a test file").unwrap();

        let r1 = repo.ingest_file(&input_path, 5).unwrap();
        let r2 = repo.ingest_file(&input_path, 5).unwrap();

        assert_eq!(r1.object_version, r2.object_version);
        assert_eq!(r1.manifest.to_pb_bytes(), r2.manifest.to_pb_bytes());
        assert!(r1.manifest_path.is_file());
    }

    #[test]
    fn manifest_bytes_are_identical_across_backends() {
        let dir = tempfile::tempdir().unwrap();

        let input_path = dir.path().join("input.bin");
        std::fs::write(&input_path, b"hello world, this is a test file").unwrap();
        let bytes = std::fs::read(&input_path).unwrap();
        let file_len = bytes.len() as u64;

        let repo_default = Repository::open(dir.path().join("repo_default")).unwrap();
        let repo_dummy = Repository::open(dir.path().join("repo_dummy")).unwrap();

        let part_size = 5;
        let r_default = repo_default.ingest_file(&input_path, part_size).unwrap();
        let r_dummy = ingest_file_with_backend(
            &repo_dummy,
            &input_path,
            file_len,
            part_size,
            MemBackend::new(bytes),
        )
        .unwrap();

        assert_eq!(r_default.object_version, r_dummy.object_version);
        assert_eq!(
            r_default.manifest.to_pb_bytes(),
            r_dummy.manifest.to_pb_bytes()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn ingest_with_compression_sets_stored_length_and_alg() {
        let _guard = COMPRESSION_TEST_LOCK.lock().unwrap();

        crate::compression::set_compression_config(Some(crate::compression::CompressionConfig {
            zstd_seekable_level: 3,
            zstd_seekable_max_frame_size: 256 * 1024,
        }));

        let dir = tempfile::tempdir().unwrap();
        let repo = Repository::open(dir.path().join("repo")).unwrap();

        let input_path = dir.path().join("input.bin");
        let input_bytes = vec![0_u8; 8 * 1024 * 1024];
        std::fs::write(&input_path, &input_bytes).unwrap();

        let part_size = 4 * 1024 * 1024;
        let res = repo.ingest_file(&input_path, part_size).unwrap();
        let pb = res.manifest.clone().into_pb();

        assert_eq!(pb.parts.len(), 2);
        for p in &pb.parts {
            assert_eq!(p.length, part_size);
            assert!(p.stored_length < p.length, "expected compressed part");
            assert_eq!(
                p.compression,
                pbv1::CompressionAlgorithm::ZstdSeekable as i32
            );
        }

        // Stored-bytes verify still passes.
        let reader = crate::api::Reader::new(res.manifest.clone(), dir.path().join("repo"))
            .with_part_store(PartStore::new(dir.path().join("repo/parts")).unwrap());
        reader.verify().unwrap();

        // And we can reconstruct the original bytes.
        let mut out = Vec::new();
        reader.cat(&mut out).unwrap();
        assert_eq!(out, input_bytes);

        // Ranged reads work through compressed parts.
        let offset = part_size - 10;
        let len = 20_u64;
        let mut got = Vec::new();
        reader.range(offset, len, &mut got).unwrap();
        let start = offset as usize;
        let end = (offset + len) as usize;
        assert_eq!(got, input_bytes[start..end]);

        crate::compression::set_compression_config(None);
    }
}
