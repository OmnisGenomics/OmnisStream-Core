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
use crate::manifest::Manifest;
use crate::object_version::{compute_object_version, ObjectVersionEntry};
use crate::part_store::PartStore;
use crate::pb::omnisstream::v1 as pbv1;
use crate::upload::UploadManager;

#[derive(Clone, Debug)]
pub struct Repository {
    root: PathBuf,
    part_store: PartStore,
    uploads: UploadManager,
}

impl Repository {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = ensure_dir(root.as_ref())?;
        let part_store = PartStore::new(root.join("parts"))?;
        let uploads = UploadManager::new(root.join("uploads"), part_store.clone())?;
        Ok(Self {
            root,
            part_store,
            uploads,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn part_store(&self) -> &PartStore {
        &self.part_store
    }

    pub fn uploads(&self) -> &UploadManager {
        &self.uploads
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

    let object_id = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "object".to_string());

    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Err(IngestError::EmptyFile);
    }

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

    let (tx, rx) = std::sync::mpsc::channel::<Result<PartResult, IngestError>>();
    let stop = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let file = file.try_clone()?;
        let part_store = repo.part_store.clone();

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

                let res = ingest_one_part(&file, &part_store, part_index, part_number, offset, len);
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
            compression: pbv1::CompressionAlgorithm::None as i32,
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
    file: &File,
    part_store: &PartStore,
    part_index: usize,
    part_number: u32,
    offset: u64,
    len: u64,
) -> Result<PartResult, IngestError> {
    let mut buf = vec![0_u8; len as usize];
    read_exact_at(file, &mut buf, offset)?;

    let crc32c = crc32c_bytes(&buf);
    let blake3_256 = blake3_256_bytes(&buf);

    part_store.put_bytes_with_digest(blake3_256, &buf)?;

    Ok(PartResult {
        part_index,
        part_number,
        offset,
        length: len,
        stored_length: len,
        crc32c,
        blake3_256,
    })
}

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt as _;

    let mut read = 0_usize;
    while read < buf.len() {
        let n = file.read_at(&mut buf[read..], offset.saturating_add(read as u64))?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        read += n;
    }
    Ok(())
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
    use super::*;

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
}
