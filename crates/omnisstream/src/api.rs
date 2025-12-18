use std::io::Write;
use std::path::Path;

#[cfg(feature = "backend-unstable")]
use omnisstream_backend_api::IngestBackend;

pub use crate::hashing::{Blake3Digest, Crc32c, HashSummary};
pub use crate::manifest::{Manifest, ManifestDecodeError, ManifestValidationError};
pub use crate::part_store::PartStore;
pub use crate::reader::{ReaderError, VerifySummary};
pub use crate::repo::{IngestError, IngestResult};
pub use crate::upload::UploadError;

/// Supported manifest schema range for this build of OmnisStream core.
pub const SUPPORTED_MANIFEST_SCHEMA: &str = "0.1.x";

/// Stable, minimal reader API for reconstructing/validating an object described by a `Manifest`.
#[derive(Clone, Debug)]
pub struct Reader {
    manifest: Manifest,
    resolver: crate::reader::PartResolver,
}

impl Reader {
    pub fn new(manifest: Manifest, base_dir: impl AsRef<Path>) -> Self {
        Self {
            manifest,
            resolver: crate::reader::PartResolver::new(base_dir),
        }
    }

    pub fn with_part_store(mut self, part_store: PartStore) -> Self {
        self.resolver = self.resolver.clone().with_part_store(part_store);
        self
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn cat(&self, out: &mut impl Write) -> Result<(), ReaderError> {
        crate::reader::cat(&self.manifest, &self.resolver, out)
    }

    pub fn verify(&self) -> Result<VerifySummary, ReaderError> {
        crate::reader::verify(&self.manifest, &self.resolver)
    }

    pub fn range(&self, offset: u64, len: u64, out: &mut impl Write) -> Result<(), ReaderError> {
        crate::reader::range(&self.manifest, &self.resolver, offset, len, out)
    }
}

/// Stable, minimal upload session API.
#[derive(Clone, Debug)]
pub struct UploadSession {
    uploads: crate::upload::UploadManager,
    upload_id: String,
}

impl UploadSession {
    pub fn create(repo_root: impl AsRef<Path>, object_id: &str) -> Result<Self, UploadError> {
        let repo_root = repo_root.as_ref();
        let part_store = PartStore::new(repo_root.join("parts"))?;
        let uploads = crate::upload::UploadManager::new(repo_root.join("uploads"), part_store)?;
        let upload_id = uploads.create(object_id)?;
        Ok(Self { uploads, upload_id })
    }

    pub fn open(
        repo_root: impl AsRef<Path>,
        upload_id: impl Into<String>,
    ) -> Result<Self, UploadError> {
        let repo_root = repo_root.as_ref();
        let part_store = PartStore::new(repo_root.join("parts"))?;
        let uploads = crate::upload::UploadManager::new(repo_root.join("uploads"), part_store)?;
        Ok(Self {
            uploads,
            upload_id: upload_id.into(),
        })
    }

    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    pub fn put_part(&self, part_number: u32, bytes: &[u8]) -> Result<String, UploadError> {
        self.uploads.put_part(&self.upload_id, part_number, bytes)
    }

    pub fn complete(&self) -> Result<(Manifest, String), UploadError> {
        self.uploads.complete(&self.upload_id)
    }
}

pub fn ingest_file(
    repo_root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    part_size: u64,
) -> Result<IngestResult, IngestError> {
    let repo = crate::repo::Repository::open(repo_root)?;
    repo.ingest_file(path, part_size)
}

/// Ingest using a custom backend (positional reads only).
///
/// # Stability
/// This API is **unstable** and gated behind the `backend-unstable` Cargo feature. It exists so
/// external backends (e.g. io_uring) can plug into core ingest without forking core logic.
#[cfg(feature = "backend-unstable")]
pub fn ingest_file_with_backend<B: IngestBackend>(
    repo_root: impl AsRef<Path>,
    path: impl AsRef<Path>,
    part_size: u64,
    backend: B,
) -> Result<IngestResult, IngestError> {
    let repo = crate::repo::Repository::open(repo_root)?;
    let path = path.as_ref();
    let file_len = std::fs::metadata(path)?.len();
    crate::repo::ingest_file_with_backend(&repo, path, file_len, part_size, backend)
}

impl Manifest {
    /// Stable human-readable output, intended for `omnisstream inspect`.
    pub fn inspect(&self) -> String {
        crate::inspect::format_manifest(self)
    }
}
