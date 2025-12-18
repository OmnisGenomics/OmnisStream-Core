use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_util::{atomic_write_bytes, ensure_dir, read_to_string_if_exists};
use crate::hashing::{blake3_256_bytes, crc32c_bytes, Blake3Digest, Crc32c};
use crate::manifest::Manifest;
use crate::object_version::{compute_object_version, ObjectVersionEntry};
use crate::part_store::PartStore;
use crate::pb::omnisstream::v1 as pbv1;

#[derive(Clone, Debug)]
pub(crate) struct UploadManager {
    root: PathBuf,
    part_store: PartStore,
}

impl UploadManager {
    pub fn new(root: impl AsRef<Path>, part_store: PartStore) -> io::Result<Self> {
        let root = ensure_dir(root.as_ref())?;
        Ok(Self { root, part_store })
    }

    pub fn create(&self, object_id: &str) -> Result<String, UploadError> {
        if object_id.trim().is_empty() {
            return Err(UploadError::InvalidObjectId);
        }

        let upload_id = uuid::Uuid::new_v4().to_string();
        let dir = self.session_dir(&upload_id);
        std::fs::create_dir_all(&dir)?;

        let now = unix_ms_now();
        let session = SessionFile {
            schema_version: 1,
            upload_id: upload_id.clone(),
            object_id: object_id.to_string(),
            state: SessionState::Pending,
            created_unix_ms: now,
            updated_unix_ms: now,
            committed_unix_ms: None,
            parts: BTreeMap::new(),
        };

        self.save_session(&upload_id, &session)?;
        Ok(upload_id)
    }

    pub fn put_part(
        &self,
        upload_id: &str,
        part_number: u32,
        bytes: &[u8],
    ) -> Result<String, UploadError> {
        if part_number == 0 {
            return Err(UploadError::InvalidPartNumber);
        }

        let mut session = self.load_session(upload_id)?;
        match session.state {
            SessionState::Pending => {}
            SessionState::Complete => return Err(UploadError::AlreadyComplete),
            SessionState::Aborted => return Err(UploadError::Aborted),
        }

        let crc32c = crc32c_bytes(bytes);
        let blake3 = blake3_256_bytes(bytes);
        let len = bytes.len() as u64;

        if let Some(existing) = session.parts.get(&part_number) {
            if existing.blake3_256_hex == blake3.to_hex()
                && existing.crc32c_be_hex == crc32c.to_be_hex()
                && existing.length == len
            {
                return Ok(existing.blake3_256_hex.clone());
            }
            return Err(UploadError::PartConflict { part_number });
        }

        self.part_store.put_bytes_with_digest(blake3, bytes)?;

        session.parts.insert(
            part_number,
            PartRecord {
                length: len,
                stored_length: len,
                compression: pbv1::CompressionAlgorithm::None as i32,
                crc32c_be_hex: crc32c.to_be_hex(),
                blake3_256_hex: blake3.to_hex(),
            },
        );

        session.updated_unix_ms = unix_ms_now();
        self.save_session(upload_id, &session)?;

        Ok(blake3.to_hex())
    }

    pub fn complete(&self, upload_id: &str) -> Result<(Manifest, String), UploadError> {
        let mut session = self.load_session(upload_id)?;

        match session.state {
            SessionState::Complete => {
                let manifest_path = self.session_dir(upload_id).join("manifest.pb");
                let bytes = std::fs::read(&manifest_path)?;
                let manifest = Manifest::from_pb_bytes(&bytes)?;
                return Ok((manifest, session.object_version_hex()?));
            }
            SessionState::Aborted => return Err(UploadError::Aborted),
            SessionState::Pending => {}
        }

        if session.parts.is_empty() {
            return Err(UploadError::NoPartsUploaded);
        }

        let mut version_entries = Vec::with_capacity(session.parts.len());
        for (part_number, part) in &session.parts {
            version_entries.push(ObjectVersionEntry {
                part_number: *part_number,
                length: part.length,
                blake3_256: decode_blake3_hex(&part.blake3_256_hex)?,
            });
        }
        let object_version = compute_object_version(&version_entries);
        let object_version_hex = object_version.to_hex();

        let mut parts_pb = Vec::with_capacity(session.parts.len());
        let mut offset = 0_u64;
        for (part_number, part) in &session.parts {
            let blake3 = decode_blake3_hex(&part.blake3_256_hex)?;
            let crc32c = decode_crc32c_hex(&part.crc32c_be_hex)?;

            let hashes = vec![
                pbv1::HashDigest {
                    alg: pbv1::HashAlgorithm::Blake3256 as i32,
                    digest: blake3.as_bytes().to_vec(),
                },
                pbv1::HashDigest {
                    alg: pbv1::HashAlgorithm::Crc32c as i32,
                    digest: crc32c.to_be_bytes().to_vec(),
                },
            ];

            parts_pb.push(pbv1::PartMeta {
                part_number: *part_number,
                offset,
                length: part.length,
                stored_length: part.stored_length,
                compression: part.compression,
                hashes,
                relative_path: String::new(),
                tags: Default::default(),
                extensions: Default::default(),
            });

            offset = offset.saturating_add(part.length);
        }

        session.state = SessionState::Complete;
        session.updated_unix_ms = unix_ms_now();
        session.committed_unix_ms = Some(session.updated_unix_ms);

        let manifest_pb = pbv1::ObjectManifest {
            manifest_version: "0.1.0".to_string(),
            object_id: session.object_id.clone(),
            object_length: offset,
            parts: parts_pb,
            upload_session: Some(pbv1::UploadSession {
                upload_id: session.upload_id.clone(),
                state: pbv1::UploadSessionState::Complete as i32,
                created_unix_ms: session.created_unix_ms,
                updated_unix_ms: session.updated_unix_ms,
                tags: Default::default(),
                extensions: Default::default(),
            }),
            commit: Some(pbv1::CommitMeta {
                commit_id: object_version_hex.clone(),
                committed_unix_ms: session.committed_unix_ms.unwrap_or(0),
            }),
            tags: Default::default(),
            extensions: Default::default(),
        };
        let manifest = Manifest::new(manifest_pb);
        manifest.validate_basic()?;

        let manifest_bytes = manifest.to_pb_bytes();
        atomic_write_bytes(
            &self.session_dir(upload_id).join("manifest.pb"),
            &manifest_bytes,
        )?;
        self.save_session(upload_id, &session)?;

        Ok((manifest, object_version_hex))
    }

    fn load_session(&self, upload_id: &str) -> Result<SessionFile, UploadError> {
        let path = self.session_path(upload_id);
        let Some(s) = read_to_string_if_exists(&path)? else {
            return Err(UploadError::NotFound);
        };
        let mut session: SessionFile = serde_json::from_str(&s)?;
        self.recover_session_state(upload_id, &mut session)?;
        Ok(session)
    }

    fn save_session(&self, upload_id: &str, session: &SessionFile) -> Result<(), UploadError> {
        let bytes = serde_json::to_vec_pretty(session)?;
        atomic_write_bytes(&self.session_path(upload_id), &bytes)?;
        Ok(())
    }

    fn session_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join(upload_id)
    }

    fn session_path(&self, upload_id: &str) -> PathBuf {
        self.session_dir(upload_id).join("session.json")
    }

    fn recover_session_state(
        &self,
        upload_id: &str,
        session: &mut SessionFile,
    ) -> Result<(), UploadError> {
        let dir = self.session_dir(upload_id);
        let manifest_path = dir.join("manifest.pb");

        if manifest_path.is_file() {
            let bytes = std::fs::read(&manifest_path)?;
            let manifest = Manifest::from_pb_bytes(&bytes)?;
            manifest.validate_basic()?;

            // Crash recovery: derive COMPLETE state from the finalized manifest artifact.
            if !matches!(session.state, SessionState::Complete) {
                session.state = SessionState::Complete;
                if let Some(commit) = &manifest.pb().commit {
                    session.committed_unix_ms = Some(commit.committed_unix_ms);
                }
                self.save_session(upload_id, session)?;
            }
            return Ok(());
        }

        // If a temp manifest exists without a finalized manifest, treat as pending and clean up.
        let tmp_path = crate::fs_util::tmp_path_for_final(&manifest_path);
        if tmp_path.is_file() {
            let _ = std::fs::remove_file(tmp_path);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("object_id must be non-empty")]
    InvalidObjectId,

    #[error("part_number must be > 0")]
    InvalidPartNumber,

    #[error("upload session not found")]
    NotFound,

    #[error("upload session is already complete")]
    AlreadyComplete,

    #[error("upload session is aborted")]
    Aborted,

    #[error("no parts uploaded")]
    NoPartsUploaded,

    #[error("conflicting PutPart for part_number={part_number}")]
    PartConflict { part_number: u32 },

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    ManifestDecode(#[from] crate::manifest::ManifestDecodeError),

    #[error(transparent)]
    ManifestValidation(#[from] crate::manifest::ManifestValidationError),

    #[error("invalid digest hex in session file")]
    InvalidDigestHex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionFile {
    schema_version: u32,
    upload_id: String,
    object_id: String,
    state: SessionState,
    created_unix_ms: i64,
    updated_unix_ms: i64,
    committed_unix_ms: Option<i64>,
    parts: BTreeMap<u32, PartRecord>,
}

impl SessionFile {
    fn object_version_hex(&self) -> Result<String, UploadError> {
        let mut version_entries = Vec::with_capacity(self.parts.len());
        for (part_number, part) in &self.parts {
            version_entries.push(ObjectVersionEntry {
                part_number: *part_number,
                length: part.length,
                blake3_256: decode_blake3_hex(&part.blake3_256_hex)?,
            });
        }
        Ok(compute_object_version(&version_entries).to_hex())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SessionState {
    Pending,
    Complete,
    Aborted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartRecord {
    length: u64,
    stored_length: u64,
    compression: i32,
    crc32c_be_hex: String,
    blake3_256_hex: String,
}

fn unix_ms_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(0)
}

fn decode_blake3_hex(s: &str) -> Result<Blake3Digest, UploadError> {
    let bytes = hex::decode(s).map_err(|_| UploadError::InvalidDigestHex)?;
    if bytes.len() != 32 {
        return Err(UploadError::InvalidDigestHex);
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Blake3Digest::from_bytes(out))
}

fn decode_crc32c_hex(s: &str) -> Result<Crc32c, UploadError> {
    let bytes = hex::decode(s).map_err(|_| UploadError::InvalidDigestHex)?;
    if bytes.len() != 4 {
        return Err(UploadError::InvalidDigestHex);
    }
    let mut out = [0_u8; 4];
    out.copy_from_slice(&bytes);
    Ok(Crc32c::from_u32(u32::from_be_bytes(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_part_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();
        let uploads = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();

        let upload_id = uploads.create("object-1").unwrap();
        let etag1 = uploads.put_part(&upload_id, 1, b"hello").unwrap();
        let etag2 = uploads.put_part(&upload_id, 1, b"hello").unwrap();
        assert_eq!(etag1, etag2);
    }

    #[test]
    fn put_part_rejects_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();
        let uploads = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();

        let upload_id = uploads.create("object-1").unwrap();
        uploads.put_part(&upload_id, 1, b"hello").unwrap();
        let err = uploads.put_part(&upload_id, 1, b"world").unwrap_err();
        assert!(matches!(err, UploadError::PartConflict { part_number: 1 }));
    }

    #[test]
    fn complete_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();
        let uploads = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();

        let upload_id = uploads.create("object-1").unwrap();
        uploads.put_part(&upload_id, 1, b"hello").unwrap();
        uploads.put_part(&upload_id, 2, b"world").unwrap();

        let (_m1, v1) = uploads.complete(&upload_id).unwrap();
        let (_m2, v2) = uploads.complete(&upload_id).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn recovery_marks_complete_if_manifest_exists() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();
        let uploads = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();

        let upload_id = uploads.create("object-1").unwrap();
        uploads.put_part(&upload_id, 1, b"hello").unwrap();
        uploads.complete(&upload_id).unwrap();

        // Simulate a crash that left session.json in PENDING while manifest.pb is finalized.
        let session_path = uploads.session_path(&upload_id);
        let mut session: SessionFile =
            serde_json::from_str(&std::fs::read_to_string(&session_path).unwrap()).unwrap();
        session.state = SessionState::Pending;
        atomic_write_bytes(&session_path, &serde_json::to_vec_pretty(&session).unwrap()).unwrap();

        let err = uploads.put_part(&upload_id, 2, b"world").unwrap_err();
        assert!(matches!(err, UploadError::AlreadyComplete));
    }

    #[test]
    fn recovery_ignores_stray_manifest_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();
        let uploads = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();

        let upload_id = uploads.create("object-1").unwrap();
        uploads.put_part(&upload_id, 1, b"hello").unwrap();

        let manifest_path = uploads.session_dir(&upload_id).join("manifest.pb");
        let tmp_path = crate::fs_util::tmp_path_for_final(&manifest_path);
        std::fs::write(&tmp_path, b"partial").unwrap();
        assert!(tmp_path.is_file());

        uploads.put_part(&upload_id, 2, b"world").unwrap();
        assert!(!tmp_path.exists());
    }

    #[test]
    fn resume_after_restart_completes() {
        let dir = tempfile::tempdir().unwrap();
        let part_store = PartStore::new(dir.path().join("parts")).unwrap();

        let uploads1 = UploadManager::new(dir.path().join("uploads"), part_store.clone()).unwrap();
        let upload_id = uploads1.create("object-1").unwrap();
        uploads1.put_part(&upload_id, 1, b"hello").unwrap();
        drop(uploads1);

        let uploads2 = UploadManager::new(dir.path().join("uploads"), part_store).unwrap();
        uploads2.put_part(&upload_id, 2, b"world").unwrap();
        let (manifest, _v) = uploads2.complete(&upload_id).unwrap();
        manifest.validate_basic().unwrap();
    }
}
