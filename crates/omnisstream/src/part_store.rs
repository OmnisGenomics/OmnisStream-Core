use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::fs_util::fsync_dir;
use crate::hashing::{Blake3Digest, HashSummary};

#[derive(Clone, Debug)]
pub struct PartStore {
    root: PathBuf,
}

impl PartStore {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join("_tmp"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn exists(&self, digest: Blake3Digest) -> bool {
        self.path_for_digest(digest).is_file()
    }

    pub fn open(&self, digest: Blake3Digest) -> io::Result<File> {
        File::open(self.path_for_digest(digest))
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> io::Result<Blake3Digest> {
        let digest = crate::hashing::blake3_256_bytes(bytes);
        self.put_bytes_with_digest(digest, bytes)?;
        Ok(digest)
    }

    pub fn put_bytes_with_digest(&self, digest: Blake3Digest, bytes: &[u8]) -> io::Result<()> {
        let final_path = self.path_for_digest(digest);

        if final_path.is_file() {
            return Ok(());
        }

        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut tmp = tempfile::NamedTempFile::new_in(self.tmp_dir())?;
        tmp.as_file_mut().write_all(bytes)?;
        tmp.as_file().sync_all()?;

        self.rename_atomic(tmp.into_temp_path(), &final_path)
    }

    pub fn put_reader(&self, reader: &mut impl Read) -> io::Result<(Blake3Digest, HashSummary)> {
        let mut tmp = tempfile::NamedTempFile::new_in(self.tmp_dir())?;
        let summary = copy_and_hash(reader, tmp.as_file_mut())?;
        tmp.as_file().sync_all()?;

        let digest = summary.blake3_256;
        let final_path = self.path_for_digest(digest);
        if final_path.is_file() {
            return Ok((digest, summary));
        }

        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        self.rename_atomic(tmp.into_temp_path(), &final_path)?;
        Ok((digest, summary))
    }

    fn path_for_digest(&self, digest: Blake3Digest) -> PathBuf {
        let hex = digest.to_hex();
        let (p1, p2) = (&hex[0..2], &hex[2..4]);
        self.root.join(p1).join(p2).join(hex)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("_tmp")
    }

    fn rename_atomic(&self, tmp_path: tempfile::TempPath, final_path: &Path) -> io::Result<()> {
        match std::fs::rename(&tmp_path, final_path) {
            Ok(()) => {
                if let Some(parent) = final_path.parent() {
                    fsync_dir(parent)?;
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn copy_and_hash(reader: &mut impl Read, writer: &mut impl Write) -> io::Result<HashSummary> {
    let mut crc = 0_u32;
    let mut hasher = blake3::Hasher::new();

    let mut buf = [0_u8; 64 * 1024];
    let mut len = 0_u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        len += n as u64;
        crc = crc32c::crc32c_append(crc, &buf[..n]);
        hasher.update(&buf[..n]);
    }

    Ok(HashSummary {
        len,
        crc32c: crate::hashing::Crc32c::from_u32(crc),
        blake3_256: Blake3Digest::from_bytes(*hasher.finalize().as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_bytes_is_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let store = PartStore::new(dir.path()).unwrap();

        let d1 = store.put_bytes(b"hello").unwrap();
        let d2 = store.put_bytes(b"hello").unwrap();
        assert_eq!(d1, d2);

        let path = store.path_for_digest(d1);
        assert!(path.is_file());
    }

    #[test]
    fn put_reader_is_atomic_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let store = PartStore::new(dir.path()).unwrap();

        let mut r1: &mut dyn Read = &mut &b"abc123"[..];
        let (d1, _s1) = store.put_reader(&mut r1).unwrap();
        let mut r2: &mut dyn Read = &mut &b"abc123"[..];
        let (d2, _s2) = store.put_reader(&mut r2).unwrap();
        assert_eq!(d1, d2);

        assert!(store.exists(d1));
        let mut f = store.open(d1).unwrap();
        let mut out = Vec::new();
        f.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc123");
    }
}
