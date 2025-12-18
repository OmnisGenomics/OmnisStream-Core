use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::hashing::{hash_reader, Blake3Digest, Crc32c, HashSummary};
use crate::manifest::{Manifest, ManifestValidationError};
use crate::part_store::PartStore;
use crate::pb::omnisstream::v1 as pbv1;

#[derive(Clone, Debug)]
pub struct PartResolver {
    base_dir: PathBuf,
    part_store: Option<PartStore>,
}

impl PartResolver {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            part_store: None,
        }
    }

    pub fn with_part_store(mut self, part_store: PartStore) -> Self {
        self.part_store = Some(part_store);
        self
    }

    fn open_part(&self, part: &pbv1::PartMeta) -> Result<File, ReaderError> {
        if !part.relative_path.is_empty() {
            let path = self.base_dir.join(&part.relative_path);
            return Ok(File::open(path)?);
        }

        let Some(part_store) = &self.part_store else {
            return Err(ReaderError::NoPartStoreForDigest);
        };

        let blake3 = blake3_digest_from_part(part)?;
        Ok(part_store.open(blake3)?)
    }
}

pub fn cat(
    manifest: &Manifest,
    resolver: &PartResolver,
    out: &mut impl Write,
) -> Result<(), ReaderError> {
    manifest.validate_basic()?;

    for part in &manifest.pb().parts {
        if part.compression != pbv1::CompressionAlgorithm::None as i32 {
            return Err(ReaderError::UnsupportedCompression {
                part_number: part.part_number,
                compression: part.compression,
            });
        }

        let mut f = resolver.open_part(part)?;
        copy_exact(&mut f, out, part.stored_length)?;
    }
    Ok(())
}

pub fn verify(manifest: &Manifest, resolver: &PartResolver) -> Result<VerifySummary, ReaderError> {
    manifest.validate_basic()?;

    let mut total_bytes = 0_u64;
    for part in &manifest.pb().parts {
        let mut f = resolver.open_part(part)?;
        let summary = hash_reader_exact(&mut f, part.stored_length)?;

        let expected_crc32c = crc32c_digest_from_part(part)?;
        let expected_blake3 = blake3_digest_from_part(part)?;

        if summary.crc32c.to_be_bytes() != expected_crc32c.to_be_bytes() {
            return Err(ReaderError::HashMismatch {
                part_number: part.part_number,
                alg: "crc32c",
                expected_hex: expected_crc32c.to_be_hex(),
                actual_hex: summary.crc32c.to_be_hex(),
            });
        }
        if summary.blake3_256.as_bytes() != expected_blake3.as_bytes() {
            return Err(ReaderError::HashMismatch {
                part_number: part.part_number,
                alg: "blake3-256",
                expected_hex: expected_blake3.to_hex(),
                actual_hex: summary.blake3_256.to_hex(),
            });
        }

        total_bytes = total_bytes.saturating_add(part.stored_length);
    }

    Ok(VerifySummary {
        parts: manifest.pb().parts.len(),
        bytes: total_bytes,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifySummary {
    pub parts: usize,
    pub bytes: u64,
}

pub fn range(
    manifest: &Manifest,
    resolver: &PartResolver,
    offset: u64,
    len: u64,
    out: &mut impl Write,
) -> Result<(), ReaderError> {
    manifest.validate_basic()?;

    if len == 0 {
        return Ok(());
    }
    let end = offset
        .checked_add(len)
        .ok_or(ReaderError::RangeOutOfBounds)?;
    if end > manifest.pb().object_length {
        return Err(ReaderError::RangeOutOfBounds);
    }

    let mut remaining = len;
    let mut cur = offset;

    while remaining > 0 {
        let (idx, within) =
            locate_part(&manifest.pb().parts, cur).ok_or(ReaderError::RangeOutOfBounds)?;
        let part = &manifest.pb().parts[idx];

        if part.compression != pbv1::CompressionAlgorithm::None as i32 {
            return Err(ReaderError::UnsupportedCompression {
                part_number: part.part_number,
                compression: part.compression,
            });
        }

        let available = part.length.saturating_sub(within);
        let to_read = available.min(remaining);

        let mut f = resolver.open_part(part)?;
        f.seek(SeekFrom::Start(within))?;
        copy_exact(&mut f, out, to_read)?;

        remaining -= to_read;
        cur += to_read;
    }

    Ok(())
}

fn locate_part(parts: &[pbv1::PartMeta], offset: u64) -> Option<(usize, u64)> {
    let mut lo = 0_usize;
    let mut hi = parts.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let p = &parts[mid];
        let start = p.offset;
        let end = p.offset.saturating_add(p.length);
        if offset < start {
            hi = mid;
        } else if offset >= end {
            lo = mid + 1;
        } else {
            return Some((mid, offset - start));
        }
    }
    None
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, mut n: u64) -> io::Result<()> {
    let mut buf = [0_u8; 64 * 1024];
    while n > 0 {
        let chunk = (buf.len() as u64).min(n) as usize;
        let got = reader.read(&mut buf[..chunk])?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        writer.write_all(&buf[..got])?;
        n -= got as u64;
    }
    Ok(())
}

fn hash_reader_exact(reader: &mut impl Read, n: u64) -> Result<HashSummary, ReaderError> {
    let mut limited = reader.take(n);
    let summary = hash_reader(&mut limited)?;
    if summary.len != n {
        return Err(ReaderError::UnexpectedEof);
    }
    Ok(summary)
}

fn blake3_digest_from_part(part: &pbv1::PartMeta) -> Result<Blake3Digest, ReaderError> {
    let hash = part
        .hashes
        .iter()
        .find(|h| h.alg == pbv1::HashAlgorithm::Blake3256 as i32)
        .ok_or(ReaderError::MissingDigest { alg: "blake3-256" })?;
    if hash.digest.len() != 32 {
        return Err(ReaderError::InvalidDigestLength {
            alg: "blake3-256",
            expected: 32,
            actual: hash.digest.len(),
        });
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hash.digest);
    Ok(Blake3Digest::from_bytes(out))
}

fn crc32c_digest_from_part(part: &pbv1::PartMeta) -> Result<Crc32c, ReaderError> {
    let hash = part
        .hashes
        .iter()
        .find(|h| h.alg == pbv1::HashAlgorithm::Crc32c as i32)
        .ok_or(ReaderError::MissingDigest { alg: "crc32c" })?;
    if hash.digest.len() != 4 {
        return Err(ReaderError::InvalidDigestLength {
            alg: "crc32c",
            expected: 4,
            actual: hash.digest.len(),
        });
    }
    let mut out = [0_u8; 4];
    out.copy_from_slice(&hash.digest);
    Ok(Crc32c::from_u32(u32::from_be_bytes(out)))
}

#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    ManifestValidation(#[from] ManifestValidationError),

    #[error("part store is required for digest-addressed parts")]
    NoPartStoreForDigest,

    #[error("unsupported compression for part_number={part_number}: {compression}")]
    UnsupportedCompression { part_number: u32, compression: i32 },

    #[error("missing required digest: {alg}")]
    MissingDigest { alg: &'static str },

    #[error("invalid digest length for {alg}: expected {expected}, got {actual}")]
    InvalidDigestLength {
        alg: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("hash mismatch for part_number={part_number} ({alg}): expected={expected_hex} actual={actual_hex}")]
    HashMismatch {
        part_number: u32,
        alg: &'static str,
        expected_hex: String,
        actual_hex: String,
    },

    #[error("range out of bounds")]
    RangeOutOfBounds,

    #[error("unexpected EOF while reading part payload")]
    UnexpectedEof,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn spec_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/omnisstream-spec")
    }

    fn load_manifest(vector: &str) -> Manifest {
        let bytes = std::fs::read(
            spec_root()
                .join("test-vectors")
                .join(vector)
                .join("manifest.pb"),
        )
        .unwrap();
        Manifest::from_pb_bytes(&bytes).unwrap()
    }

    #[test]
    fn cat_matches_vector_minimal_bytes() {
        let manifest = load_manifest("vector-minimal");
        let base_dir = spec_root().join("test-vectors/vector-minimal");
        let resolver = PartResolver::new(&base_dir);

        let mut out = Vec::new();
        cat(&manifest, &resolver, &mut out).unwrap();

        let mut expected = Vec::new();
        for part in &manifest.pb().parts {
            let bytes = std::fs::read(base_dir.join(&part.relative_path)).unwrap();
            expected.extend_from_slice(&bytes);
        }

        assert_eq!(out, expected);
        assert_eq!(out.len() as u64, manifest.pb().object_length);
    }

    #[test]
    fn range_spans_part_boundaries() {
        let manifest = load_manifest("vector-minimal");
        let base_dir = spec_root().join("test-vectors/vector-minimal");
        let resolver = PartResolver::new(&base_dir);

        let mut full = Vec::new();
        cat(&manifest, &resolver, &mut full).unwrap();

        let offset = 4_u64;
        let len = 5_u64;
        let mut got = Vec::new();
        range(&manifest, &resolver, offset, len, &mut got).unwrap();

        let expected = &full[offset as usize..(offset + len) as usize];
        assert_eq!(got, expected);
    }

    #[test]
    fn verify_detects_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let src = spec_root().join("test-vectors/vector-minimal");
        let dst = temp.path().join("vector-minimal");

        std::fs::create_dir_all(dst.join("parts")).unwrap();
        std::fs::copy(src.join("manifest.pb"), dst.join("manifest.pb")).unwrap();
        std::fs::copy(
            src.join("parts/part-0001.bin"),
            dst.join("parts/part-0001.bin"),
        )
        .unwrap();
        std::fs::copy(
            src.join("parts/part-0002.bin"),
            dst.join("parts/part-0002.bin"),
        )
        .unwrap();
        std::fs::copy(
            src.join("parts/part-0003.bin"),
            dst.join("parts/part-0003.bin"),
        )
        .unwrap();

        let bytes = std::fs::read(dst.join("manifest.pb")).unwrap();
        let manifest = Manifest::from_pb_bytes(&bytes).unwrap();
        let resolver = PartResolver::new(&dst);

        verify(&manifest, &resolver).unwrap();

        // Flip one byte.
        let part_path = dst.join("parts/part-0002.bin");
        let mut part_bytes = std::fs::read(&part_path).unwrap();
        part_bytes[0] ^= 0xFF;
        std::fs::write(&part_path, part_bytes).unwrap();

        let err = verify(&manifest, &resolver).unwrap_err();
        assert!(matches!(err, ReaderError::HashMismatch { .. }));
    }

    #[test]
    fn verify_detects_truncated_part() {
        let temp = tempfile::tempdir().unwrap();
        let src = spec_root().join("test-vectors/vector-minimal");
        let dst = temp.path().join("vector-minimal");

        std::fs::create_dir_all(dst.join("parts")).unwrap();
        std::fs::copy(src.join("manifest.pb"), dst.join("manifest.pb")).unwrap();
        std::fs::copy(
            src.join("parts/part-0001.bin"),
            dst.join("parts/part-0001.bin"),
        )
        .unwrap();
        std::fs::copy(
            src.join("parts/part-0002.bin"),
            dst.join("parts/part-0002.bin"),
        )
        .unwrap();
        std::fs::copy(
            src.join("parts/part-0003.bin"),
            dst.join("parts/part-0003.bin"),
        )
        .unwrap();

        let bytes = std::fs::read(dst.join("manifest.pb")).unwrap();
        let manifest = Manifest::from_pb_bytes(&bytes).unwrap();
        let resolver = PartResolver::new(&dst);

        verify(&manifest, &resolver).unwrap();

        // Truncate a part.
        let part_path = dst.join("parts/part-0001.bin");
        let mut part_bytes = std::fs::read(&part_path).unwrap();
        part_bytes.pop();
        std::fs::write(&part_path, part_bytes).unwrap();

        let err = verify(&manifest, &resolver).unwrap_err();
        assert!(matches!(err, ReaderError::UnexpectedEof));
    }

    #[test]
    fn verify_passes_vector_compressed() {
        let manifest = load_manifest("vector-compressed");
        let base_dir = spec_root().join("test-vectors/vector-compressed");
        let resolver = PartResolver::new(&base_dir);

        verify(&manifest, &resolver).unwrap();
    }
}
