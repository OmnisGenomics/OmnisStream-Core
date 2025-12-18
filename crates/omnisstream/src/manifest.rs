use std::path::Path;

use prost::Message as _;

use crate::pb::omnisstream::v1 as pbv1;

#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pb: pbv1::ObjectManifest,
}

impl Manifest {
    pub fn new(pb: pbv1::ObjectManifest) -> Self {
        Self { pb }
    }

    pub fn pb(&self) -> &pbv1::ObjectManifest {
        &self.pb
    }

    pub fn into_pb(self) -> pbv1::ObjectManifest {
        self.pb
    }

    pub fn from_pb_bytes(bytes: &[u8]) -> Result<Self, ManifestDecodeError> {
        let pb = pbv1::ObjectManifest::decode(bytes)?;
        Ok(Self::new(pb))
    }

    pub fn to_pb_bytes(&self) -> Vec<u8> {
        self.pb.encode_to_vec()
    }

    pub fn validate_basic(&self) -> Result<(), ManifestValidationError> {
        validate_manifest_basic(&self.pb)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestDecodeError {
    #[error("failed to decode ObjectManifest protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestValidationError {
    #[error("manifest_version must be SemVer MAJOR.MINOR.PATCH with supported major; got {manifest_version:?}")]
    InvalidManifestVersion { manifest_version: String },

    #[error("object_id must be non-empty")]
    MissingObjectId,

    #[error("parts must be non-empty in v0.1.x")]
    EmptyParts,

    #[error("object_length mismatch: expected {expected} from parts but was {actual}")]
    ObjectLengthMismatch { expected: u64, actual: u64 },

    #[error("parts must start at offset 0 but first offset was {offset}")]
    PartsMustStartAtZero { offset: u64 },

    #[error("parts must be sorted by strictly increasing offset (found prev_offset={prev_offset}, next_offset={next_offset})")]
    PartsNotStrictlyIncreasingOffset { prev_offset: u64, next_offset: u64 },

    #[error("parts must be contiguous in v0.1.x (found gap/overlap: prev_end={prev_end}, next_offset={next_offset})")]
    PartsNotContiguous { prev_end: u64, next_offset: u64 },

    #[error("part_number must be > 0 (part index {index})")]
    InvalidPartNumber { index: usize },

    #[error("part length must be > 0 (part index {index})")]
    InvalidPartLength { index: usize },

    #[error("part stored_length must be > 0 (part index {index})")]
    InvalidStoredLength { index: usize },

    #[error("compression must not be unspecified (part index {index})")]
    CompressionUnspecified { index: usize },

    #[error("relative_path must be relative and must not contain '..' (part index {index}): {relative_path:?}")]
    InvalidRelativePath { index: usize, relative_path: String },

    #[error("tag/extension key is invalid ({location}): {key:?}")]
    InvalidKey { location: &'static str, key: String },

    #[error("hash alg must not be unspecified (part index {index})")]
    HashAlgUnspecified { index: usize },

    #[error("hash digest must not be empty (part index {index})")]
    EmptyHashDigest { index: usize },

    #[error("missing required hash (part index {index}): {alg}")]
    MissingRequiredHash { index: usize, alg: &'static str },

    #[error("duplicate required hash (part index {index}): {alg}")]
    DuplicateRequiredHash { index: usize, alg: &'static str },

    #[error("invalid digest length for {alg} (part index {index}): expected {expected} bytes, got {actual}")]
    InvalidDigestLength {
        index: usize,
        alg: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("stored_length must equal length when compression==none (part index {index})")]
    StoredLengthMustEqualLengthForNone { index: usize },
}

pub fn validate_manifest_basic(pb: &pbv1::ObjectManifest) -> Result<(), ManifestValidationError> {
    let v = semver::Version::parse(pb.manifest_version.trim())
        .ok()
        .filter(|v| v.pre.is_empty() && v.build.is_empty() && v.major == 0)
        .ok_or_else(|| ManifestValidationError::InvalidManifestVersion {
            manifest_version: pb.manifest_version.clone(),
        })?;
    let _ = v;

    if pb.object_id.trim().is_empty() {
        return Err(ManifestValidationError::MissingObjectId);
    }

    if pb.parts.is_empty() {
        return Err(ManifestValidationError::EmptyParts);
    }

    validate_keys("object tags", pb.tags.keys())?;
    validate_keys("object extensions", pb.extensions.keys())?;

    for (index, part) in pb.parts.iter().enumerate() {
        validate_part_basic(index, part)?;
    }

    validate_parts_order_and_coverage(pb)?;
    Ok(())
}

fn validate_part_basic(index: usize, part: &pbv1::PartMeta) -> Result<(), ManifestValidationError> {
    if part.part_number == 0 {
        return Err(ManifestValidationError::InvalidPartNumber { index });
    }
    if part.length == 0 {
        return Err(ManifestValidationError::InvalidPartLength { index });
    }
    if part.stored_length == 0 {
        return Err(ManifestValidationError::InvalidStoredLength { index });
    }

    if part.compression == pbv1::CompressionAlgorithm::Unspecified as i32 {
        return Err(ManifestValidationError::CompressionUnspecified { index });
    }
    if part.compression < 0 {
        return Err(ManifestValidationError::CompressionUnspecified { index });
    }
    if part.compression == pbv1::CompressionAlgorithm::None as i32
        && part.stored_length != part.length
    {
        return Err(ManifestValidationError::StoredLengthMustEqualLengthForNone { index });
    }

    if !part.relative_path.is_empty() {
        validate_relative_path(index, &part.relative_path)?;
    }

    validate_keys("part tags", part.tags.keys())?;
    validate_keys("part extensions", part.extensions.keys())?;

    validate_hashes(index, &part.hashes)?;
    Ok(())
}

fn validate_relative_path(
    index: usize,
    relative_path: &str,
) -> Result<(), ManifestValidationError> {
    let path = Path::new(relative_path);
    let mut invalid = path.is_absolute();

    for component in path.components() {
        use std::path::Component;

        match component {
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                invalid = true;
                break;
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }

    if invalid {
        return Err(ManifestValidationError::InvalidRelativePath {
            index,
            relative_path: relative_path.to_string(),
        });
    }
    Ok(())
}

fn validate_parts_order_and_coverage(
    pb: &pbv1::ObjectManifest,
) -> Result<(), ManifestValidationError> {
    let Some(first) = pb.parts.first() else {
        return Err(ManifestValidationError::EmptyParts);
    };
    if first.offset != 0 {
        return Err(ManifestValidationError::PartsMustStartAtZero {
            offset: first.offset,
        });
    }

    for window in pb.parts.windows(2) {
        let a = &window[0];
        let b = &window[1];

        if a.offset >= b.offset {
            return Err(ManifestValidationError::PartsNotStrictlyIncreasingOffset {
                prev_offset: a.offset,
                next_offset: b.offset,
            });
        }

        let prev_end = a.offset.saturating_add(a.length);
        if prev_end != b.offset {
            return Err(ManifestValidationError::PartsNotContiguous {
                prev_end,
                next_offset: b.offset,
            });
        }
    }

    let last = pb.parts.last().expect("non-empty");
    let expected_object_length = last.offset.saturating_add(last.length);
    if pb.object_length != expected_object_length {
        return Err(ManifestValidationError::ObjectLengthMismatch {
            expected: expected_object_length,
            actual: pb.object_length,
        });
    }

    Ok(())
}

fn validate_hashes(
    index: usize,
    hashes: &[pbv1::HashDigest],
) -> Result<(), ManifestValidationError> {
    let mut seen_crc32c = false;
    let mut seen_blake3 = false;

    for hash in hashes {
        if hash.alg == pbv1::HashAlgorithm::Unspecified as i32 {
            return Err(ManifestValidationError::HashAlgUnspecified { index });
        }
        if hash.alg < 0 {
            return Err(ManifestValidationError::HashAlgUnspecified { index });
        }
        if hash.digest.is_empty() {
            return Err(ManifestValidationError::EmptyHashDigest { index });
        }

        match pbv1::HashAlgorithm::try_from(hash.alg).ok() {
            Some(pbv1::HashAlgorithm::Crc32c) => {
                if seen_crc32c {
                    return Err(ManifestValidationError::DuplicateRequiredHash {
                        index,
                        alg: "crc32c",
                    });
                }
                if hash.digest.len() != 4 {
                    return Err(ManifestValidationError::InvalidDigestLength {
                        index,
                        alg: "crc32c",
                        expected: 4,
                        actual: hash.digest.len(),
                    });
                }
                seen_crc32c = true;
            }
            Some(pbv1::HashAlgorithm::Blake3256) => {
                if seen_blake3 {
                    return Err(ManifestValidationError::DuplicateRequiredHash {
                        index,
                        alg: "blake3-256",
                    });
                }
                if hash.digest.len() != 32 {
                    return Err(ManifestValidationError::InvalidDigestLength {
                        index,
                        alg: "blake3-256",
                        expected: 32,
                        actual: hash.digest.len(),
                    });
                }
                seen_blake3 = true;
            }
            _ => {
                // Unknown algorithms are allowed in v0.1.x.
            }
        }
    }

    if !seen_crc32c {
        return Err(ManifestValidationError::MissingRequiredHash {
            index,
            alg: "crc32c",
        });
    }
    if !seen_blake3 {
        return Err(ManifestValidationError::MissingRequiredHash {
            index,
            alg: "blake3-256",
        });
    }
    Ok(())
}

fn validate_keys<'a, I>(location: &'static str, keys: I) -> Result<(), ManifestValidationError>
where
    I: IntoIterator<Item = &'a String>,
{
    for key in keys {
        if !is_valid_map_key(key) {
            return Err(ManifestValidationError::InvalidKey {
                location,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn is_valid_map_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 128 || !key.is_ascii() {
        return false;
    }

    let mut iter = key.as_bytes().iter().copied();
    let Some(first) = iter.next() else {
        return false;
    };
    if !is_ascii_alnum(first) {
        return false;
    }

    for b in iter {
        if is_ascii_alnum(b) || b == b'_' || b == b'.' || b == b'-' {
            continue;
        }
        return false;
    }
    true
}

fn is_ascii_alnum(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn spec_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/omnisstream-spec")
    }

    fn read_spec(rel: &str) -> Vec<u8> {
        std::fs::read(spec_root().join(rel)).expect("read spec file")
    }

    #[test]
    fn parse_and_validate_vector_minimal() {
        let bytes = read_spec("test-vectors/vector-minimal/manifest.pb");
        let manifest = Manifest::from_pb_bytes(&bytes).expect("decode");
        manifest.validate_basic().expect("validate");
    }

    #[test]
    fn parse_and_validate_vector_compressed() {
        let bytes = read_spec("test-vectors/vector-compressed/manifest.pb");
        let manifest = Manifest::from_pb_bytes(&bytes).expect("decode");
        manifest.validate_basic().expect("validate");
    }

    #[test]
    fn validate_rejects_missing_object_id() {
        let bytes = read_spec("test-vectors/vector-minimal/manifest.pb");
        let mut pb = Manifest::from_pb_bytes(&bytes).unwrap().into_pb();
        pb.object_id.clear();
        let err = Manifest::new(pb).validate_basic().unwrap_err();
        assert!(matches!(err, ManifestValidationError::MissingObjectId));
    }

    #[test]
    fn validate_rejects_out_of_order_parts() {
        let bytes = read_spec("test-vectors/vector-minimal/manifest.pb");
        let mut pb = Manifest::from_pb_bytes(&bytes).unwrap().into_pb();
        pb.parts.swap(0, 1);
        let err = Manifest::new(pb).validate_basic().unwrap_err();
        assert!(matches!(
            err,
            ManifestValidationError::PartsNotStrictlyIncreasingOffset { .. }
                | ManifestValidationError::PartsMustStartAtZero { .. }
                | ManifestValidationError::PartsNotContiguous { .. }
        ));
    }

    #[test]
    fn validate_rejects_object_length_mismatch() {
        let bytes = read_spec("test-vectors/vector-minimal/manifest.pb");
        let mut pb = Manifest::from_pb_bytes(&bytes).unwrap().into_pb();
        pb.object_length += 1;
        let err = Manifest::new(pb).validate_basic().unwrap_err();
        assert!(matches!(
            err,
            ManifestValidationError::ObjectLengthMismatch { .. }
        ));
    }
}
