use crate::hashing::Blake3Digest;

#[derive(Clone, Copy, Debug)]
pub struct ObjectVersionEntry {
    pub part_number: u32,
    pub length: u64,
    pub blake3_256: Blake3Digest,
}

/// Computes a deterministic object version identifier from the ordered part list.
///
/// This is a format-internal identifier (not the protobuf manifest hash). It is stable across
/// re-ingest as long as the part boundaries and stored payload bytes are unchanged.
pub fn compute_object_version(entries: &[ObjectVersionEntry]) -> Blake3Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"omnisstream.object_version.v0\n");

    for e in entries {
        hasher.update(&e.part_number.to_be_bytes());
        hasher.update(&e.length.to_be_bytes());
        hasher.update(e.blake3_256.as_bytes());
    }

    Blake3Digest::from_bytes(*hasher.finalize().as_bytes())
}
