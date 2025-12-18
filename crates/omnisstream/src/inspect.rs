use crate::manifest::Manifest;
use crate::pb::omnisstream::v1 as pbv1;

pub fn format_manifest(manifest: &Manifest) -> String {
    let pb = manifest.pb();
    let mut out = String::new();

    push_kv(&mut out, "manifest_version", &pb.manifest_version);
    push_kv(&mut out, "object_id", &pb.object_id);
    push_kv(&mut out, "object_length", &pb.object_length.to_string());
    push_kv(&mut out, "part_count", &pb.parts.len().to_string());

    if let Some(upload) = &pb.upload_session {
        out.push_str("\n[upload_session]\n");
        push_kv(&mut out, "upload_id", &upload.upload_id);
        push_kv(&mut out, "state", &enum_name_upload_state(upload.state));
        push_kv(
            &mut out,
            "created_unix_ms",
            &upload.created_unix_ms.to_string(),
        );
        push_kv(
            &mut out,
            "updated_unix_ms",
            &upload.updated_unix_ms.to_string(),
        );
        push_map(&mut out, "tags", &upload.tags, |v| v.clone());
        push_map(&mut out, "extensions", &upload.extensions, |v| {
            hex::encode(v)
        });
    }

    if let Some(commit) = &pb.commit {
        out.push_str("\n[commit]\n");
        push_kv(&mut out, "commit_id", &commit.commit_id);
        push_kv(
            &mut out,
            "committed_unix_ms",
            &commit.committed_unix_ms.to_string(),
        );
    }

    if !pb.tags.is_empty() || !pb.extensions.is_empty() {
        out.push_str("\n[object]\n");
        push_map(&mut out, "tags", &pb.tags, |v| v.clone());
        push_map(&mut out, "extensions", &pb.extensions, |v| hex::encode(v));
    }

    for (idx, part) in pb.parts.iter().enumerate() {
        out.push_str(&format!("\n[part {}]\n", idx + 1));
        push_kv(&mut out, "part_number", &part.part_number.to_string());
        push_kv(&mut out, "offset", &part.offset.to_string());
        push_kv(&mut out, "length", &part.length.to_string());
        push_kv(&mut out, "stored_length", &part.stored_length.to_string());
        push_kv(
            &mut out,
            "compression",
            &enum_name_compression(part.compression),
        );
        if !part.relative_path.is_empty() {
            push_kv(&mut out, "relative_path", &part.relative_path);
        }

        let mut hashes = part.hashes.clone();
        hashes.sort_by_key(|h| h.alg);
        for h in hashes {
            let alg = enum_name_hash_alg(h.alg);
            out.push_str(&format!("hash.{alg} = {}\n", hex::encode(h.digest)));
        }

        push_map(&mut out, "tags", &part.tags, |v| v.clone());
        push_map(&mut out, "extensions", &part.extensions, |v| hex::encode(v));
    }

    out
}

fn push_kv(out: &mut String, k: &str, v: &str) {
    out.push_str(k);
    out.push_str(" = ");
    out.push_str(v);
    out.push('\n');
}

fn push_map<V, F>(out: &mut String, name: &str, map: &std::collections::HashMap<String, V>, f: F)
where
    F: Fn(&V) -> String,
{
    if map.is_empty() {
        return;
    }
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys {
        out.push_str(name);
        out.push('.');
        out.push_str(k);
        out.push_str(" = ");
        out.push_str(&f(&map[k]));
        out.push('\n');
    }
}

fn enum_name_hash_alg(alg: i32) -> String {
    match pbv1::HashAlgorithm::try_from(alg).ok() {
        Some(pbv1::HashAlgorithm::Crc32c) => "crc32c".to_string(),
        Some(pbv1::HashAlgorithm::Blake3256) => "blake3_256".to_string(),
        Some(pbv1::HashAlgorithm::Unspecified) | None => format!("unknown_{alg}"),
    }
}

fn enum_name_compression(alg: i32) -> String {
    match pbv1::CompressionAlgorithm::try_from(alg).ok() {
        Some(pbv1::CompressionAlgorithm::None) => "none".to_string(),
        Some(pbv1::CompressionAlgorithm::ZstdSeekable) => "zstd_seekable".to_string(),
        Some(pbv1::CompressionAlgorithm::Bgzf) => "bgzf".to_string(),
        Some(pbv1::CompressionAlgorithm::Unspecified) | None => format!("unknown_{alg}"),
    }
}

fn enum_name_upload_state(state: i32) -> String {
    match pbv1::UploadSessionState::try_from(state).ok() {
        Some(pbv1::UploadSessionState::Pending) => "pending".to_string(),
        Some(pbv1::UploadSessionState::Complete) => "complete".to_string(),
        Some(pbv1::UploadSessionState::Aborted) => "aborted".to_string(),
        Some(pbv1::UploadSessionState::Unspecified) | None => format!("unknown_{state}"),
    }
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
    fn inspect_is_deterministic() {
        let manifest = load_manifest("vector-minimal");
        assert_eq!(format_manifest(&manifest), format_manifest(&manifest));
    }

    #[test]
    fn inspect_works_on_both_vectors() {
        for vector in ["vector-minimal", "vector-compressed"] {
            let manifest = load_manifest(vector);
            let out = format_manifest(&manifest);
            assert!(out.contains("object_id = "));
            assert!(out.contains("part_count = "));
        }
    }
}
