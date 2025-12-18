use omnisstream::{ingest_file, Manifest, PartStore, Reader, UploadSession};

#[test]
fn api_surface_allows_core_workflows() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let repo_root = dir.path().join("repo");

    // Part store + uploads.
    let session = UploadSession::create(&repo_root, "object-1")?;
    session.put_part(1, b"hello")?;
    session.put_part(2, b"world")?;

    let (manifest, _version) = session.complete()?;
    manifest.validate_basic()?;

    // Reader (digest-addressed) verify + cat.
    let part_store = PartStore::new(repo_root.join("parts"))?;
    let reader = Reader::new(manifest, &repo_root).with_part_store(part_store);

    reader.verify()?;
    let mut out = Vec::new();
    reader.cat(&mut out)?;
    assert_eq!(out, b"helloworld");

    // Ingest.
    let input_path = dir.path().join("input.bin");
    std::fs::write(&input_path, b"abcdefghij")?;
    let ingest = ingest_file(&repo_root, &input_path, 4)?;

    let part_store = PartStore::new(repo_root.join("parts"))?;
    let reader = Reader::new(ingest.manifest, ingest.manifest_path.parent().unwrap())
        .with_part_store(part_store);
    reader.verify()?;

    let mut out = Vec::new();
    reader.cat(&mut out)?;
    assert_eq!(out, b"abcdefghij");

    Ok(())
}

#[test]
fn manifest_roundtrips_pb_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let spec_manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb");
    let bytes = std::fs::read(spec_manifest)?;
    let manifest = Manifest::from_pb_bytes(&bytes)?;
    manifest.validate_basic()?;
    let out = manifest.to_pb_bytes();
    assert!(!out.is_empty());
    Ok(())
}
