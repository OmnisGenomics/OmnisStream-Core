use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../spec/omnisstream-spec/proto");
    let manifest_proto = proto_root.join("omnisstream/v1/manifest.proto");

    println!("cargo:rerun-if-changed={}", manifest_proto.display());

    prost_build::Config::new().compile_protos(&[manifest_proto], &[proto_root])?;
    Ok(())
}
