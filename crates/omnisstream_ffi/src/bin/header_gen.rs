use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = crate_dir.join("cbindgen.toml");
    let config = cbindgen::Config::from_file(&config_path)?;

    let bindings = cbindgen::generate_with_config(&crate_dir, config)?;

    let header_path = crate_dir.join("../../include/omnisstream_ffi.h");
    if let Some(parent) = header_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    bindings.write_to_file(header_path);
    Ok(())
}
