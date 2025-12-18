# OmnisStream Core

Rust workspace implementing the OmnisStream core formats and storage primitives.

This repository vendors the spec as a git submodule at `spec/omnisstream-spec`.

```bash
git submodule update --init --recursive
```

## Build

```bash
cargo build
```

## Test

```bash
cargo test
```

## CLI

```bash
cargo run -p omnisstream_cli -- --help
```

### Examples (spec vectors)

```bash
# Inspect a manifest
cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb

# Verify stored payload bytes against the manifest hashes
cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb

# Reconstruct object bytes (writes raw bytes to stdout)
cargo run -p omnisstream_cli -- cat spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb > /tmp/vector-minimal.out

# Read an arbitrary byte range
cargo run -p omnisstream_cli -- range spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb 4 5
```
