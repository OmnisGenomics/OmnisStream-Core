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

## Quick start (release artifacts)

Download the zip for your platform from GitHub Releases:

- Linux x86_64: `omnisstream-vX.Y.Z-x86_64-unknown-linux-gnu.zip`
- Windows x86_64: `omnisstream-vX.Y.Z-x86_64-pc-windows-msvc.zip`

Unzip and run:

```bash
./omnisstream version
./omnisstream --help
```

Verify the downloaded zips against the published `SHA256SUMS`, then (after unzip) verify the package contents `SHA256SUMS`:

```bash
# In the directory containing the downloaded release assets:
sha256sum -c SHA256SUMS

# After unzip:
sha256sum -c SHA256SUMS
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
