# OmnisStream Core

Rust workspace implementing the OmnisStream core formats plus storage primitives.

The canonical specification is vendored as a git submodule at `spec/omnisstream-spec`.

## What’s in here

* Core data model and hashing
* Manifest and payload verification
* Storage primitives used by higher level services
* CLI for inspecting and validating spec vectors

## Repository layout

* `spec/omnisstream-spec`  Spec submodule plus test vectors
* `crates/`  Workspace crates
* `omnisstream_cli`  CLI crate (invoked via Cargo during development)

## Prerequisites

* Rust toolchain (stable)
* Git with submodules enabled

## Get the spec submodule
`git submodule update --init --recursive`
## Build
`cargo build`
## Test
`cargo test`
Quick start with release artifacts
Download the zip for your platform from GitHub Releases:

Linux x86_64: `omnisstream-vX.Y.Z-x86_64-unknown-linux-gnu.zip`

Windows x86_64: `omnisstream-vX.Y.Z-x86_64-pc-windows-msvc.zip`

Unzip and run:

`./omnisstream version`
`./omnisstream --help`
Verify the downloaded zips against the published SHA256SUMS, then after unzip verify the package contents SHA256SUMS:

# In the directory containing the downloaded release assets:
`sha256sum -c SHA256SUMS`

# After unzip:
`sha256sum -c SHA256SUMS`

#CLI (development)
## Run the workspace CLI crate:
`cargo run -p omnisstream_cli -- --help`
## Examples (spec vectors)

# Inspect a manifest
`cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`

# Verify stored payload bytes against the manifest hashes
`cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`

# Reconstruct object bytes (writes raw bytes to stdout)
`cargo run -p omnisstream_cli -- cat spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb > /tmp/vector-minimal.out`

# Read an arbitrary byte range
`cargo run -p omnisstream_cli -- range spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb 4 5`
Common dev checks (optional but recommended)

`cargo fmt --all`
`cargo clippy --all-targets --all-features`
