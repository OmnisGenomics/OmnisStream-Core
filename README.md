# OmnisStream Core

Rust workspace implementing the OmnisStream core formats plus storage primitives.

The canonical specification is vendored as a git submodule at `spec/omnisstream-spec`.

Performance benchmarks live in the OmnisStream Service repo: https://github.com/OmnisGenomics/omnisstream-service#benchmarks

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

* Nix with flakes enabled
* Git with submodules enabled for direct Cargo development

## First run for operators

Start with [docs/first-run.md](docs/first-run.md) for the supported clone,
submodule, validation, CLI, and troubleshooting path.

For the short path:

```sh
git submodule update --init --recursive
nix build
nix flake check
cd spec/omnisstream-spec
python3 -m venv .venv
. .venv/bin/activate
pip install -e tools/validator
python -m unittest discover -s tools/validator/tests
```

If the validator package is installed from `spec/omnisstream-spec`, the
`omnisstream-validate` command can be used directly for manifest checks.
Run `bash scripts/check-first-run-docs.sh` to verify the first-run documentation
still references supported commands.

## Get the spec submodule

```sh
git submodule update --init --recursive
```

## Build

```sh
nix build
```

## Test

```sh
nix flake check
```

## Quick start with release artifacts

Download the zip for your platform from GitHub Releases:

Linux x86_64: `omnisstream-vX.Y.Z-x86_64-unknown-linux-gnu.zip`

Unzip and run:

```sh
./omnisstream version
./omnisstream --help
```

Verify the downloaded zips against the published SHA256SUMS, then after unzip verify the package contents SHA256SUMS:

```sh
# In the directory containing the downloaded release assets:
sha256sum -c SHA256SUMS

# After unzip:
sha256sum -c SHA256SUMS
```

## CLI (development)

Run the workspace CLI crate:

```sh
cargo run -p omnisstream_cli -- --help
```

## Examples (spec vectors)

Inspect a manifest:

```sh
cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
```

Verify stored payload bytes against the manifest hashes:

```sh
cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
```

Reconstruct object bytes (writes raw bytes to stdout):

```sh
cargo run -p omnisstream_cli -- cat spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb > /tmp/vector-minimal.out
```

Read an arbitrary byte range:

```sh
cargo run -p omnisstream_cli -- range spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb 4 5
```

## Common dev checks

CI runs these through `nix flake check`. For direct Cargo development, enter
the flake shell first:

```sh
nix develop
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

This repository is licensed under the Apache License, Version 2.0. See LICENSE.

The specification is vendored as a git submodule at spec/omnisstream-spec and is licensed separately. See spec/omnisstream-spec/LICENSE.
