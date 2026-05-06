---
page_id: playbook
page_type: playbook
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:02:00.909Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "234ab09467a0c213aa1b93cf97edb8545f24f754",
  "plannerReason": "Generated when enough workflow, runtime, and hotspot evidence exists to assemble an operational guide.",
  "changedPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "crates/omnisstream/build.rs",
    "crates/omnisstream/Cargo.toml",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream_benchdiff/Cargo.toml"
  ],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "crates/omnisstream/build.rs",
    "crates/omnisstream/Cargo.toml",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream_benchdiff/Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml"
  ],
  "evidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Playbook

Operational guide for validating and debugging OmnisStream-Core.

## Related Pages

- [workflows](workflows.md)
- [testing](testing.md)
- [runtime](runtime.md)
- [components](components.md)

## Validation Order

1. Run `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`.
2. Run `cargo build` (build) from `.`.
3. Run `cargo check` (check) from `.`.
4. Run `cargo test` (test) from `.`.

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Debugging Entrypoints

- Start from workflow `omnisstream-validate` (run).
- Inspect omnisstream at `crates/omnisstream`.
- Inspect crates/omnisstream/src at `crates/omnisstream/src`.
- Inspect spec/omnisstream-spec/tools/validator/src at `spec/omnisstream-spec/tools/validator/src`.
- Inspect omnisstream_cli at `crates/omnisstream_cli` via `crates/omnisstream_cli/src/main.rs`.

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
</details>

## Change-Safety Notes

- crates/omnisstream/src: score 1797; validate around inbound 297, outbound 300, and 2 bridged subsystem boundaries.
- omnisstream: score 276; validate around inbound 40, outbound 51, and 1 bridged subsystem boundary.
- omnisstream_benchdiff: score 255; validate around inbound 41, outbound 42, and 2 bridged subsystem boundaries.

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>
