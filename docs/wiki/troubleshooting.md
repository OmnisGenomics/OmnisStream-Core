---
page_id: troubleshooting
page_type: troubleshooting
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.287Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "2c7814a59551eae33da5ebd5bd9afb64a2b30f2b",
  "plannerReason": "Generated when enough deterministic runtime, hotspot, and validation evidence exists to assemble a bounded troubleshooting guide.",
  "changedPaths": [],
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

# Troubleshooting

Failure-first inspection guide for OmnisStream-Core.

## Related Pages

- [playbook](playbook.md)
- [runtime](runtime.md)
- [components](components.md)
- [testing](testing.md)

## First Inspection Points

- Reproduce the failure through `omnisstream-validate` (run) from `spec/omnisstream-spec/tools/validator`.
- Inspect omnisstream at `crates/omnisstream`.
- Inspect crates/omnisstream/src at `crates/omnisstream/src`.
- Inspect spec/omnisstream-spec/tools/validator/src at `spec/omnisstream-spec/tools/validator/src`.
- Inspect omnisstream_cli at `crates/omnisstream_cli` via `crates/omnisstream_cli/src/main.rs`.

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
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
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

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

## Likely Failure Boundaries

- crates/omnisstream/src: score 1797; watch inbound 297, outbound 300, and 2 bridged subsystem boundaries from `crates/omnisstream/src`.
- omnisstream: score 264; watch inbound 38, outbound 49, and 1 bridged subsystem boundary from `crates/omnisstream_cli/src`.
- omnisstream_benchdiff: score 255; watch inbound 41, outbound 42, and 2 bridged subsystem boundaries from `crates/omnisstream_benchdiff/src`.
- omnisstream: score 174; watch inbound 28, outbound 29, and 1 bridged subsystem boundary from `crates/omnisstream`.

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
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
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

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

## Relevant Validation Commands

- Run `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator` after reproducing or patching the issue.
- Run `cargo build` (build) from `.` after reproducing or patching the issue.
- Run `cargo check` (check) from `.` after reproducing or patching the issue.
- Run `cargo test` (test) from `.` after reproducing or patching the issue.
- If needed, re-run `omnisstream-validate` to verify the runtime path after the fix.

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
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
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

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
