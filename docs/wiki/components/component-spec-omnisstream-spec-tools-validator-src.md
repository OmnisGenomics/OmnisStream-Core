---
page_id: component-component:spec/omnisstream-spec/tools/validator/src
page_type: component
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.804Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "5eb47c293942aa37e24974f9a0b1963a33cd12cf",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "docs/ffi_cmake.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface.json",
    "ingest:file:target/debug/build/cbindgen-741b44f13a1fd46a/out/tests.rs",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface.json",
    "ingest:file:target/debug/build/cbindgen-741b44f13a1fd46a/out/tests.rs",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# spec/omnisstream-spec/tools/validator/src

Source module rooted at spec/omnisstream-spec/tools/validator/src.

## Related Pages

- [components](components.md)
- [workflows](workflows.md)
- [interfaces](interfaces.md)
- [dependencies](dependencies.md)

## Implementation Roles

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
Role classification: inferred validator.
Proved signals:
- Defines validation-like symbols `validate_manifest`.
- Participates in 12 connected call edges.
- Exports 2 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit enforces checks or normalizes inputs before downstream work proceeds.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
Role classification: inferred execution boundary.
Proved signals:
- Defines execution-like symbols `main`.
- Participates in 3 connected call edges.
- Exports 1 symbol on the visible component surface.
Why this role fits: These proved signals suggest this unit is a first-hop execution boundary that receives control and hands it into component logic.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
Role classification: inferred state owner.
Proved signals:
- Defines state-change or persistence-like symbols `CommitMeta`.
- Participates in 5 connected call edges.
- Exports 5 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit owns durable, cached, or mutation-heavy state transitions inside the component.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:36`

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:36`
</details>

## Module Responsibilities

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
Role: Core implementation module.
Primary behavior: Exports `req_str` (function), `req_int` (function), `load_manifest` (function), which makes this one of the visible implementation surfaces for `spec/omnisstream-spec/tools/validator/src`.
Why this module matters: 3 exported symbols make this file part of the component's public surface. 17 connected call edges mark this file as implementation-active.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:135`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:141`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
Role: Core implementation module.
Primary behavior: Exports `ValidationIssue` (class), `validate_manifest` (function), which makes this one of the visible implementation surfaces for `spec/omnisstream-spec/tools/validator/src`.
Why this module matters: 2 exported symbols make this file part of the component's public surface. 12 connected call edges mark this file as implementation-active.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:16`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`

### `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
Role: Data model and schema module.
Primary behavior: Exports `HashDigest` (class), `PartMeta` (class), `UploadSession` (class), which makes this one of the visible implementation surfaces for `spec/omnisstream-spec/tools/validator/src`.
Why this module matters: 5 exported symbols make this file part of the component's public surface. 5 connected call edges mark this file as implementation-active.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:7`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:13`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:26`

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:135`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:141`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:16`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:7`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:13`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:26`
</details>

## Key Symbols

### `validate_manifest` (function)
Behavior: Validates or guards a code path in `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`. It directly calls `exists`, `get`.
Receives: Called by `main`, `test_corrupt_byte_fails`, `test_vector_compressed_passes`.
Produces or triggers: Triggers `exists`, `get`, `blake3_256`.
Connected symbols:
- Callers: `main`, `test_corrupt_byte_fails`, `test_vector_compressed_passes`.
- Callees: `exists`, `get`, `blake3_256`.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`
- `crates/omnisstream/src/part_store.rs:41`

### `_from_protobuf` (function)
Behavior: Implements component logic in `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py` by coordinating nearby symbol calls. It directly calls `bytes`, `_compression_name_from_proto`.
Receives: Called by `load_manifest`.
Produces or triggers: Triggers `bytes`, `_compression_name_from_proto`, `_hash_alg_name_from_proto`.
Connected symbols:
- Callers: `load_manifest`.
- Callees: `bytes`, `_compression_name_from_proto`, `_hash_alg_name_from_proto`.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:77`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`
- `crates/omnisstream_benchdiff/src/main.rs:481`

### `load_manifest` (function)
Behavior: Reads or loads data or dependencies for `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`. It directly calls `exists`, `_fmt_from_path`.
Receives: Called by `main`.
Produces or triggers: Triggers `exists`, `_fmt_from_path`, `_from_json`.
Connected symbols:
- Callers: `main`.
- Callees: `exists`, `_fmt_from_path`, `_from_json`.
Supporting implementation citations:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`
- `crates/omnisstream/src/part_store.rs:41`

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`
- `crates/omnisstream/src/part_store.rs:41`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:77`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`
- `crates/omnisstream_benchdiff/src/main.rs:481`
</details>

## State Boundaries

Validated at:
- Likely validated at `validate_manifest` in `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`; this is inferred from validation-like naming rather than proved full program semantics. Validate with the README-backed workflow from `spec/omnisstream-spec`: expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`. Run `cargo build` (build) from `.`.

Mutated in:
- none

Persisted or emitted through:
- Likely persisted or emitted through `CommitMeta` in `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`; this is inferred from persistence/emission naming and nearby implementation context. Recheck with the README-backed workflow from `spec/omnisstream-spec`: expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:36`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:36`
</details>

## State Ownership and Handoffs

Insufficient evidence to infer state ownership and handoffs confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Request Lifecycle

Insufficient evidence to infer a bounded request lifecycle confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Responsibilities

Source module rooted at spec/omnisstream-spec/tools/validator/src.

Type: module
Root path: `spec/omnisstream-spec/tools/validator/src`
Ecosystem: unknown

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:67`
</details>

## Entrypoints and Runtime Surface

- none

## Interfaces and Config

- none

## Dependencies and Relationships

- `component:docs` documents `component:spec/omnisstream-spec/tools/validator/src` (medium)
- `repository` contains `component:spec/omnisstream-spec/tools/validator/src` (high)
- `component:tests` tests `component:spec/omnisstream-spec/tools/validator/src` (high)

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:67`
</details>

## Why This Hotspot Matters

Architectural role: Hotspot score 156 with 24 inbound and 27 outbound inferred edges marks `spec/omnisstream-spec/tools/validator/src` as a coordination-heavy component. It bridges `crates`.

Main coupling surfaces:
- Coupled components: `Documentation`, `Tests`.
- Call-heavy surface with 51 inferred call edges.

Likely failure modes:
- Upstream breakage risk: 24 inbound edges suggest downstream callers depend on this boundary staying stable.
- Coordination risk: 27 outbound edges mean changes can ripple into neighboring components.
- Cross-subsystem regression risk: changes can disrupt handoffs across `crates`.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:67`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream/tests/api_surface.rs`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:67`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
</details>

## Operational Risk Surface

Likely fault domains:
- Cross-subsystem handoffs: `crates`.

High-cost dependencies:
- 24 inbound edges raise the cost of breaking this component's callers.

First validation checks:
- From `spec/omnisstream-spec`, expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`.
- Run `cargo build` (build) from `.`.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Invariants and Failure Handling

Insufficient evidence to infer invariants and failure handling confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Where to Edit

Likely change entry files:
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with the README-backed workflow from `spec/omnisstream-spec`: expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Cross-subsystem risk touches `crates`.
- Hotspot score 156 with 24 inbound and 27 outbound edges suggests higher coordination risk.

Suggested verification steps:
- Validate with the README-backed workflow from `spec/omnisstream-spec`: expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:50`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:24`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:36`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:135`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:141`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:218`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py:16`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:7`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:13`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py:26`
- `crates/omnisstream/src/part_store.rs:41`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:77`
- `crates/omnisstream_benchdiff/src/main.rs:481`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py:67`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
