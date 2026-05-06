---
page_id: component-component:crates/omnisstream/src
page_type: component
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:01:38.886Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "e1b658f035583908e584e7dc27cebf211589d417",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [
    "crates/omnisstream/src/hashing.rs",
    "crates/omnisstream/src/reader.rs",
    "crates/omnisstream/src/part_store.rs",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/manifest.rs",
    "crates/omnisstream/src/upload.rs",
    "crates/omnisstream/src/group_commit.rs",
    "crates/omnisstream/src/repo.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "crates/omnisstream/src/ingest_backend.rs",
    "crates/omnisstream/src/inspect.rs",
    "crates/omnisstream/src",
    "docs/ffi_cmake.md",
    "docs/monarchic-launch.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/.editorconfig",
    "spec/omnisstream-spec/.gitignore",
    "spec/omnisstream-spec/CANONICAL_JSON.md",
    "spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyPaths": [
    "crates/omnisstream/src/hashing.rs",
    "crates/omnisstream/src/reader.rs",
    "crates/omnisstream/src/part_store.rs",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/manifest.rs",
    "crates/omnisstream/src/upload.rs",
    "crates/omnisstream/src/group_commit.rs",
    "crates/omnisstream/src/repo.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "crates/omnisstream/src/ingest_backend.rs",
    "crates/omnisstream/src/inspect.rs",
    "crates/omnisstream/src",
    "docs/ffi_cmake.md",
    "docs/monarchic-launch.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/.editorconfig",
    "spec/omnisstream-spec/.gitignore",
    "spec/omnisstream-spec/CANONICAL_JSON.md",
    "spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream_bench/src/main.rs",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:crates/omnisstream_cli/src/main.rs",
    "ingest:file:crates/omnisstream_ffi/src/lib.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/object_version.rs",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:crates/omnisstream/src/repo.rs",
    "ingest:file:crates/omnisstream/src/upload.rs",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:docs/monarchic-launch.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:spec/omnisstream-spec/.gitignore",
    "ingest:file:spec/omnisstream-spec/CANONICAL_JSON.md",
    "ingest:file:spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "ingest:file:spec/omnisstream-spec/CONTRIBUTING.md",
    "ingest:file:spec/omnisstream-spec/LICENSE",
    "ingest:file:spec/omnisstream-spec/MANIFEST_SPEC.md",
    "ingest:file:spec/omnisstream-spec/NOTICE",
    "ingest:file:spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto",
    "ingest:file:spec/omnisstream-spec/proto/protoc.sh",
    "ingest:file:spec/omnisstream-spec/REPOSITORY_SPEC.md",
    "ingest:file:spec/omnisstream-spec/SECURITY.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:spec/omnisstream-spec/VERSIONING.md",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream_bench/src/main.rs",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:crates/omnisstream_cli/src/main.rs",
    "ingest:file:crates/omnisstream_ffi/src/lib.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/object_version.rs",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:crates/omnisstream/src/repo.rs",
    "ingest:file:crates/omnisstream/src/upload.rs",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:docs/monarchic-launch.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:spec/omnisstream-spec/.gitignore",
    "ingest:file:spec/omnisstream-spec/CANONICAL_JSON.md",
    "ingest:file:spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "ingest:file:spec/omnisstream-spec/CONTRIBUTING.md",
    "ingest:file:spec/omnisstream-spec/LICENSE",
    "ingest:file:spec/omnisstream-spec/MANIFEST_SPEC.md",
    "ingest:file:spec/omnisstream-spec/NOTICE",
    "ingest:file:spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto",
    "ingest:file:spec/omnisstream-spec/proto/protoc.sh",
    "ingest:file:spec/omnisstream-spec/REPOSITORY_SPEC.md",
    "ingest:file:spec/omnisstream-spec/SECURITY.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:spec/omnisstream-spec/VERSIONING.md",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# crates/omnisstream/src

Source module rooted at crates/omnisstream/src.

## Related Pages

- [components](../components.md)
- [workflows](../workflows.md)
- [interfaces](../interfaces.md)
- [dependencies](../dependencies.md)

## Implementation Roles

### `crates/omnisstream/src/hashing.rs`
Role classification: inferred validator.
Proved signals:
- Defines validation-like symbols `parse_expected_line`.
- Participates in 73 connected call edges.
- Exports 13 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit enforces checks or normalizes inputs before downstream work proceeds.
Supporting implementation citations:
- `crates/omnisstream/src/hashing.rs:99`

### `crates/omnisstream/src/reader.rs`
Role classification: inferred coordinator.
Proved signals:
- Defines boundary-oriented symbols `load_manifest`.
- Imports 3 repository-local paths.
- Participates in 52 connected call edges.
- Exports 4 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit mostly coordinates nearby collaborators instead of acting as a leaf implementation.
Supporting implementation citations:
- `crates/omnisstream/src/reader.rs:99`
- `crates/omnisstream/src/reader.rs:439`

### `crates/omnisstream/src/part_store.rs`
Role classification: inferred coordinator.
Proved signals:
- Imports 2 repository-local paths.
- Participates in 49 connected call edges.
- Exports 8 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit mostly coordinates nearby collaborators instead of acting as a leaf implementation.
Supporting implementation citations:
- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:19`

### `crates/omnisstream/src/api.rs`
Role classification: inferred state owner.
Proved signals:
- Defines state-change or persistence-like symbols `set_compression_config`, `set_group_commit_config`.
- Imports 1 repository-local path.
- Participates in 23 connected call edges.
- Exports 21 symbols on the visible component surface.
Why this role fits: These proved signals suggest this unit owns durable, cached, or mutation-heavy state transitions inside the component.
Supporting implementation citations:
- `crates/omnisstream/src/api.rs:69`
- `crates/omnisstream/src/api.rs:36`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/reader.rs`
- `crates/omnisstream/src/part_store.rs`
- `crates/omnisstream/src/api.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/hashing.rs:99`
- `crates/omnisstream/src/reader.rs:99`
- `crates/omnisstream/src/reader.rs:439`
- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:19`
- `crates/omnisstream/src/api.rs:69`
- `crates/omnisstream/src/api.rs:36`
</details>

## Module Responsibilities

### `crates/omnisstream/src/hashing.rs`
Role: Core implementation module.
Primary behavior: Exports `Crc32c` (class), `from_u32` (function), `value` (function), which makes this one of the visible implementation surfaces for `crates/omnisstream/src`.
Why this module matters: 13 exported symbols make this file part of the component's public surface. 73 connected call edges mark this file as implementation-active.
Supporting implementation citations:
- `crates/omnisstream/src/hashing.rs:4`
- `crates/omnisstream/src/hashing.rs:7`
- `crates/omnisstream/src/hashing.rs:11`

### `crates/omnisstream/src/manifest.rs`
Role: Core implementation module.
Primary behavior: Exports `Manifest` (class), `PartSpan` (class), `from_pb_bytes` (function), which makes this one of the visible implementation surfaces for `crates/omnisstream/src`.
Why this module matters: 14 exported symbols make this file part of the component's public surface. 63 connected call edges mark this file as implementation-active. Imports 1 distinct path, which suggests orchestration or integration work.
Supporting implementation citations:
- `crates/omnisstream/src/manifest.rs:9`
- `crates/omnisstream/src/manifest.rs:14`
- `crates/omnisstream/src/manifest.rs:34`

### `crates/omnisstream/src/upload.rs`
Role: Core implementation module.
Primary behavior: Exports `new` (function), `create` (function), `put_part` (function), which makes this one of the visible implementation surfaces for `crates/omnisstream/src`.
Why this module matters: 5 exported symbols make this file part of the component's public surface. 65 connected call edges mark this file as implementation-active. Imports 5 distinct paths, which suggests orchestration or integration work.
Supporting implementation citations:
- `crates/omnisstream/src/upload.rs:21`
- `crates/omnisstream/src/upload.rs:26`
- `crates/omnisstream/src/upload.rs:51`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/manifest.rs`
- `crates/omnisstream/src/upload.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/hashing.rs:4`
- `crates/omnisstream/src/hashing.rs:7`
- `crates/omnisstream/src/hashing.rs:11`
- `crates/omnisstream/src/manifest.rs:9`
- `crates/omnisstream/src/manifest.rs:14`
- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream/src/upload.rs:21`
- `crates/omnisstream/src/upload.rs:26`
- `crates/omnisstream/src/upload.rs:51`
</details>

## Key Symbols

### `from_pb_bytes` (function)
Behavior: Defines a visible implementation unit in `crates/omnisstream/src/manifest.rs` without strong downstream call evidence.
Receives: Called by `load_manifest`, `load_manifest`, `parse_and_validate_vector_compressed`.
Produces or triggers: Exports `from_pb_bytes` as part of the component's callable surface.
Connected symbols:
- Callers: `load_manifest`, `load_manifest`, `parse_and_validate_vector_compressed`.
Supporting implementation citations:
- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream_cli/src/main.rs:196`

### `complete` (function)
Behavior: Implements component logic in `crates/omnisstream/src/upload.rs` by coordinating nearby symbol calls. It directly calls `atomic_write_bytes`, `as_bytes`.
Receives: Called by `complete_is_idempotent`, `recovery_marks_complete_if_manifest_exists`, `resume_after_restart_completes`.
Produces or triggers: Triggers `atomic_write_bytes`, `as_bytes`, `read`.
Connected symbols:
- Callers: `complete_is_idempotent`, `recovery_marks_complete_if_manifest_exists`, `resume_after_restart_completes`.
- Callees: `atomic_write_bytes`, `as_bytes`, `read`.
Supporting implementation citations:
- `crates/omnisstream/src/upload.rs:101`
- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/fs_util.rs:20`

### `validate_basic` (function)
Behavior: Validates or guards a code path in `crates/omnisstream/src/manifest.rs`. It directly calls `validate_manifest_basic`.
Receives: Called by `parse_and_validate_vector_compressed`, `parse_and_validate_vector_minimal`, `part_store_digests_hex`.
Produces or triggers: Triggers `validate_manifest_basic`.
Connected symbols:
- Callers: `parse_and_validate_vector_compressed`, `parse_and_validate_vector_minimal`, `part_store_digests_hex`.
- Callees: `validate_manifest_basic`.
Supporting implementation citations:
- `crates/omnisstream/src/manifest.rs:43`
- `crates/omnisstream/src/manifest.rs:489`
- `crates/omnisstream/src/manifest.rs:198`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/manifest.rs`
- `crates/omnisstream/src/upload.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream_cli/src/main.rs:196`
- `crates/omnisstream/src/upload.rs:101`
- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/fs_util.rs:20`
- `crates/omnisstream/src/manifest.rs:43`
- `crates/omnisstream/src/manifest.rs:489`
- `crates/omnisstream/src/manifest.rs:198`
</details>

## State Boundaries

Validated at:
- Likely validated at `parse_expected_line` in `crates/omnisstream/src/hashing.rs`; this is inferred from validation-like naming rather than proved full program semantics. Validate with Run `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`. Run `cargo build` (build) from `.`.

Mutated in:
- Likely mutated in `create` in `crates/omnisstream/src/api.rs`; this marks an inferred state-change boundary, not a formal dataflow proof.

Persisted or emitted through:
- Likely persisted or emitted through `write` in `crates/omnisstream/src/repo.rs`; this is inferred from persistence/emission naming and nearby implementation context. Recheck with Run `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/hashing.rs:99`
- `crates/omnisstream/src/api.rs:121`
- `crates/omnisstream/src/repo.rs:371`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/manifest.rs`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/group_commit.rs`
- `crates/omnisstream/src/upload.rs`
- `crates/omnisstream/src/repo.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/hashing.rs:99`
- `crates/omnisstream/src/api.rs:121`
- `crates/omnisstream/src/repo.rs:371`
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

Source module rooted at crates/omnisstream/src.

Type: module
Root path: `crates/omnisstream/src`
Ecosystem: unknown

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src/group_commit.rs`
- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/ingest_backend.rs`
- `crates/omnisstream/src/inspect.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream/src/fs_util.rs:20`
</details>

## Entrypoints and Runtime Surface

- none

## Interfaces and Config

- none

## Dependencies and Relationships

Repository-owned edges:
- `repository` contains `component:crates/omnisstream/src` (high)
- `component:docs` documents `component:crates/omnisstream/src` (medium)
- `component:tests` tests `component:crates/omnisstream/src` (high)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream_backend_api/src/lib.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/durability.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream_backend_api/src/lib.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/manifest.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/hashing.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/hashing.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/fs_util.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/hashing.rs` (medium)
- `component:crates/omnisstream/src` depends_on `crates/omnisstream/src/hashing.rs` (medium)
- 15 more repository-owned dependency edges omitted from this page.
External dependency edges (bounded):
- `component:crates/omnisstream/src` depends_on `component:external:rust:prost` (medium)
- `component:crates/omnisstream/src` depends_on `component:external:rust:rayon` (medium)
- `component:crates/omnisstream/src` depends_on `component:external:rust:serde` (medium)

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src/group_commit.rs`
- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/ingest_backend.rs`
- `crates/omnisstream/src/inspect.rs`
- `crates/omnisstream/src`
- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/.gitignore`
- `spec/omnisstream-spec/CANONICAL_JSON.md`
- `spec/omnisstream-spec/CODE_OF_CONDUCT.md`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream/src/fs_util.rs:20`
</details>

## Why This Hotspot Matters

Architectural role: Hotspot score 1797 with 297 inbound and 300 outbound inferred edges marks `crates/omnisstream/src` as a coordination-heavy component. It bridges `external`, `spec`.

Main coupling surfaces:
- Coupled components: `Documentation`, `Tests`, `omnisstream_backend_api`, `omnisstream`.
- Call-heavy surface with 570 inferred call edges.
- Dependency-heavy surface with 27 inferred dependency edges.

Likely failure modes:
- Upstream breakage risk: 297 inbound edges suggest downstream callers depend on this boundary staying stable.
- Coordination risk: 300 outbound edges mean changes can ripple into neighboring components.
- Cross-subsystem regression risk: changes can disrupt handoffs across `external`, `spec`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream/src/fs_util.rs:20`
- `crates/omnisstream/src`
- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src`
- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream/src/fs_util.rs:20`
- `crates/omnisstream/src`
- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
</details>

## Operational Risk Surface

Likely fault domains:
- External dependency boundaries: `prost`, `rayon`, `serde`.
- Cross-subsystem handoffs: `external`, `spec`.

High-cost dependencies:
- `prost` acts as a external dependency boundary.
- `rayon` acts as a external dependency boundary.
- `serde` acts as a external dependency boundary.
- 297 inbound edges raise the cost of breaking this component's callers.

First validation checks:
- Run `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`.
- Run `cargo build` (build) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Invariants and Failure Handling

### `ensure_dir`
Guard condition: `ensure_dir` in `crates/omnisstream/src/fs_util.rs` is an explicit validation or guard-like symbol that likely enforces a precondition before downstream work proceeds.
Failure trigger: if the condition enforced by `ensure_dir` is not met, downstream callers are likely blocked or forced onto an error path; this is inferred from the guard-like symbol name rather than proved full-program control flow.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/fs_util.rs:65`
</details>

### `validate_manifest_basic`
Guard condition: `validate_manifest_basic` in `crates/omnisstream/src/manifest.rs` is an explicit validation or guard-like symbol that likely enforces a precondition before downstream work proceeds.
Failure trigger: if the condition enforced by `validate_manifest_basic` is not met, downstream callers are likely blocked or forced onto an error path; this is inferred from the guard-like symbol name rather than proved full-program control flow.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/manifest.rs:198`
</details>

### `validate_part_basic`
Guard condition: `validate_part_basic` in `crates/omnisstream/src/manifest.rs` is an explicit validation or guard-like symbol that likely enforces a precondition before downstream work proceeds.
Failure trigger: if the condition enforced by `validate_part_basic` is not met, downstream callers are likely blocked or forced onto an error path; this is inferred from the guard-like symbol name rather than proved full-program control flow.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/manifest.rs:232`
</details>

### `validate_relative_path`
Guard condition: `validate_relative_path` in `crates/omnisstream/src/manifest.rs` is an explicit validation or guard-like symbol that likely enforces a precondition before downstream work proceeds.
Failure trigger: if the condition enforced by `validate_relative_path` is not met, downstream callers are likely blocked or forced onto an error path; this is inferred from the guard-like symbol name rather than proved full-program control flow.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/manifest.rs:266`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src/manifest.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/fs_util.rs:65`
- `crates/omnisstream/src/manifest.rs:198`
- `crates/omnisstream/src/manifest.rs:232`
- `crates/omnisstream/src/manifest.rs:266`
</details>

## Where to Edit

Likely change entry files:
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Downstream components likely affected: `omnisstream_backend_api`, `omnisstream`, `prost`, `rayon`.
- Cross-subsystem risk touches `external`, `spec`.
- Hotspot score 1797 with 297 inbound and 300 outbound edges suggests higher coordination risk.

Suggested verification steps:
- Validate with `python -m unittest discover -s tools/validator/tests` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/hashing.rs:99`
- `crates/omnisstream/src/reader.rs:99`
- `crates/omnisstream/src/reader.rs:439`
- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:19`
- `crates/omnisstream/src/api.rs:69`
- `crates/omnisstream/src/api.rs:36`
- `crates/omnisstream/src/hashing.rs:4`
- `crates/omnisstream/src/hashing.rs:7`
- `crates/omnisstream/src/hashing.rs:11`
- `crates/omnisstream/src/manifest.rs:9`
- `crates/omnisstream/src/manifest.rs:14`
- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream/src/upload.rs:21`
- `crates/omnisstream/src/upload.rs:26`
- `crates/omnisstream/src/upload.rs:51`
- `crates/omnisstream_cli/src/main.rs:196`
- `crates/omnisstream/src/upload.rs:101`
- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/fs_util.rs:20`
- `crates/omnisstream/src/manifest.rs:43`
- `crates/omnisstream/src/manifest.rs:489`
- `crates/omnisstream/src/manifest.rs:198`
- `crates/omnisstream/src/api.rs:121`
- `crates/omnisstream/src/repo.rs:371`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream/src`
- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/src/fs_util.rs:65`
- `crates/omnisstream/src/manifest.rs:232`
- `crates/omnisstream/src/manifest.rs:266`
</details>
