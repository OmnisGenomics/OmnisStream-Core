---
page_id: component-component:cargo:crates/omnisstream
page_type: component
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.740Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "b04ed04533b7c71f76265b7374a1e0ccadc2b62f",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream/build.rs",
    "crates/omnisstream/tests/api_surface.rs",
    "crates/omnisstream/Cargo.toml",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "crates/omnisstream/src/group_commit.rs",
    "crates/omnisstream/src/hashing.rs",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_ffi/Cargo.toml",
    "crates/omnisstream_bench/src/main.rs",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:crates/omnisstream/build.rs",
    "component:crates/omnisstream/Cargo.toml",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
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
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
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
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "ingest:file:crates/omnisstream/build.rs",
    "component:crates/omnisstream/Cargo.toml",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
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
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
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
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# omnisstream

omnisstream rust component

## Related Pages

- [components](components.md)
- [workflows](workflows.md)
- [interfaces](interfaces.md)
- [dependencies](dependencies.md)

## Implementation Roles

### `crates/omnisstream/build.rs`
Role classification: inferred execution boundary.
Proved signals:
- Defines execution-like symbols `main`.
Why this role fits: These proved signals suggest this unit is a first-hop execution boundary that receives control and hands it into component logic.
Supporting implementation citations:
- `crates/omnisstream/build.rs:3`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
</details>

## Module Responsibilities

### `crates/omnisstream/build.rs`
Role: Internal implementation module.
Primary behavior: Defines `main` (function), suggesting local implementation behavior rather than a manifest-only surface.
Why this module matters:
Supporting implementation citations:
- `crates/omnisstream/build.rs:3`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
</details>

## Key Symbols

### `api_surface_allows_core_workflows` (function)
Behavior: Implements component logic in `crates/omnisstream/tests/api_surface.rs` by coordinating nearby symbol calls. It directly calls `cat`, `Reader`.
Receives: No strong upstream caller evidence was inferred.
Produces or triggers: Triggers `cat`, `Reader`, `verify`.
Connected symbols:
- Callees: `cat`, `Reader`, `verify`.
Supporting implementation citations:
- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream/src/api.rs:100`

### `manifest_roundtrips_pb_bytes` (function)
Behavior: Implements component logic in `crates/omnisstream/tests/api_surface.rs` by coordinating nearby symbol calls. It directly calls `read`, `from_pb_bytes`.
Receives: No strong upstream caller evidence was inferred.
Produces or triggers: Triggers `read`, `from_pb_bytes`, `to_pb_bytes`.
Connected symbols:
- Callees: `read`, `from_pb_bytes`, `to_pb_bytes`.
Supporting implementation citations:
- `crates/omnisstream/tests/api_surface.rs:44`
- `crates/omnisstream/src/hashing.rs:209`

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/tests/api_surface.rs:44`
- `crates/omnisstream/src/hashing.rs:209`
</details>

## State Boundaries

Insufficient evidence to infer state boundaries confidently.

<details>
<summary>Supporting citations:</summary>

- none
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

omnisstream rust component

Type: package
Root path: `crates/omnisstream`
Ecosystem: rust

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src/group_commit.rs`
- `crates/omnisstream/src/hashing.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
</details>

## Entrypoints and Runtime Surface

- none

## Interfaces and Config

- none

## Dependencies and Relationships

- `component:cargo:crates/omnisstream_bench` depends_on `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream_ffi` depends_on `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream` depends_on `component:cargo:crates/omnisstream_backend_api` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:anyhow.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:blake3.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:bytes.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:crc32c.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:hex.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:prost-build` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:prost-types.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:prost.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:protoc-bin-vendored` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:rayon.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:rustix` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:semver.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:serde_json.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:serde.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:tempfile.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:thiserror.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:tracing.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:uuid.workspace` (high)
- `component:cargo:crates/omnisstream` depends_on `component:external:rust:zstd-framed` (high)
- `repository` contains `component:cargo:crates/omnisstream` (high)
- `component:docs` documents `component:cargo:crates/omnisstream` (medium)
- `component:tests` tests `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream` depends_on `crates/omnisstream/src/lib.rs` (medium)

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream/src/group_commit.rs`
- `crates/omnisstream/src/hashing.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
</details>

## Why This Hotspot Matters

Architectural role: Hotspot score 174 with 28 inbound and 29 outbound inferred edges marks `omnisstream` as a coordination-heavy component. It bridges `external`.

Main coupling surfaces:
- Coupled components: `omnisstream_bench`, `omnisstream_cli`, `omnisstream_ffi`, `omnisstream_backend_api`.
- Call-heavy surface with 8 inferred call edges.
- Dependency-heavy surface with 49 inferred dependency edges.

Likely failure modes:
- Upstream breakage risk: 28 inbound edges suggest downstream callers depend on this boundary staying stable.
- Coordination risk: 29 outbound edges mean changes can ripple into neighboring components.
- Cross-subsystem regression risk: changes can disrupt handoffs across `external`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_backend_api/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_backend_api/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_backend_api/Cargo.toml`
</details>

## Operational Risk Surface

Likely fault domains:
- External dependency boundaries: `anyhow.workspace`, `blake3.workspace`, `bytes.workspace`, `crc32c.workspace`.
- Cross-subsystem handoffs: `external`.

High-cost dependencies:
- `anyhow.workspace` acts as a external dependency boundary.
- `blake3.workspace` acts as a external dependency boundary.
- `bytes.workspace` acts as a external dependency boundary.
- `crc32c.workspace` acts as a external dependency boundary.

First validation checks:
- Run `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Run `cargo build` (build) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
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
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Downstream components likely affected: `omnisstream_backend_api`, `anyhow.workspace`, `blake3.workspace`, `bytes.workspace`.
- Cross-subsystem risk touches `external`.
- Hotspot score 174 with 28 inbound and 29 outbound edges suggests higher coordination risk.

Suggested verification steps:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/tests/api_surface.rs:5`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/tests/api_surface.rs:44`
- `crates/omnisstream/src/hashing.rs:209`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
