---
page_id: component-component:cargo:crates/omnisstream_cli
page_type: component
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.882Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "3f97e11c730a9335728ceb943b2ea9f262524637",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream/Cargo.toml",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:crates/omnisstream_cli/build.rs",
    "component:crates/omnisstream_cli/Cargo.toml",
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
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "ingest:file:crates/omnisstream_cli/build.rs",
    "component:crates/omnisstream_cli/Cargo.toml",
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
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# omnisstream_cli

omnisstream_cli rust component

## Related Pages

- [components](components.md)
- [workflows](workflows.md)
- [interfaces](interfaces.md)
- [dependencies](dependencies.md)

## Implementation Roles

### `crates/omnisstream_cli/src/main.rs`
Role classification: inferred execution boundary.
Proved signals:
- Matched an inferred entrypoint or entrypoint symbol in `crates/omnisstream_cli/src/main.rs`.
Why this role fits: These proved signals suggest this unit is a first-hop execution boundary that receives control and hands it into component logic.
Supporting implementation citations:
- `crates/omnisstream_cli/src/main.rs:16`

### `crates/omnisstream_cli/build.rs`
Role classification: inferred execution boundary.
Proved signals:
- Defines execution-like symbols `main`.
- Participates in 5 connected call edges.
Why this role fits: These proved signals suggest this unit is a first-hop execution boundary that receives control and hands it into component logic.
Supporting implementation citations:
- `crates/omnisstream_cli/build.rs:1`

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/build.rs:1`
</details>

## Module Responsibilities

### `crates/omnisstream_cli/build.rs`
Role: Internal implementation module.
Primary behavior: Defines `main` (function), `find_git_dir` (function), `read_gitdir_file` (function), suggesting local implementation behavior rather than a manifest-only surface.
Why this module matters: 5 connected call edges mark this file as implementation-active.
Supporting implementation citations:
- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:16`
- `crates/omnisstream_cli/build.rs:31`

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:16`
- `crates/omnisstream_cli/build.rs:31`
</details>

## Key Symbols

### `main` (function)
Behavior: Starts or orchestrates execution for `crates/omnisstream_cli/build.rs`. It directly calls `find_common_git_dir`, `find_git_dir`.
Receives: No strong upstream caller evidence was inferred.
Produces or triggers: Triggers `find_common_git_dir`, `find_git_dir`, `read_git_commit`.
Connected symbols:
- Callees: `find_common_git_dir`, `find_git_dir`, `read_git_commit`.
Supporting implementation citations:
- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:42`

### `find_git_dir` (function)
Behavior: Implements component logic in `crates/omnisstream_cli/build.rs` by coordinating nearby symbol calls. It directly calls `read_gitdir_file`.
Receives: Called by `main`.
Produces or triggers: Triggers `read_gitdir_file`.
Connected symbols:
- Callers: `main`.
- Callees: `read_gitdir_file`.
Supporting implementation citations:
- `crates/omnisstream_cli/build.rs:16`
- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:31`

### `read_git_commit` (function)
Behavior: Reads or loads data or dependencies for `crates/omnisstream_cli/build.rs`. It directly calls `candidate_git_paths`.
Receives: Called by `main`.
Produces or triggers: Triggers `candidate_git_paths`.
Connected symbols:
- Callers: `main`.
- Callees: `candidate_git_paths`.
Supporting implementation citations:
- `crates/omnisstream_cli/build.rs:62`
- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:110`

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:42`
- `crates/omnisstream_cli/build.rs:16`
- `crates/omnisstream_cli/build.rs:31`
- `crates/omnisstream_cli/build.rs:62`
- `crates/omnisstream_cli/build.rs:110`
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

omnisstream_cli rust component

Type: package
Root path: `crates/omnisstream_cli`
Ecosystem: rust

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
</details>

## Entrypoints and Runtime Surface

- `crates/omnisstream_cli/src/main.rs`

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
</details>

## Interfaces and Config

- none

## Dependencies and Relationships

- `component:cargo:crates/omnisstream_cli` depends_on `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:external:rust:anyhow.workspace` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:external:rust:clap.workspace` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:external:rust:rayon.workspace` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:external:rust:tempfile.workspace` (high)
- `component:cargo:crates/omnisstream_cli` depends_on `component:external:rust:tracing-subscriber.workspace` (high)
- `repository` contains `component:cargo:crates/omnisstream_cli` (high)
- `component:docs` documents `component:cargo:crates/omnisstream_cli` (medium)
- `component:tests` tests `component:cargo:crates/omnisstream_cli` (high)

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
</details>

## Why This Hotspot Matters

Architectural role: Hotspot score 51 with 5 inbound and 11 outbound inferred edges marks `omnisstream_cli` as a coordination-heavy component. It bridges `external`. It also owns runtime entrypoints at `crates/omnisstream_cli/src/main.rs`.

Main coupling surfaces:
- Coupled components: `omnisstream`, `anyhow.workspace`, `clap.workspace`, `rayon.workspace`.
- Call-heavy surface with 10 inferred call edges.
- Dependency-heavy surface with 6 inferred dependency edges.

Likely failure modes:
- Upstream breakage risk: 5 inbound edges suggest downstream callers depend on this boundary staying stable.
- Coordination risk: 11 outbound edges mean changes can ripple into neighboring components.
- Cross-subsystem regression risk: changes can disrupt handoffs across `external`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/Cargo.toml`
</details>

## Operational Risk Surface

Likely fault domains:
- External dependency boundaries: `anyhow.workspace`, `clap.workspace`, `rayon.workspace`, `tempfile.workspace`.
- Cross-subsystem handoffs: `external`.

High-cost dependencies:
- `anyhow.workspace` acts as a external dependency boundary.
- `clap.workspace` acts as a external dependency boundary.
- `rayon.workspace` acts as a external dependency boundary.
- `tempfile.workspace` acts as a external dependency boundary.

First validation checks:
- Run `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Run `cargo build` (build) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
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
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Downstream components likely affected: `omnisstream`, `anyhow.workspace`, `clap.workspace`, `rayon.workspace`.
- Cross-subsystem risk touches `external`.
- Hotspot score 51 with 5 inbound and 11 outbound edges suggests higher coordination risk.

Suggested verification steps:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/build.rs:1`
- `crates/omnisstream_cli/build.rs:16`
- `crates/omnisstream_cli/build.rs:31`
- `crates/omnisstream_cli/build.rs:42`
- `crates/omnisstream_cli/build.rs:62`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
