---
page_id: component-component:cargo:crates/omnisstream_ffi
page_type: component
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.856Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "77d172bb407fd4819d2ca351bc7ff0355e6ff247",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream_ffi/Cargo.toml",
    "crates/omnisstream_ffi/cbindgen.toml",
    "crates/omnisstream_ffi/src/bin/header_gen.rs",
    "crates/omnisstream_ffi/src/lib.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "component:crates/omnisstream_ffi/Cargo.toml",
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
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "component:crates/omnisstream_ffi/Cargo.toml",
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
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# omnisstream_ffi

omnisstream_ffi rust component

## Related Pages

- [components](components.md)
- [workflows](workflows.md)
- [interfaces](interfaces.md)
- [dependencies](dependencies.md)

## Implementation Roles

Insufficient evidence to infer implementation roles confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Module Responsibilities

Insufficient evidence to infer module responsibilities confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Key Symbols

Insufficient evidence to infer key symbol behavior confidently.

<details>
<summary>Supporting citations:</summary>

- none
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

omnisstream_ffi rust component

Type: package
Root path: `crates/omnisstream_ffi`
Ecosystem: rust

<details>
<summary>Related files:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/src/lib.rs:53`
</details>

## Entrypoints and Runtime Surface

- none

## Interfaces and Config

- none

## Dependencies and Relationships

- `component:cargo:crates/omnisstream_ffi` depends_on `component:cargo:crates/omnisstream` (high)
- `component:cargo:crates/omnisstream_ffi` depends_on `component:external:rust:cbindgen` (high)
- `component:cargo:crates/omnisstream_ffi` depends_on `component:external:rust:name` (high)
- `component:cargo:crates/omnisstream_ffi` depends_on `component:external:rust:path` (high)
- `component:cargo:crates/omnisstream_ffi` depends_on `component:external:rust:required-features` (high)
- `repository` contains `component:cargo:crates/omnisstream_ffi` (high)
- `component:docs` documents `component:cargo:crates/omnisstream_ffi` (medium)
- `component:tests` tests `component:cargo:crates/omnisstream_ffi` (high)

<details>
<summary>Related files:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/src/lib.rs:53`
</details>

## Why This Hotspot Matters

Insufficient evidence to explain this component as a hotspot confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Operational Risk Surface

Insufficient evidence to infer operational risk surface confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Invariants and Failure Handling

Insufficient evidence to infer invariants and failure handling confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Where to Edit

Likely change entry files:
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Downstream components likely affected: `omnisstream`, `cbindgen`, `name`, `path`.

Suggested verification steps:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/src/lib.rs:53`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
