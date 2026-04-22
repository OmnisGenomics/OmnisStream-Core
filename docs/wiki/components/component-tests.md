---
page_id: component-component:tests
page_type: component
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.719Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "997ec175a05cf40e6627124b7605f47549370ee2",
  "plannerReason": "Generated because the component was ranked as significant for repo navigation.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
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
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
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
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Tests

Repository tests and fixtures.

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

Repository tests and fixtures.

Type: tests
Root path: `tests`
Ecosystem: unknown

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
</details>

## Entrypoints and Runtime Surface

- none

## Interfaces and Config

- none

## Dependencies and Relationships

- `component:docs` documents `component:tests` (medium)
- `component:tests` tests `component:bin:omnisstream` (high)
- `component:tests` tests `component:bin:omnisstream_bench` (high)
- `component:tests` tests `component:bin:omnisstream_benchdiff` (high)
- `component:tests` tests `component:bin:omnisstream_ffi_header` (high)
- `component:tests` tests `component:cargo:crates/omnisstream` (high)
- `component:tests` tests `component:cargo:crates/omnisstream_backend_api` (high)
- `component:tests` tests `component:cargo:crates/omnisstream_bench` (high)
- `component:tests` tests `component:cargo:crates/omnisstream_benchdiff` (high)
- `component:tests` tests `component:cargo:crates/omnisstream_cli` (high)
- `component:tests` tests `component:cargo:crates/omnisstream_ffi` (high)
- `component:tests` tests `component:Cargo.toml` (high)
- `component:tests` tests `component:crates/omnisstream_backend_api/src` (high)
- `component:tests` tests `component:crates/omnisstream_bench/src` (high)
- `component:tests` tests `component:crates/omnisstream_benchdiff/src` (high)
- `component:tests` tests `component:crates/omnisstream_cli/src` (high)
- `component:tests` tests `component:crates/omnisstream_ffi/src` (high)
- `component:tests` tests `component:crates/omnisstream/src` (high)
- `component:tests` tests `component:external:rust:aho-corasick` (high)
- `component:tests` tests `component:external:rust:anstream` (high)
- `component:tests` tests `component:external:rust:anstyle` (high)
- `component:tests` tests `component:external:rust:anstyle-parse` (high)
- `component:tests` tests `component:external:rust:anstyle-query` (high)
- `component:tests` tests `component:external:rust:anstyle-wincon` (high)
- `component:tests` tests `component:external:rust:anyhow` (high)
- `component:tests` tests `component:external:rust:anyhow.workspace` (high)
- `component:tests` tests `component:external:rust:arrayref` (high)
- `component:tests` tests `component:external:rust:arrayvec` (high)
- `component:tests` tests `component:external:rust:bitflags` (high)
- `component:tests` tests `component:external:rust:blake3` (high)
- `component:tests` tests `component:external:rust:blake3.workspace` (high)
- `component:tests` tests `component:external:rust:bumpalo` (high)
- `component:tests` tests `component:external:rust:bytes` (high)
- `component:tests` tests `component:external:rust:bytes.workspace` (high)
- `component:tests` tests `component:external:rust:cbindgen` (high)
- `component:tests` tests `component:external:rust:cc` (high)
- `component:tests` tests `component:external:rust:cfg-if` (high)
- `component:tests` tests `component:external:rust:clap` (high)
- `component:tests` tests `component:external:rust:clap_builder` (high)
- `component:tests` tests `component:external:rust:clap_derive` (high)
- `component:tests` tests `component:external:rust:clap_lex` (high)
- `component:tests` tests `component:external:rust:clap.workspace` (high)
- `component:tests` tests `component:external:rust:colorchoice` (high)
- `component:tests` tests `component:external:rust:constant_time_eq` (high)
- `component:tests` tests `component:external:rust:crc32c` (high)
- `component:tests` tests `component:external:rust:crc32c.workspace` (high)
- `component:tests` tests `component:external:rust:crossbeam-deque` (high)
- `component:tests` tests `component:external:rust:crossbeam-epoch` (high)
- `component:tests` tests `component:external:rust:crossbeam-utils` (high)
- `component:tests` tests `component:external:rust:either` (high)
- `component:tests` tests `component:external:rust:equivalent` (high)
- `component:tests` tests `component:external:rust:errno` (high)
- `component:tests` tests `component:external:rust:fastrand` (high)
- `component:tests` tests `component:external:rust:find-msvc-tools` (high)
- `component:tests` tests `component:external:rust:fixedbitset` (high)
- `component:tests` tests `component:external:rust:getrandom` (high)
- `component:tests` tests `component:external:rust:hashbrown` (high)
- `component:tests` tests `component:external:rust:heck` (high)
- `component:tests` tests `component:external:rust:hex` (high)
- `component:tests` tests `component:external:rust:hex.workspace` (high)
- `component:tests` tests `component:external:rust:indexmap` (high)
- `component:tests` tests `component:external:rust:is_terminal_polyfill` (high)
- `component:tests` tests `component:external:rust:itertools` (high)
- `component:tests` tests `component:external:rust:itoa` (high)
- `component:tests` tests `component:external:rust:jobserver` (high)
- `component:tests` tests `component:external:rust:js-sys` (high)
- `component:tests` tests `component:external:rust:lazy_static` (high)
- `component:tests` tests `component:external:rust:libc` (high)
- `component:tests` tests `component:external:rust:libc.workspace` (high)
- `component:tests` tests `component:external:rust:linux-raw-sys` (high)
- `component:tests` tests `component:external:rust:log` (high)
- `component:tests` tests `component:external:rust:matchers` (high)
- `component:tests` tests `component:external:rust:memchr` (high)
- `component:tests` tests `component:external:rust:multimap` (high)
- `component:tests` tests `component:external:rust:name` (high)
- `component:tests` tests `component:external:rust:nu-ansi-term` (high)
- `component:tests` tests `component:external:rust:once_cell` (high)
- `component:tests` tests `component:external:rust:once_cell_polyfill` (high)
- `component:tests` tests `component:external:rust:path` (high)
- `component:tests` tests `component:external:rust:petgraph` (high)
- `component:tests` tests `component:external:rust:pin-project-lite` (high)
- `component:tests` tests `component:external:rust:pkg-config` (high)
- `component:tests` tests `component:external:rust:prettyplease` (high)
- `component:tests` tests `component:external:rust:proc-macro2` (high)
- `component:tests` tests `component:external:rust:prost` (high)
- `component:tests` tests `component:external:rust:prost-build` (high)
- `component:tests` tests `component:external:rust:prost-derive` (high)
- `component:tests` tests `component:external:rust:prost-types` (high)
- `component:tests` tests `component:external:rust:prost-types.workspace` (high)
- `component:tests` tests `component:external:rust:prost.workspace` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-linux-aarch_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-linux-ppcle_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-linux-s390_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-linux-x86_32` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-linux-x86_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-macos-aarch_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-macos-x86_64` (high)
- `component:tests` tests `component:external:rust:protoc-bin-vendored-win32` (high)
- `component:tests` tests `component:external:rust:quote` (high)
- `component:tests` tests `component:external:rust:r-efi` (high)
- `component:tests` tests `component:external:rust:rayon` (high)
- `component:tests` tests `component:external:rust:rayon-core` (high)
- `component:tests` tests `component:external:rust:rayon.workspace` (high)
- `component:tests` tests `component:external:rust:regex` (high)
- `component:tests` tests `component:external:rust:regex-automata` (high)
- `component:tests` tests `component:external:rust:regex-syntax` (high)
- `component:tests` tests `component:external:rust:required-features` (high)
- `component:tests` tests `component:external:rust:rustc_version` (high)
- `component:tests` tests `component:external:rust:rustix` (high)
- `component:tests` tests `component:external:rust:rustversion` (high)
- `component:tests` tests `component:external:rust:ryu` (high)
- `component:tests` tests `component:external:rust:semver` (high)
- `component:tests` tests `component:external:rust:semver.workspace` (high)
- `component:tests` tests `component:external:rust:serde` (high)
- `component:tests` tests `component:external:rust:serde_core` (high)
- `component:tests` tests `component:external:rust:serde_derive` (high)
- `component:tests` tests `component:external:rust:serde_json` (high)
- `component:tests` tests `component:external:rust:serde_json.workspace` (high)
- `component:tests` tests `component:external:rust:serde_spanned` (high)
- `component:tests` tests `component:external:rust:serde.workspace` (high)
- `component:tests` tests `component:external:rust:sharded-slab` (high)
- `component:tests` tests `component:external:rust:shlex` (high)
- `component:tests` tests `component:external:rust:smallvec` (high)
- `component:tests` tests `component:external:rust:strsim` (high)
- `component:tests` tests `component:external:rust:syn` (high)
- `component:tests` tests `component:external:rust:tempfile` (high)
- `component:tests` tests `component:external:rust:tempfile.workspace` (high)
- `component:tests` tests `component:external:rust:thiserror` (high)
- `component:tests` tests `component:external:rust:thiserror-impl` (high)
- `component:tests` tests `component:external:rust:thiserror.workspace` (high)
- `component:tests` tests `component:external:rust:thread_local` (high)
- `component:tests` tests `component:external:rust:toml` (high)
- `component:tests` tests `component:external:rust:toml_datetime` (high)
- `component:tests` tests `component:external:rust:toml_edit` (high)
- `component:tests` tests `component:external:rust:toml_write` (high)
- `component:tests` tests `component:external:rust:tracing` (high)
- `component:tests` tests `component:external:rust:tracing-attributes` (high)
- `component:tests` tests `component:external:rust:tracing-core` (high)
- `component:tests` tests `component:external:rust:tracing-log` (high)
- `component:tests` tests `component:external:rust:tracing-subscriber` (high)
- `component:tests` tests `component:external:rust:tracing-subscriber.workspace` (high)
- `component:tests` tests `component:external:rust:tracing.workspace` (high)
- `component:tests` tests `component:external:rust:unicode-ident` (high)
- `component:tests` tests `component:external:rust:utf8parse` (high)
- `component:tests` tests `component:external:rust:uuid` (high)
- `component:tests` tests `component:external:rust:uuid.workspace` (high)
- `component:tests` tests `component:external:rust:valuable` (high)
- `component:tests` tests `component:external:rust:wasip2` (high)
- `component:tests` tests `component:external:rust:wasm-bindgen` (high)
- `component:tests` tests `component:external:rust:wasm-bindgen-macro` (high)
- `component:tests` tests `component:external:rust:wasm-bindgen-macro-support` (high)
- `component:tests` tests `component:external:rust:wasm-bindgen-shared` (high)
- `component:tests` tests `component:external:rust:windows-link` (high)
- `component:tests` tests `component:external:rust:windows-sys` (high)
- `component:tests` tests `component:external:rust:winnow` (high)
- `component:tests` tests `component:external:rust:wit-bindgen` (high)
- `component:tests` tests `component:external:rust:zstd` (high)
- `component:tests` tests `component:external:rust:zstd-framed` (high)
- `component:tests` tests `component:external:rust:zstd-safe` (high)
- `component:tests` tests `component:external:rust:zstd-sys` (high)
- `component:tests` tests `component:python-script:spec/omnisstream-spec/tools/validator/pyproject.toml:omnisstream-validate` (high)
- `component:tests` tests `component:spec/omnisstream-spec/tools/validator/pyproject.toml` (high)
- `component:tests` tests `component:spec/omnisstream-spec/tools/validator/src` (high)

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
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
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`

Owned interfaces:
- none

Nearby verification surfaces:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Change Planning

Impacted areas:
- Downstream components likely affected: `omnisstream`, `omnisstream_bench`, `omnisstream_benchdiff`, `omnisstream_ffi_header`.

Suggested verification steps:
- Validate with `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
- Validate with `cargo test` (test) from `.`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Nearby Workflows

- none

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
