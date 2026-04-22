---
page_id: components
page_type: components
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.240Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "db63c5e2f6514477ec01fafd83be273fb4c4c123",
  "plannerReason": "Workspace template selected because deterministic evidence suggests a multi-package or multi-application repository.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "crates/omnisstream/build.rs",
    "crates/omnisstream/Cargo.toml",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "spec/omnisstream-spec/tools/validator/README.md",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "docs/ffi_cmake.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_ffi/Cargo.toml",
    "crates/omnisstream_ffi/cbindgen.toml",
    "crates/omnisstream_ffi/src/bin/header_gen.rs",
    "crates/omnisstream_ffi/src/lib.rs",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_cli/src/main.rs"
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
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml"
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
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Components

Component inventory for OmnisStream-Core.

## Related Pages

- [component-component:tests](component-component:tests.md)
- [component-component:cargo:crates/omnisstream](component-component:cargo:crates/omnisstream.md)
- [component-component:crates/omnisstream/src](component-component:crates/omnisstream/src.md)
- [component-component:spec/omnisstream-spec/tools/validator/pyproject.toml](component-component:spec/omnisstream-spec/tools/validator/pyproject.toml.md)
- [component-component:spec/omnisstream-spec/tools/validator/src](component-component:spec/omnisstream-spec/tools/validator/src.md)
- [component-component:docs](component-component:docs.md)
- [component-component:external:rust:anyhow.workspace](component-component:external:rust:anyhow.workspace.md)
- [component-component:cargo:crates/omnisstream_ffi](component-component:cargo:crates/omnisstream_ffi.md)
- [component-component:external:rust:clap.workspace](component-component:external:rust:clap.workspace.md)
- [component-component:cargo:crates/omnisstream_cli](component-component:cargo:crates/omnisstream_cli.md)
- [component-component:external:rust:serde_json.workspace](component-component:external:rust:serde_json.workspace.md)
- [component-component:external:rust:serde.workspace](component-component:external:rust:serde.workspace.md)

## Component Inventory

- Tests (tests) at `tests` with 47 files.
- omnisstream (package) at `crates/omnisstream` with 19 files.
- crates/omnisstream/src (module) at `crates/omnisstream/src` with 16 files.
- omnisstream-validator (application) at `spec/omnisstream-spec/tools/validator` with 12 files.
- spec/omnisstream-spec/tools/validator/src (module) at `spec/omnisstream-spec/tools/validator/src` with 9 files.
- Documentation (docs) at `docs` with 6 files.
- anyhow.workspace (package) at `external/rust/anyhow.workspace` with 4 files.
- omnisstream_ffi (package) at `crates/omnisstream_ffi` with 4 files.
- clap.workspace (package) at `external/rust/clap.workspace` with 3 files.
- omnisstream_cli (package) at `crates/omnisstream_cli` with 3 files.
- serde_json.workspace (package) at `external/rust/serde_json.workspace` with 3 files.
- serde.workspace (package) at `external/rust/serde.workspace` with 3 files.

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `docs/ffi_cmake.md`
- `README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
</details>

## Where to Look Next

- [component-component:tests](components/component-tests.md)
- [component-component:cargo:crates/omnisstream](components/component-cargo-crates-omnisstream.md)
- [component-component:crates/omnisstream/src](components/component-crates-omnisstream-src.md)
- [component-component:spec/omnisstream-spec/tools/validator/pyproject.toml](components/component-spec-omnisstream-spec-tools-validator-pyproject.toml.md)
- [component-component:spec/omnisstream-spec/tools/validator/src](components/component-spec-omnisstream-spec-tools-validator-src.md)
- [component-component:docs](components/component-docs.md)
- [component-component:external:rust:anyhow.workspace](components/component-external-rust-anyhow.workspace.md)
- [component-component:cargo:crates/omnisstream_ffi](components/component-cargo-crates-omnisstream_ffi.md)
- [component-component:external:rust:clap.workspace](components/component-external-rust-clap.workspace.md)
- [component-component:cargo:crates/omnisstream_cli](components/component-cargo-crates-omnisstream_cli.md)
- [component-component:external:rust:serde_json.workspace](components/component-external-rust-serde_json.workspace.md)
- [component-component:external:rust:serde.workspace](components/component-external-rust-serde.workspace.md)

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `docs/ffi_cmake.md`
- `README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/Cargo.toml`
</details>
