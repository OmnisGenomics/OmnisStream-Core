---
page_id: index
page_type: index
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:49.938Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "820b3dfe32f5a2f28b5305fdd75bfb33aca86e5c",
  "plannerReason": "Workspace template selected because deterministic evidence suggests a multi-package or multi-application repository.",
  "changedPaths": [],
  "dependencyPaths": [
    "docs/ffi_cmake.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/tools/validator/README.md",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "crates/omnisstream/tests/api_surface.rs",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream/build.rs",
    "crates/omnisstream/Cargo.toml",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "crates/omnisstream_ffi/Cargo.toml",
    "crates/omnisstream_ffi/cbindgen.toml",
    "crates/omnisstream_ffi/src/bin/header_gen.rs",
    "crates/omnisstream_ffi/src/lib.rs",
    "crates/omnisstream_cli/build.rs"
  ],
  "dependencyEvidenceIds": [
    "component:external:rust:aho-corasick",
    "component:external:rust:anstream",
    "component:bin:omnisstream",
    "component:bin:omnisstream_bench",
    "component:python-script:spec/omnisstream-spec/tools/validator/pyproject.toml:omnisstream-validate",
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:docs",
    "component:Cargo.toml",
    "component:tests",
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
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
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
    "component:crates/omnisstream_ffi/Cargo.toml"
  ],
  "evidenceIds": [
    "component:external:rust:aho-corasick",
    "component:external:rust:anstream",
    "component:bin:omnisstream",
    "component:bin:omnisstream_bench",
    "component:python-script:spec/omnisstream-spec/tools/validator/pyproject.toml:omnisstream-validate",
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:docs",
    "component:Cargo.toml",
    "component:tests",
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
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
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
    "component:crates/omnisstream_ffi/Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# OmnisStream-Core Wiki

Purpose: OmnisStream-Core is a repository indexed by RepoIntel MCP.

Documentation starts at docs/ffi_cmake.md, README.md, spec/omnisstream-spec/proto/README.md.

Context:
- Version control: git
- Detected ecosystems: python, rust
- Inventory: 5814 files, 165 components, 5 workflows

## Related Pages

- [architecture](architecture.md)
- [configuration](configuration.md)
- [playbook](playbook.md)
- [validation](validation.md)
- [change-guide](change-guide.md)
- [troubleshooting](troubleshooting.md)
- [components](components.md)
- [workflows](workflows.md)
- [runtime](runtime.md)
- [interfaces](interfaces.md)
- [dependencies](dependencies.md)
- [testing](testing.md)
- [diagrams](diagrams.md)
- [glossary](glossary.md)

## Repository Overview

Purpose: OmnisStream-Core is a repository indexed by RepoIntel MCP.

Documentation starts at docs/ffi_cmake.md, README.md, spec/omnisstream-spec/proto/README.md.

Context:
- Version control: git
- Detected ecosystems: python, rust
- Inventory: 5814 files, 165 components, 5 workflows

Primary capabilities:
- run: `omnisstream-validate`
- test: `python -m pytest`
- build: `cargo build`
- check: `cargo check`

Major subsystem map:
- external: external groups 143 components under external/ or related paths.
- crates: crates groups 16 components under crates/ or related paths.
- spec: spec groups 3 components under spec/ or related paths.
- docs: docs groups 1 components under docs/ or related paths.

Suggested reading order:
1. Read [architecture](architecture.md) next for the subsystem view.
2. Read [configuration](configuration.md) next for the required setup, tunable knobs, and risk-sensitive settings.
3. Read [playbook](playbook.md) next for the operational validation and debugging guide.
4. Read [validation](validation.md) next for the validation layers and the confidence they provide.
5. Read [change-guide](change-guide.md) next for the task-first change priorities, edit entrypoints, and verification order.
6. Read [troubleshooting](troubleshooting.md) next for the failure-first inspection points and validation commands.
7. Read [runtime](runtime.md) next for the runtime and operational picture.
8. Read [components](components.md) next for the important component inventory.
9. Read [diagrams](diagrams.md) next for the diagrams details.
10. Read [dependencies](dependencies.md) next for the dependencies details.
11. Read [workflows](workflows.md) next for the workflows details.

<details>
<summary>Related files:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs`
</details>

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## Critical Components

### 1. crates/omnisstream/src
Why it matters: Hotspot score 1797 with 297 inbound and 300 outbound inferred edges. Touches 30 inferred dependency edges.

What it owns:
- Source module rooted at crates/omnisstream/src.
- Owns files rooted at `crates/omnisstream/src`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
</details>

Ranking score: 1827.

### 2. omnisstream
Why it matters: Hotspot score 264 with 38 inbound and 49 outbound inferred edges. Contributes 1 runtime-facing entrypoint or service signal. Touches 7 inferred dependency edges.

What it owns:
- Rust binary target omnisstream.
- Owns files rooted at `crates/omnisstream_cli/src`.
- Entrypoint: `crates/omnisstream_cli/src/main.rs`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
</details>

Ranking score: 275.

### 3. omnisstream_benchdiff
Why it matters: Hotspot score 255 with 41 inbound and 42 outbound inferred edges. Contributes 1 runtime-facing entrypoint or service signal. Touches 6 inferred dependency edges.

What it owns:
- Rust binary target omnisstream_benchdiff.
- Owns files rooted at `crates/omnisstream_benchdiff/src`.
- Entrypoint: `crates/omnisstream_benchdiff/src/main.rs`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
</details>

Ranking score: 265.

### 4. omnisstream
Why it matters: Hotspot score 174 with 28 inbound and 29 outbound inferred edges. Touches 27 inferred dependency edges.

What it owns:
- omnisstream rust component
- Owns files rooted at `crates/omnisstream`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
</details>

Ranking score: 201.

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
</details>

## Repository Summary

Purpose: OmnisStream-Core is a repository indexed by RepoIntel MCP.

Documentation starts at docs/ffi_cmake.md, README.md, spec/omnisstream-spec/proto/README.md.

Context:
- Version control: git
- Detected ecosystems: python, rust
- Inventory: 5814 files, 165 components, 5 workflows

Indexed revision: git:b2c38f75aab65dac9570951906b60645afe91be8.
Indexed at: 2026-04-18T05:55:49.640Z.

<details>
<summary>Related files:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

## Repository Shape

- `.github/`
- `crates/`
- `docs/`
- `examples/`
- `include/`
- `spec/`
- `target/`

Languages:
- json
- markdown
- python
- rust
- shell
- toml
- yaml

<details>
<summary>Related files:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

## Important Components

- Tests (tests) at `tests`: Repository tests and fixtures.
- omnisstream (package) at `crates/omnisstream`: omnisstream rust component
- crates/omnisstream/src (module) at `crates/omnisstream/src`: Source module rooted at crates/omnisstream/src.
- omnisstream-validator (application) at `spec/omnisstream-spec/tools/validator`: omnisstream-validator python component
- spec/omnisstream-spec/tools/validator/src (module) at `spec/omnisstream-spec/tools/validator/src`: Source module rooted at spec/omnisstream-spec/tools/validator/src.
- Documentation (docs) at `docs`: Repository documentation and wiki source files.
- anyhow.workspace (package) at `external/rust/anyhow.workspace`: External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream_benchdiff/Cargo.toml, crates/omnisstream_cli/Cargo.toml, crates/omnisstream/Cargo.toml.
- omnisstream_ffi (package) at `crates/omnisstream_ffi`: omnisstream_ffi rust component
- clap.workspace (package) at `external/rust/clap.workspace`: External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream_benchdiff/Cargo.toml, crates/omnisstream_cli/Cargo.toml.
- omnisstream_cli (package) at `crates/omnisstream_cli`: omnisstream_cli rust component
- serde_json.workspace (package) at `external/rust/serde_json.workspace`: External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream_benchdiff/Cargo.toml, crates/omnisstream/Cargo.toml.
- serde.workspace (package) at `external/rust/serde.workspace`: External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream_benchdiff/Cargo.toml, crates/omnisstream/Cargo.toml.

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

## Citations

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_cli/build.rs:110`
</details>
