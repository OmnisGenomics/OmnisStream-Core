---
page_id: runtime
page_type: runtime
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.289Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "3ad6e5d1984f598a2629a1652b56c0c707d0fcb2",
  "plannerReason": "Generated because agents often need to know how the repo runs before they modify it.",
  "changedPaths": [],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "omnisstream-validate",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "Cargo.toml",
    "crates/omnisstream_bench/src/main.rs",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_ffi/src/bin/header_gen.rs",
    "crates/omnisstream_ffi/Cargo.toml",
    "spec/omnisstream-spec/tools/validator/README.md",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py"
  ],
  "dependencyEvidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Runtime

Runtime-oriented view of OmnisStream-Core.

## Related Pages

- [workflows](workflows.md)
- [components](components.md)

## Startup Flow

Steps:
1. Start with `omnisstream-validate` (run) from `spec/omnisstream-spec/tools/validator`.
2. Enter through `omnisstream-validate`.
3. Hand off to omnisstream (application) as the main startup owner.

Owned components:
- omnisstream (application)

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
</details>

## Primary Request or Job Flow

Steps:
1. Work begins in omnisstream (application).
2. It delegates to `anyhow`, `clap`, `rayon` through inferred internal edges.
3. The flow stays closest to subsystem crates.

Owned components:
- omnisstream (application)
- anyhow
- clap
- rayon

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
</details>

## Operational Workflow

Steps:
1. Run `python -m pytest` for test from `spec/omnisstream-spec/tools/validator`.
2. Run `cargo build` for build from `.`.
3. Run `cargo test` for test from `.`.

Owned components:
- omnisstream-validate (application)
- omnisstream-validator (application)
- OmnisStream-Core (workspace)

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

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

## Entrypoints

- `omnisstream-validate`

<details>
<summary>Related files:</summary>

- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
</details>

## Services

- none

<details>
<summary>Related files:</summary>

- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>
