---
page_id: change-guide
page_type: change-guide
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.275Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "867b72b417f6fc041f63eb4883549997d4ad8d81",
  "plannerReason": "Generated when deterministic critical-component, edit-surface, and validation evidence is strong enough to assemble a bounded change-oriented reader path.",
  "changedPaths": [],
  "dependencyPaths": [
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "crates/omnisstream/src/fs_util.rs",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "Cargo.toml",
    "spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "dependencyEvidenceIds": [
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
    "workflow:Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "evidenceIds": [
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
    "workflow:Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Change Guide

Task-first guide for making bounded changes in OmnisStream-Core.

## Related Pages

- [components](components.md)
- [validation](validation.md)
- [playbook](playbook.md)
- [workflows](workflows.md)

## Change Priorities

1. `crates/omnisstream/src`: Hotspot score 1797 with 297 inbound and 300 outbound inferred edges. Touches 30 inferred dependency edges.
2. `omnisstream`: Hotspot score 264 with 38 inbound and 49 outbound inferred edges. Contributes 1 runtime-facing entrypoint or service signal. Touches 7 inferred dependency edges.
3. `omnisstream_benchdiff`: Hotspot score 255 with 41 inbound and 42 outbound inferred edges. Contributes 1 runtime-facing entrypoint or service signal. Touches 6 inferred dependency edges.

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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Where to Start Editing

- Start with `crates/omnisstream/src` via `crates/omnisstream/src/api.rs`, `crates/omnisstream/src/compression.rs`. Then read [crates/omnisstream/src](components/crates-omnisstream-src.md) for the bounded component guide.
- Start with `omnisstream` via `crates/omnisstream_cli/src/main.rs`, `crates/omnisstream_cli/Cargo.toml`. Then read [omnisstream](components/bin-omnisstream.md) for the bounded component guide.
- Start with `omnisstream_benchdiff` via `crates/omnisstream_benchdiff/src/main.rs`, `crates/omnisstream_benchdiff/Cargo.toml`. Then read [omnisstream_benchdiff](components/bin-omnisstream_benchdiff.md) for the bounded component guide.

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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Validation Order

1. Fast feedback: run `cargo build` (build) from `.`.
1. Fast feedback: run `cargo check` (check) from `.`.
2. Behavioral verification: run `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.
2. Behavioral verification: run `cargo test` (test) from `.`.
3. Release-safety validation: run `cargo build` (build) from `.`.

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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
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
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Common Change Paths

### 1. Modify validation flow for `crates/omnisstream/src`

Start here:
- Open `crates/omnisstream/src/api.rs` first; it is the strongest workflow or owning file tied to the current validation path.
- Then cross-check [validation](validation.md) and [crates/omnisstream/src](components/crates-omnisstream-src.md) before changing the command order or scope.

Likely files:
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`

Risk boundary:
- Validation changes cover hotspot-heavy behavior for `crates/omnisstream/src`, which currently carries score 1797.
- A weaker validation path can miss regressions that ripple into `omnisstream_bench`, `omnisstream_benchdiff`, `omnisstream`.
- Release-safety checks are part of the current confidence boundary, so removing or weakening them can raise publish or deploy risk.

Validate with:
- Run `cargo build` (build) from `.`.
- Run `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator`.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>
