---
page_id: workflows
page_type: workflows
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.241Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "b509458c5ae2abd1c68595e8ab3e16adaddf97bc",
  "plannerReason": "Generated because workflows are one of the primary agent interaction surfaces.",
  "changedPaths": [],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
  "dependencyEvidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "evidenceIds": [
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Workflows

Workflow guide for OmnisStream-Core.

## Related Pages

- [testing](testing.md)
- [architecture](architecture.md)

## Workflow Inventory

- `omnisstream-validate` (run, confidence medium)
- `python -m pytest` (test, confidence high)
- `cargo build` (build, confidence high)
- `cargo check` (check, confidence high)
- `cargo test` (test, confidence high)

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

## Testing and Validation

- `python -m pytest`
- `cargo test`

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

## Runtime Entrypoints

- `omnisstream-validate`

<details>
<summary>Related files:</summary>

- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>
