---
page_id: workflows
page_type: workflows
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:01:58.627Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "b509458c5ae2abd1c68595e8ab3e16adaddf97bc",
  "plannerReason": "Generated because workflows are one of the primary agent interaction surfaces.",
  "changedPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml"
  ],
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
- `python -m unittest discover -s tools/validator/tests` (test, confidence high)
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

- `python -m unittest discover -s tools/validator/tests`
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
