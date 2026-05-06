---
page_id: configuration
page_type: configuration
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:02:18.055Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "c699ffd8cd252d67c04c456fb41735228d0aca7f",
  "plannerReason": "Generated when enough deterministic configuration evidence exists to separate required setup, optional knobs, and risk-sensitive settings.",
  "changedPaths": [
    "Cargo.toml",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_cli/Cargo.toml",
    "spec/omnisstream-spec/.editorconfig",
    "spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "dependencyPaths": [
    "Cargo.toml",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_cli/Cargo.toml",
    "spec/omnisstream-spec/.editorconfig",
    "spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_bench/Cargo.toml",
    "ingest:file:crates/omnisstream_benchdiff/Cargo.toml",
    "ingest:file:crates/omnisstream_cli/Cargo.toml",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "evidenceIds": [
    "ingest:file:Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_bench/Cargo.toml",
    "ingest:file:crates/omnisstream_benchdiff/Cargo.toml",
    "ingest:file:crates/omnisstream_cli/Cargo.toml",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Configuration

Configuration guide for OmnisStream-Core.

## Related Pages

- [playbook](playbook.md)
- [interfaces](interfaces.md)
- [runtime](runtime.md)

## Required Setup

- Use package manager `cargo` for setup-sensitive commands.
- Check `Cargo.toml` before the first run; it likely carries required setup or environment prerequisites.
- Check `crates/omnisstream_backend_api/Cargo.toml` before the first run; it likely carries required setup or environment prerequisites.
- Check `crates/omnisstream_bench/Cargo.toml` before the first run; it likely carries required setup or environment prerequisites.
- Check `crates/omnisstream_benchdiff/Cargo.toml` before the first run; it likely carries required setup or environment prerequisites.
- Check `crates/omnisstream_cli/Cargo.toml` before the first run; it likely carries required setup or environment prerequisites.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Optional Knobs

- Review `spec/omnisstream-spec/.editorconfig` for optional tuning knobs and repo-local defaults.
- Review `spec/omnisstream-spec/tools/validator/pyproject.toml` for optional tuning knobs and repo-local defaults.
- spec/omnisstream-spec/tools/validator/pyproject.toml: Configuration surface defined by spec/omnisstream-spec/tools/validator/pyproject.toml.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Risk-Sensitive Settings

Insufficient evidence to infer risk-sensitive settings.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>
