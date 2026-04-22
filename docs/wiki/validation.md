---
page_id: validation
page_type: validation
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.255Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "02e3e503d4903c49486067082da6f595eadb4d97",
  "plannerReason": "Generated when enough deterministic workflow evidence exists to separate fast feedback, behavioral verification, and release-safety validation.",
  "changedPaths": [],
  "dependencyPaths": [
    "Cargo.toml",
    "spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "dependencyEvidenceIds": [
    "workflow:Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "evidenceIds": [
    "workflow:Cargo.toml",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml"
  ],
  "qualityWarnings": []
}

```
</details>

# Validation

Validation strategy guide for OmnisStream-Core.

## Related Pages

- [playbook](playbook.md)
- [testing](testing.md)
- [troubleshooting](troubleshooting.md)
- [workflows](workflows.md)

## Fast Feedback

- Run `cargo build` (build) from `.` for fast structural feedback before broader validation.
- Run `cargo check` (check) from `.` for fast structural feedback before broader validation.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Behavioral Verification

- Use `python -m pytest` (test) from `spec/omnisstream-spec/tools/validator` to confirm user-visible or behavior-level expectations.
- Use `cargo test` (test) from `.` to confirm user-visible or behavior-level expectations.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Release-Safety Validation

- Reserve `cargo build` (build) from `.` for packaging, release, deploy, or pre-release safety gates.
- Review `.github/workflows/ci.yml` when changing release-sensitive validation because it likely influences build, deployment, or publication steps.
- Review `.github/workflows/release.yml` when changing release-sensitive validation because it likely influences build, deployment, or publication steps.

<details>
<summary>Related files:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `Cargo.toml`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
</details>
