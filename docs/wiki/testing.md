---
page_id: testing
page_type: testing
generation_mode: inferred
freshness_status: new
updated_at: 2026-05-06T23:02:00.621Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "cf1de889b382a1cf82f6588cfb0461fe6b84f5e7",
  "plannerReason": "Generated because test workflows are critical for validation and agent execution safety.",
  "changedPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "spec/omnisstream-spec/.editorconfig",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/.gitignore",
    "spec/omnisstream-spec/CANONICAL_JSON.md",
    "spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "spec/omnisstream-spec/CONTRIBUTING.md",
    "spec/omnisstream-spec/LICENSE",
    "spec/omnisstream-spec/MANIFEST_SPEC.md",
    "spec/omnisstream-spec/NOTICE",
    "spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto",
    "spec/omnisstream-spec/proto/protoc.sh",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "spec/omnisstream-spec/REPOSITORY_SPEC.md",
    "spec/omnisstream-spec/SECURITY.md",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt"
  ],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "spec/omnisstream-spec/.editorconfig",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/.gitignore",
    "spec/omnisstream-spec/CANONICAL_JSON.md",
    "spec/omnisstream-spec/CODE_OF_CONDUCT.md",
    "spec/omnisstream-spec/CONTRIBUTING.md",
    "spec/omnisstream-spec/LICENSE",
    "spec/omnisstream-spec/MANIFEST_SPEC.md",
    "spec/omnisstream-spec/NOTICE",
    "spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto",
    "spec/omnisstream-spec/proto/protoc.sh",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "spec/omnisstream-spec/REPOSITORY_SPEC.md",
    "spec/omnisstream-spec/SECURITY.md",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt"
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

# Testing

Testing guidance for OmnisStream-Core.

## Related Pages

- [workflows](workflows.md)

## Test Workflows

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

## Known Test Files

- `spec/omnisstream-spec/.editorconfig`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/.gitignore`
- `spec/omnisstream-spec/CANONICAL_JSON.md`
- `spec/omnisstream-spec/CODE_OF_CONDUCT.md`
- `spec/omnisstream-spec/CONTRIBUTING.md`
- `spec/omnisstream-spec/LICENSE`
- `spec/omnisstream-spec/MANIFEST_SPEC.md`
- `spec/omnisstream-spec/NOTICE`
- `spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto`
- `spec/omnisstream-spec/proto/protoc.sh`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/REPOSITORY_SPEC.md`
- `spec/omnisstream-spec/SECURITY.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/.editorconfig`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/.gitignore`
- `spec/omnisstream-spec/CANONICAL_JSON.md`
- `spec/omnisstream-spec/CODE_OF_CONDUCT.md`
- `spec/omnisstream-spec/CONTRIBUTING.md`
- `spec/omnisstream-spec/LICENSE`
- `spec/omnisstream-spec/MANIFEST_SPEC.md`
- `spec/omnisstream-spec/NOTICE`
- `spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto`
- `spec/omnisstream-spec/proto/protoc.sh`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/REPOSITORY_SPEC.md`
- `spec/omnisstream-spec/SECURITY.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/.editorconfig`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/.gitignore`
- `spec/omnisstream-spec/CANONICAL_JSON.md`
- `spec/omnisstream-spec/CODE_OF_CONDUCT.md`
- `spec/omnisstream-spec/CONTRIBUTING.md`
- `spec/omnisstream-spec/LICENSE`
- `spec/omnisstream-spec/MANIFEST_SPEC.md`
- `spec/omnisstream-spec/NOTICE`
- `spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto`
- `spec/omnisstream-spec/proto/protoc.sh`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/REPOSITORY_SPEC.md`
- `spec/omnisstream-spec/SECURITY.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `spec/omnisstream-spec/.editorconfig`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/.gitignore`
- `spec/omnisstream-spec/CANONICAL_JSON.md`
- `spec/omnisstream-spec/CODE_OF_CONDUCT.md`
- `spec/omnisstream-spec/CONTRIBUTING.md`
- `spec/omnisstream-spec/LICENSE`
- `spec/omnisstream-spec/MANIFEST_SPEC.md`
- `spec/omnisstream-spec/NOTICE`
- `spec/omnisstream-spec/proto/omnisstream/v1/manifest.proto`
- `spec/omnisstream-spec/proto/protoc.sh`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/REPOSITORY_SPEC.md`
- `spec/omnisstream-spec/SECURITY.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
</details>
