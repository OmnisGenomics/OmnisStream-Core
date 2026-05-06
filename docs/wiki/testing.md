---
page_id: testing
page_type: testing
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.252Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "71015bf5d4654424eed633fbebe6aefe37148a62",
  "plannerReason": "Generated because test workflows are critical for validation and agent execution safety.",
  "changedPaths": [],
  "dependencyPaths": [
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "Cargo.toml",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb",
    "spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
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

Testing guidance for OmnisStream-Core. Stale build-artifact carryover removed; repo-local source files remain authoritative.

## Related Pages [build-artifact carryover removed]

- [workflows](workflows.md)

## Test Workflows

- From `spec/omnisstream-spec`, expose the validator package first, for example with `pip install -e tools/validator`, then run `python -m unittest discover -s tools/validator/tests`.
- `cargo test`

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `Cargo.toml`
</details>

## Known Test Files

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin`
- `spec/omnisstream-spec/tools/validator/tests/test_vectors.py`

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
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin`
- `spec/omnisstream-spec/tools/validator/tests/test_vectors.py`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin`
- `spec/omnisstream-spec/tools/validator/tests/test_vectors.py:14`
</details>

## Citations

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json`
- `spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin`
- `spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin`
- `spec/omnisstream-spec/tools/validator/tests/test_vectors.py:14`
</details>
