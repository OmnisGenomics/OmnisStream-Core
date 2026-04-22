# Monarchic Launch

Use a constrained launch profile for `OmnisStream-Core`.

## First Read

1. `AGENTS.md`
2. `docs/wiki/playbook.md`
3. `docs/wiki/change-guide.md`
4. This file

## Default Write Scope

- `crates/omnisstream_cli/`
- `spec/omnisstream-spec/tools/validator/`
- `spec/omnisstream-spec/test-vectors/`
- repository documentation under `docs/`

## Guarded Surfaces

- `crates/omnisstream/`
- `crates/omnisstream_ffi/`
- semantic changes to the vendored spec under `spec/omnisstream-spec/`

Only enter a guarded surface when the task explicitly requires core format, storage primitive, or FFI work.

## Validation

Run these after changes unless the task is strictly documentation-only:

1. For validator changes, prefer the checked-in README workflow from `spec/omnisstream-spec`: expose the package first, then run `python -m unittest discover -s tools/validator/tests`
2. `cargo build`
3. `cargo check`
4. `cargo test`

## RepoIntel Notes

- `.repointel.json` excludes `target/` and generated `wiki/` content from future scans.
- RepoIntel currently infers `python -m pytest` for the validator, but the checked-in validator README uses an install-or-PYTHONPATH step plus `python -m unittest discover -s tools/validator/tests`. Prefer the README workflow until the inferred workflow is fixed.
- Some existing reused wiki pages may still mention `target/` because they were carried forward from the pre-config index state. Treat those references as stale until RepoIntel performs a full page invalidation for this repo.
