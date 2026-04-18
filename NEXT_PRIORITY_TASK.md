# Next Priority Task

Assert exact release version metadata.

The CI `spec-contract` job now checks that `cargo run -p omnisstream_cli -- version`
prints `spec_pin $(cat SPEC_PIN.txt)`. The release workflow also smoke-tests
`./target/release/omnisstream version`, but currently only checks that a `spec_pin`
line exists. Tightening that release check would keep shipped binaries aligned with
the same exact metadata contract used in CI.

Suggested scope:

- Update `.github/workflows/release.yml` in the existing `"smoke: version output"` step.
- Assert that `version.txt` contains `spec_pin $(cat SPEC_PIN.txt)`.
- Keep the existing key-presence checks so release smoke output remains easy to diagnose.

Suggested validation:

- `cargo run -p omnisstream_cli -- version | tee version.txt`
- `grep -Fx "spec_pin $(cat SPEC_PIN.txt)" version.txt`
