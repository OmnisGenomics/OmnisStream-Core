# Next Priority Task

Smoke-test CLI version metadata in CI.

The README release quick-start documents `./omnisstream version`, and the CLI embeds
`SPEC_PIN.txt` in that output. CI already checks the submodule pin and runs vector
`verify`/`inspect` commands, but it does not exercise the documented `version` command.
Adding a small smoke check would catch regressions in build metadata wiring without changing
runtime behavior.

Suggested scope:

- Add a `spec-contract` CI step that runs `cargo run -p omnisstream_cli -- version`.
- Assert the output contains `spec_pin $(cat SPEC_PIN.txt)`.
- Keep this separate from vector inspection/verification behavior.

Suggested validation:

- `cargo run -p omnisstream_cli -- version`
- `cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
