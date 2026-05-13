# First Run

This guide is for a new operator who needs to clone OmnisStream-Core, run the
supported validation path, and find the evidence surfaces that already exist in
the repository.

## Prerequisites

- Rust stable toolchain with Cargo.
- Git with submodule support.
- Python 3 for the reference validator.
- Optional: a virtual environment if you want the `omnisstream-validate` console
  command instead of using `PYTHONPATH`.

## Clone And Enter The Repository

```sh
git clone <repo-url> OmnisStream-Core
cd OmnisStream-Core
git submodule update --init --recursive
```

If you are already inside an existing checkout, run only the submodule command.

## Build And Test The Rust Workspace

```sh
cargo build
cargo check
cargo test
```

For formatting and lint-oriented local checks, use:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

## Run The Spec Validator Tests

The validator lives under the vendored spec submodule. Install its Python
dependencies in a virtual environment, then run the unit tests from
`spec/omnisstream-spec`:

```sh
cd spec/omnisstream-spec
python3 -m venv .venv
. .venv/bin/activate
pip install -e tools/validator
python -m unittest discover -s tools/validator/tests
```

If the validator dependencies are already installed in your current Python
environment, this shorter command is enough:

```sh
cd spec/omnisstream-spec
PYTHONPATH=tools/validator/src python -m unittest discover -s tools/validator/tests
```

After installation, inspect the validator command:

```sh
omnisstream-validate --help
```

## Inspect The CLI

From the repository root:

```sh
cargo run -p omnisstream_cli -- --help
cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb
```

## Evidence And Operator Surfaces

- `AGENTS.md` lists indexed workflows, components, and generated wiki entry
  points.
- `docs/monarchic-launch.md` defines the bounded Monarchic launch profile,
  allowed write scope, guarded surfaces, and validation expectations.
- `docs/wiki/` contains generated RepoIntel pages. Treat generated wiki changes
  as refresh output unless the task is explicitly about wiki content.
- `spec/omnisstream-spec/test-vectors/` contains canonical fixtures for CLI and
  validator checks.

This repository does not claim automatic merge authority, production deployment
authority, unchecked autonomy, or trust in agent transcripts. Changes still need
normal review, validation, and evidence.

## Common Failure Causes

- Missing spec files: run `git submodule update --init --recursive`.
- Validator import errors: install validator dependencies with `pip install -e
  tools/validator` in a virtual environment, then rerun the unit tests.
- Missing `omnisstream-validate`: install the validator package from
  `spec/omnisstream-spec`, or use the Python unit-test command above.
- Rust build failures after local edits: run `cargo fmt --all -- --check`,
  `cargo check`, and `cargo test` from the repository root.
- Generated wiki noise: inspect `git status` and avoid mixing generated wiki
  refreshes with source or operator-doc changes unless that is the intended
  task.

## Documentation Guard

Run the lightweight first-run documentation check from the repository root:

```sh
bash scripts/check-first-run-docs.sh
```
