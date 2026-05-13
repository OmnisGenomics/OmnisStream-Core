#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'first-run docs check failed: %s\n' "$1" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing required file: $path"
}

require_text() {
  local path="$1"
  local text="$2"
  grep -Fq "$text" "$path" || fail "$path does not reference: $text"
}

forbid_text() {
  local text="$1"
  if grep -RFiq -- "$text" README.md docs/first-run.md docs/monarchic-launch.md; then
    fail "unsupported claim found: $text"
  fi
}

require_file README.md
require_file docs/first-run.md
require_file docs/monarchic-launch.md
require_file scripts/check-first-run-docs.sh

require_text README.md "docs/first-run.md"
require_text README.md "scripts/check-first-run-docs.sh"
require_text README.md "omnisstream-validate"
require_text README.md "cargo check"
require_text README.md "cargo test"

require_text docs/first-run.md "Prerequisites"
require_text docs/first-run.md "git submodule update --init --recursive"
require_text docs/first-run.md "cargo build"
require_text docs/first-run.md "cargo check"
require_text docs/first-run.md "cargo test"
require_text docs/first-run.md "PYTHONPATH=tools/validator/src python -m unittest discover -s tools/validator/tests"
require_text docs/first-run.md "omnisstream-validate"
require_text docs/first-run.md "cargo run -p omnisstream_cli -- --help"
require_text docs/first-run.md "docs/monarchic-launch.md"
require_text docs/first-run.md "Common Failure Causes"

forbid_text "grants automatic merge"
forbid_text "has automatic merge authority"
forbid_text "grants production deployment authority"
forbid_text "supports unchecked autonomy"
forbid_text "trusts agent transcripts"

printf 'first-run docs check passed\n'
