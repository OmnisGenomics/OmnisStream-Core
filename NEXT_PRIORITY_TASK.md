# Next Priority Task

Clean default-feature warnings in README vector smoke commands.

The README-style CLI smoke commands pass, but `cargo run -p omnisstream_cli -- verify/inspect ...`
currently emits existing default-feature warnings from:

- `crates/omnisstream/src/repo.rs`: `stored` and `compression_alg` are only mutated when the
  `compression` feature is enabled.
- `crates/omnisstream/src/compression.rs`: `CompressionConfig` fields and
  `set_compression_config` are unused when building without the `compression` feature.

The all-feature clippy path is clean, so keep this as a focused follow-up instead of mixing it
with unrelated CLI GC behavior.

Suggested validation:

- `cargo clippy --all-targets -- -D warnings`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb`
