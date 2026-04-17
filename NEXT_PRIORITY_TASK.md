# Next Priority Task

Normalize README Markdown headings and command blocks.

The README commands are functional, but the document has several Markdown structure issues that
make the quick-start harder to scan and may render inconsistently:

- `Quick start with release artifacts` is plain text rather than a heading.
- `#CLI (development)` is missing the heading space.
- Shell comments and commands are mixed as prose and one-line inline code snippets.

Suggested scope:

- Convert the quick-start, CLI, examples, and dev-check snippets to proper Markdown headings and
  fenced `sh` blocks.
- Preserve the existing commands exactly unless a command is verified to need correction.
- Avoid changing CLI behavior in the same patch.

Suggested validation:

- `cargo run -p omnisstream_cli -- --help`
- `cargo run -p omnisstream_cli -- inspect spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
- `cargo run -p omnisstream_cli -- verify spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb`
