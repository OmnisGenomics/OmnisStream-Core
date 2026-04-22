# AGENTS.md

## Repository

OmnisStream-Core is a repository indexed by RepoIntel MCP. Version control: git. Detected ecosystems: python, rust. Inventory: 92 files, 165 components, 5 workflows. Documentation starts at docs/ffi_cmake.md, README.md, spec/omnisstream-spec/proto/README.md.

## Navigation

- `.github/`
- `crates/`
- `docs/`
- `examples/`
- `include/`
- `spec/`

## Key Workflows

- `omnisstream-validate` (run)
- `python -m pytest` (test)
- `cargo build` (build)
- `cargo check` (check)
- `cargo test` (test)

## Components

- omnisstream (application)
- omnisstream_bench (application)
- omnisstream_benchdiff (application)
- omnisstream_ffi_header (application)
- omnisstream (package)
- omnisstream_backend_api (package)
- omnisstream_bench (package)
- omnisstream_benchdiff (package)

## Generated Wiki

- Wiki root: `docs/wiki`
- Index page: [docs/wiki/index.md](docs/wiki/index.md)
- Architecture: [docs/wiki/architecture.md](docs/wiki/architecture.md)
- Workflows: [docs/wiki/workflows.md](docs/wiki/workflows.md)
- Components: [docs/wiki/components.md](docs/wiki/components.md)
- Interfaces: [docs/wiki/interfaces.md](docs/wiki/interfaces.md)
- Dependencies: [docs/wiki/dependencies.md](docs/wiki/dependencies.md)
- Diagrams: [docs/wiki/diagrams.md](docs/wiki/diagrams.md)

## Recent Change Impact

Detected 2 changed, 2 added, and 5724 removed files.

- Impacted components: Tests
- Impacted pages: configuration, testing

## Grounding

<details>
<summary>Summary citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>
- Indexed evidence records: 92
- Wiki quality warnings: Diagrams has no citations.; Glossary has no citations.
- Wiki page refresh status: 1 updated/new, 26 reused

## Notes

- Prefer reading the generated wiki before inferring repository architecture from scratch.
- Use the MCP server for targeted summary, workflow, and wiki page queries.
- For Monarchic work on this repo, start with `docs/monarchic-launch.md` before editing code.
- Default bounded write scope: `crates/omnisstream_cli/`, `spec/omnisstream-spec/tools/validator/`, and spec-vector or documentation maintenance under `spec/omnisstream-spec/`.
- Treat `crates/omnisstream/` and `crates/omnisstream_ffi/` as guarded surfaces; only change them when the task explicitly requires core format or FFI work.
- `spec/omnisstream-spec` is the vendored canonical spec submodule. Avoid semantic spec rewrites unless the task is explicitly about spec changes.
- RepoIntel currently infers `python -m pytest` for the validator, but the checked-in validator README expects the package to be installed or exposed first and documents `python -m unittest discover -s tools/validator/tests` from `spec/omnisstream-spec`. Prefer the README workflow until RepoIntel's workflow extraction is corrected.
- RepoIntel scan config now excludes `target/` and generated `wiki/` content via `.repointel.json`. If reused wiki pages still mention `target/`, treat those references as stale pre-config carryover rather than live source ownership.
