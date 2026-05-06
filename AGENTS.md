# AGENTS.md

## Repository

OmnisStream-Core is a repository indexed by RepoIntel MCP. Version control: git. Detected ecosystems: python, rust. Inventory: 90 files, 165 components, 5 workflows. Documentation starts at docs/ffi_cmake.md, docs/monarchic-launch.md, README.md.

## Navigation

- `.github/`
- `crates/`
- `docs/`
- `examples/`
- `include/`
- `spec/`

## Key Workflows

- `omnisstream-validate` (run)
- `python -m unittest discover -s tools/validator/tests` (test)
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
- Configuration: [docs/wiki/configuration.md](docs/wiki/configuration.md)
- Playbook: [docs/wiki/playbook.md](docs/wiki/playbook.md)
- Validation: [docs/wiki/validation.md](docs/wiki/validation.md)
- Change Guide: [docs/wiki/change-guide.md](docs/wiki/change-guide.md)
- Troubleshooting: [docs/wiki/troubleshooting.md](docs/wiki/troubleshooting.md)
- Components: [docs/wiki/components.md](docs/wiki/components.md)
- Workflows: [docs/wiki/workflows.md](docs/wiki/workflows.md)
- Runtime: [docs/wiki/runtime.md](docs/wiki/runtime.md)
- Interfaces: [docs/wiki/interfaces.md](docs/wiki/interfaces.md)
- Dependencies: [docs/wiki/dependencies.md](docs/wiki/dependencies.md)
- Testing: [docs/wiki/testing.md](docs/wiki/testing.md)
- Diagrams: [docs/wiki/diagrams.md](docs/wiki/diagrams.md)
- Glossary: [docs/wiki/glossary.md](docs/wiki/glossary.md)

## Recent Change Impact

Initial index created all repository artifacts.

- Impacted components: omnisstream, omnisstream_bench, omnisstream_benchdiff, omnisstream_ffi_header, omnisstream, omnisstream_backend_api, omnisstream_bench, omnisstream_benchdiff, omnisstream_cli, omnisstream_ffi, OmnisStream-Core, crates/omnisstream_backend_api/src, crates/omnisstream_bench/src, crates/omnisstream_benchdiff/src, crates/omnisstream_cli/src, crates/omnisstream_ffi/src, crates/omnisstream/src, Documentation, aho-corasick, anstream, anstyle, anstyle-parse, anstyle-query, anstyle-wincon, anyhow, anyhow.workspace, arrayref, arrayvec, bitflags, blake3, blake3.workspace, bumpalo, bytes, bytes.workspace, cbindgen, cc, cfg-if, clap, clap_builder, clap_derive, clap_lex, clap.workspace, colorchoice, constant_time_eq, crc32c, crc32c.workspace, crossbeam-deque, crossbeam-epoch, crossbeam-utils, either, equivalent, errno, fastrand, find-msvc-tools, fixedbitset, getrandom, hashbrown, heck, hex, hex.workspace, indexmap, is_terminal_polyfill, itertools, itoa, jobserver, js-sys, lazy_static, libc, libc.workspace, linux-raw-sys, log, matchers, memchr, multimap, name, nu-ansi-term, once_cell, once_cell_polyfill, path, petgraph, pin-project-lite, pkg-config, prettyplease, proc-macro2, prost, prost-build, prost-derive, prost-types, prost-types.workspace, prost.workspace, protoc-bin-vendored, protoc-bin-vendored-linux-aarch_64, protoc-bin-vendored-linux-ppcle_64, protoc-bin-vendored-linux-s390_64, protoc-bin-vendored-linux-x86_32, protoc-bin-vendored-linux-x86_64, protoc-bin-vendored-macos-aarch_64, protoc-bin-vendored-macos-x86_64, protoc-bin-vendored-win32, quote, r-efi, rayon, rayon-core, rayon.workspace, regex, regex-automata, regex-syntax, required-features, rustc_version, rustix, rustversion, ryu, semver, semver.workspace, serde, serde_core, serde_derive, serde_json, serde_json.workspace, serde_spanned, serde.workspace, sharded-slab, shlex, smallvec, strsim, syn, tempfile, tempfile.workspace, thiserror, thiserror-impl, thiserror.workspace, thread_local, toml, toml_datetime, toml_edit, toml_write, tracing, tracing-attributes, tracing-core, tracing-log, tracing-subscriber, tracing-subscriber.workspace, tracing.workspace, unicode-ident, utf8parse, uuid, uuid.workspace, valuable, wasip2, wasm-bindgen, wasm-bindgen-macro, wasm-bindgen-macro-support, wasm-bindgen-shared, windows-link, windows-sys, winnow, wit-bindgen, zstd, zstd-framed, zstd-safe, zstd-sys, omnisstream-validate, omnisstream-validator, spec/omnisstream-spec/tools/validator/src, Tests
- Impacted pages: index, architecture, configuration, component-component:bin:omnisstream, component-component:bin:omnisstream_bench, component-component:cargo:crates/omnisstream, component-component:cargo:crates/omnisstream_backend_api, component-component:cargo:crates/omnisstream_cli, component-component:cargo:crates/omnisstream_ffi, component-component:crates/omnisstream_ffi/src, component-component:crates/omnisstream/src, component-component:docs, component-component:spec/omnisstream-spec/tools/validator/pyproject.toml, component-component:spec/omnisstream-spec/tools/validator/src, component-component:tests, playbook, validation, change-guide, troubleshooting, components, workflows, runtime, interfaces, dependencies, testing, diagrams, glossary

## Grounding

<details>
<summary>Summary citations:</summary>

- `docs/ffi_cmake.md`
- `docs/monarchic-launch.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>
- Indexed evidence records: 100
- Wiki quality warnings: none
- Wiki page refresh status: 27 updated/new, 0 reused

## Notes

- Prefer reading the generated wiki before inferring repository architecture from scratch.
- Use the MCP server for targeted summary, workflow, and wiki page queries.
