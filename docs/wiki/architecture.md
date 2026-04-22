---
page_id: architecture
page_type: architecture
generation_mode: inferred
freshness_status: reused
updated_at: 2026-04-18T05:55:58.240Z
---

<details>
<summary>Build metadata</summary>

```json
{
  "freshnessKey": "50bddfc7b20d87bca4a446e51475d216734f36b1",
  "plannerReason": "Inferred architecture page summarizing repo shape and component structure.",
  "changedPaths": [],
  "dependencyPaths": [
    "docs/ffi_cmake.md",
    "README.md",
    "spec/omnisstream-spec/proto/README.md",
    "spec/omnisstream-spec/README.md",
    "spec/omnisstream-spec/test-vectors/README.md",
    "spec/omnisstream-spec/tools/validator/README.md",
    "crates/omnisstream/src/hashing.rs",
    "crates/omnisstream/src/upload.rs",
    "crates/omnisstream/src/manifest.rs",
    "crates/omnisstream/src/part_store.rs",
    "crates/omnisstream/src/reader.rs",
    "crates/omnisstream_bench/Cargo.toml",
    "crates/omnisstream_benchdiff/Cargo.toml",
    "crates/omnisstream_cli/Cargo.toml",
    "crates/omnisstream/Cargo.toml",
    "crates/omnisstream_ffi/Cargo.toml",
    "crates/omnisstream_cli/src/main.rs",
    "crates/omnisstream_bench/src/main.rs",
    "crates/omnisstream_benchdiff/src/main.rs",
    "crates/omnisstream_ffi/src/bin/header_gen.rs",
    "crates/omnisstream/build.rs",
    "crates/omnisstream/src/api.rs",
    "crates/omnisstream_backend_api/Cargo.toml",
    "crates/omnisstream_backend_api/src/lib.rs",
    "crates/omnisstream_cli/build.rs",
    "crates/omnisstream_ffi/cbindgen.toml",
    "crates/omnisstream_ffi/src/lib.rs",
    "crates/omnisstream/src/compression.rs",
    "crates/omnisstream/src/durability.rs",
    "spec/omnisstream-spec/tools/validator/pyproject.toml",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "Cargo.toml",
    "crates/omnisstream/tests/api_surface.rs",
    "spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "omnisstream-validate",
    "crates/omnisstream/src/fs_util.rs",
    "Cargo.lock",
    "spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py"
  ],
  "dependencyEvidenceIds": [
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream_bench/src/main.rs",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:crates/omnisstream_cli/src/main.rs",
    "ingest:file:crates/omnisstream_ffi/src/lib.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/object_version.rs",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:crates/omnisstream/src/repo.rs",
    "ingest:file:crates/omnisstream/src/upload.rs",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml",
    "component:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/src/lib.rs",
    "ingest:file:crates/omnisstream_ffi/src/bin/header_gen.rs",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "component:Cargo.toml",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface.json",
    "ingest:file:target/debug/build/cbindgen-741b44f13a1fd46a/out/tests.rs",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml",
    "ingest:file:Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_bench/Cargo.toml",
    "ingest:file:crates/omnisstream_benchdiff/Cargo.toml",
    "ingest:file:crates/omnisstream_cli/Cargo.toml",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:target/debug/.fingerprint/pkg-config-dd7065c4c3fc738a/lib-pkg_config.json",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:external:rust:aho-corasick",
    "component:external:rust:anstream",
    "component:external:rust:anstyle",
    "component:external:rust:anstyle-parse",
    "component:external:rust:anstyle-query",
    "component:external:rust:anstyle-wincon",
    "component:external:rust:anyhow",
    "component:external:rust:anyhow.workspace",
    "component:external:rust:arrayref",
    "component:external:rust:arrayvec",
    "component:external:rust:bitflags",
    "component:external:rust:blake3",
    "component:external:rust:blake3.workspace",
    "component:external:rust:bumpalo",
    "component:external:rust:bytes",
    "component:external:rust:bytes.workspace",
    "component:external:rust:cbindgen",
    "component:external:rust:cc",
    "component:external:rust:cfg-if",
    "component:external:rust:clap",
    "component:external:rust:clap_builder",
    "component:external:rust:clap_derive",
    "component:external:rust:clap_lex",
    "component:external:rust:clap.workspace",
    "component:external:rust:colorchoice",
    "component:external:rust:constant_time_eq",
    "component:external:rust:crc32c",
    "component:external:rust:crc32c.workspace",
    "component:external:rust:crossbeam-deque",
    "component:external:rust:crossbeam-epoch",
    "component:external:rust:crossbeam-utils",
    "component:external:rust:either",
    "component:external:rust:equivalent",
    "component:external:rust:errno",
    "component:external:rust:fastrand",
    "component:external:rust:find-msvc-tools",
    "component:external:rust:fixedbitset",
    "component:external:rust:getrandom",
    "component:external:rust:hashbrown",
    "component:external:rust:heck",
    "component:external:rust:hex",
    "component:external:rust:hex.workspace",
    "component:external:rust:indexmap",
    "component:external:rust:is_terminal_polyfill",
    "component:external:rust:itertools",
    "component:external:rust:itoa",
    "component:external:rust:jobserver",
    "component:external:rust:js-sys",
    "component:external:rust:lazy_static",
    "component:external:rust:libc",
    "component:external:rust:libc.workspace",
    "component:external:rust:linux-raw-sys",
    "component:external:rust:log",
    "component:external:rust:matchers",
    "component:external:rust:memchr",
    "component:external:rust:multimap",
    "component:external:rust:name",
    "component:external:rust:nu-ansi-term",
    "component:external:rust:once_cell",
    "component:external:rust:once_cell_polyfill",
    "component:external:rust:path",
    "component:external:rust:petgraph",
    "component:external:rust:pin-project-lite",
    "component:external:rust:pkg-config",
    "component:external:rust:prettyplease",
    "component:external:rust:proc-macro2",
    "component:external:rust:prost",
    "component:external:rust:prost-build",
    "component:external:rust:prost-derive",
    "component:external:rust:prost-types",
    "component:external:rust:prost-types.workspace",
    "component:external:rust:prost.workspace",
    "component:external:rust:protoc-bin-vendored",
    "component:external:rust:protoc-bin-vendored-linux-aarch_64",
    "component:external:rust:protoc-bin-vendored-linux-ppcle_64",
    "component:external:rust:protoc-bin-vendored-linux-s390_64",
    "component:external:rust:protoc-bin-vendored-linux-x86_32",
    "component:external:rust:protoc-bin-vendored-linux-x86_64",
    "component:external:rust:protoc-bin-vendored-macos-aarch_64",
    "component:external:rust:protoc-bin-vendored-macos-x86_64",
    "component:external:rust:protoc-bin-vendored-win32",
    "component:external:rust:quote",
    "component:external:rust:r-efi",
    "component:external:rust:rayon",
    "component:external:rust:rayon-core",
    "component:external:rust:rayon.workspace",
    "component:external:rust:regex",
    "component:external:rust:regex-automata",
    "component:external:rust:regex-syntax",
    "component:external:rust:required-features",
    "component:external:rust:rustc_version",
    "component:external:rust:rustix",
    "component:external:rust:rustversion",
    "component:external:rust:ryu",
    "component:external:rust:semver",
    "component:external:rust:semver.workspace",
    "component:external:rust:serde",
    "component:external:rust:serde_core",
    "component:external:rust:serde_derive",
    "component:external:rust:serde_json",
    "component:external:rust:serde_json.workspace",
    "component:external:rust:serde_spanned",
    "component:external:rust:serde.workspace",
    "component:external:rust:sharded-slab",
    "component:external:rust:shlex",
    "component:external:rust:smallvec",
    "component:external:rust:strsim",
    "component:external:rust:syn",
    "component:external:rust:tempfile",
    "component:external:rust:tempfile.workspace",
    "component:external:rust:thiserror",
    "component:external:rust:thiserror-impl",
    "component:external:rust:thiserror.workspace",
    "component:external:rust:thread_local",
    "component:external:rust:toml",
    "component:external:rust:toml_datetime",
    "component:external:rust:toml_edit",
    "component:external:rust:toml_write",
    "component:external:rust:tracing",
    "component:external:rust:tracing-attributes",
    "component:external:rust:tracing-core",
    "component:external:rust:tracing-log",
    "component:external:rust:tracing-subscriber",
    "component:external:rust:tracing-subscriber.workspace",
    "component:external:rust:tracing.workspace",
    "component:external:rust:unicode-ident",
    "component:external:rust:utf8parse",
    "component:external:rust:uuid",
    "component:external:rust:uuid.workspace",
    "component:external:rust:valuable",
    "component:external:rust:wasip2",
    "component:external:rust:wasm-bindgen",
    "component:external:rust:wasm-bindgen-macro",
    "component:external:rust:wasm-bindgen-macro-support",
    "component:external:rust:wasm-bindgen-shared",
    "component:external:rust:windows-link",
    "component:external:rust:windows-sys",
    "component:external:rust:winnow",
    "component:external:rust:wit-bindgen",
    "component:external:rust:zstd",
    "component:external:rust:zstd-framed",
    "component:external:rust:zstd-safe",
    "component:external:rust:zstd-sys",
    "component:bin:omnisstream",
    "component:bin:omnisstream_bench",
    "component:bin:omnisstream_benchdiff",
    "component:bin:omnisstream_ffi_header",
    "component:cargo:crates/omnisstream",
    "component:cargo:crates/omnisstream_backend_api",
    "component:cargo:crates/omnisstream_bench",
    "component:cargo:crates/omnisstream_benchdiff",
    "component:cargo:crates/omnisstream_cli",
    "component:cargo:crates/omnisstream_ffi",
    "component:crates/omnisstream_backend_api/src",
    "component:crates/omnisstream_bench/src",
    "component:crates/omnisstream_benchdiff/src",
    "component:crates/omnisstream_cli/src",
    "component:crates/omnisstream_ffi/src",
    "component:crates/omnisstream/src",
    "component:python-script:spec/omnisstream-spec/tools/validator/pyproject.toml:omnisstream-validate",
    "component:spec/omnisstream-spec/tools/validator/src",
    "component:docs",
    "component:tests"
  ],
  "evidenceIds": [
    "ingest:file:crates/omnisstream/src/hashing.rs",
    "ingest:file:crates/omnisstream_bench/src/main.rs",
    "ingest:file:crates/omnisstream_benchdiff/src/main.rs",
    "ingest:file:crates/omnisstream_cli/src/main.rs",
    "ingest:file:crates/omnisstream_ffi/src/lib.rs",
    "ingest:file:crates/omnisstream/src/fs_util.rs",
    "ingest:file:crates/omnisstream/src/inspect.rs",
    "ingest:file:crates/omnisstream/src/manifest.rs",
    "ingest:file:crates/omnisstream/src/object_version.rs",
    "ingest:file:crates/omnisstream/src/part_store.rs",
    "ingest:file:crates/omnisstream/src/reader.rs",
    "ingest:file:crates/omnisstream/src/repo.rs",
    "ingest:file:crates/omnisstream/src/upload.rs",
    "ingest:file:crates/omnisstream/tests/api_surface.rs",
    "ingest:file:crates/omnisstream/src/group_commit.rs",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/validate.py",
    "ingest:file:crates/omnisstream/src/api.rs",
    "ingest:file:crates/omnisstream/src/lib.rs",
    "component:crates/omnisstream_bench/Cargo.toml",
    "component:crates/omnisstream_benchdiff/Cargo.toml",
    "component:crates/omnisstream_cli/Cargo.toml",
    "component:crates/omnisstream/Cargo.toml",
    "component:crates/omnisstream_ffi/Cargo.toml",
    "component:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/src/lib.rs",
    "ingest:file:crates/omnisstream_ffi/src/bin/header_gen.rs",
    "ingest:file:crates/omnisstream/src/compression.rs",
    "ingest:file:crates/omnisstream/src/durability.rs",
    "ingest:file:crates/omnisstream/src/ingest_backend.rs",
    "component:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream_validate/model.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/__init__.py",
    "ingest:file:spec/omnisstream-spec/tools/validator/src/omnisstream/v1/manifest_pb2.py",
    "ingest:file:docs/ffi_cmake.md",
    "ingest:file:README.md",
    "ingest:file:spec/omnisstream-spec/proto/README.md",
    "ingest:file:spec/omnisstream-spec/README.md",
    "ingest:file:spec/omnisstream-spec/test-vectors/README.md",
    "ingest:file:spec/omnisstream-spec/tools/validator/README.md",
    "component:Cargo.toml",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-compressed/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/EXPECTED.txt",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.json",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/manifest.pb",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0001.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0002.bin",
    "ingest:file:spec/omnisstream-spec/test-vectors/vector-minimal/parts/part-0003.bin",
    "ingest:file:spec/omnisstream-spec/tools/validator/tests/test_vectors.py",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-7d160085694d4088/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api",
    "ingest:file:target/debug/.fingerprint/omnisstream_backend_api-b6608906c17c3ad5/test-lib-omnisstream_backend_api.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-2116bac95fb410da/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench",
    "ingest:file:target/debug/.fingerprint/omnisstream_bench-c3cab453de7b2fbc/test-bin-omnisstream_bench.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-d45b335813af65c9/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff",
    "ingest:file:target/debug/.fingerprint/omnisstream_benchdiff-eeab6b30bec50506/test-bin-omnisstream_benchdiff.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-7ffd4a492057dfac/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream_cli-83428a8807066f41/test-bin-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-011df452a3647069/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-2ec4543d5d4314f5/test-lib-omnisstream_ffi.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-4dd3812dc132fb84/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header",
    "ingest:file:target/debug/.fingerprint/omnisstream_ffi-9f701df7daebf619/test-bin-omnisstream_ffi_header.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-d4b8a6fbbf212def/test-integration-test-api_surface.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f33ff188f38259aa/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream",
    "ingest:file:target/debug/.fingerprint/omnisstream-f6cf2cd55d9cd535/test-lib-omnisstream.json",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface",
    "ingest:file:target/debug/.fingerprint/omnisstream-f88f61dd9cf6d8bc/test-integration-test-api_surface.json",
    "ingest:file:target/debug/build/cbindgen-741b44f13a1fd46a/out/tests.rs",
    "workflow:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "workflow:Cargo.toml",
    "ingest:file:Cargo.toml",
    "ingest:file:crates/omnisstream_backend_api/Cargo.toml",
    "ingest:file:crates/omnisstream_bench/Cargo.toml",
    "ingest:file:crates/omnisstream_benchdiff/Cargo.toml",
    "ingest:file:crates/omnisstream_cli/Cargo.toml",
    "ingest:file:spec/omnisstream-spec/.editorconfig",
    "ingest:file:target/debug/.fingerprint/pkg-config-dd7065c4c3fc738a/lib-pkg_config.json",
    "ingest:file:spec/omnisstream-spec/tools/validator/pyproject.toml",
    "component:external:rust:aho-corasick",
    "component:external:rust:anstream",
    "component:external:rust:anstyle",
    "component:external:rust:anstyle-parse",
    "component:external:rust:anstyle-query",
    "component:external:rust:anstyle-wincon",
    "component:external:rust:anyhow",
    "component:external:rust:anyhow.workspace",
    "component:external:rust:arrayref",
    "component:external:rust:arrayvec",
    "component:external:rust:bitflags",
    "component:external:rust:blake3",
    "component:external:rust:blake3.workspace",
    "component:external:rust:bumpalo",
    "component:external:rust:bytes",
    "component:external:rust:bytes.workspace",
    "component:external:rust:cbindgen",
    "component:external:rust:cc",
    "component:external:rust:cfg-if",
    "component:external:rust:clap",
    "component:external:rust:clap_builder",
    "component:external:rust:clap_derive",
    "component:external:rust:clap_lex",
    "component:external:rust:clap.workspace",
    "component:external:rust:colorchoice",
    "component:external:rust:constant_time_eq",
    "component:external:rust:crc32c",
    "component:external:rust:crc32c.workspace",
    "component:external:rust:crossbeam-deque",
    "component:external:rust:crossbeam-epoch",
    "component:external:rust:crossbeam-utils",
    "component:external:rust:either",
    "component:external:rust:equivalent",
    "component:external:rust:errno",
    "component:external:rust:fastrand",
    "component:external:rust:find-msvc-tools",
    "component:external:rust:fixedbitset",
    "component:external:rust:getrandom",
    "component:external:rust:hashbrown",
    "component:external:rust:heck",
    "component:external:rust:hex",
    "component:external:rust:hex.workspace",
    "component:external:rust:indexmap",
    "component:external:rust:is_terminal_polyfill",
    "component:external:rust:itertools",
    "component:external:rust:itoa",
    "component:external:rust:jobserver",
    "component:external:rust:js-sys",
    "component:external:rust:lazy_static",
    "component:external:rust:libc",
    "component:external:rust:libc.workspace",
    "component:external:rust:linux-raw-sys",
    "component:external:rust:log",
    "component:external:rust:matchers",
    "component:external:rust:memchr",
    "component:external:rust:multimap",
    "component:external:rust:name",
    "component:external:rust:nu-ansi-term",
    "component:external:rust:once_cell",
    "component:external:rust:once_cell_polyfill",
    "component:external:rust:path",
    "component:external:rust:petgraph",
    "component:external:rust:pin-project-lite",
    "component:external:rust:pkg-config",
    "component:external:rust:prettyplease",
    "component:external:rust:proc-macro2",
    "component:external:rust:prost",
    "component:external:rust:prost-build",
    "component:external:rust:prost-derive",
    "component:external:rust:prost-types",
    "component:external:rust:prost-types.workspace",
    "component:external:rust:prost.workspace",
    "component:external:rust:protoc-bin-vendored",
    "component:external:rust:protoc-bin-vendored-linux-aarch_64",
    "component:external:rust:protoc-bin-vendored-linux-ppcle_64",
    "component:external:rust:protoc-bin-vendored-linux-s390_64",
    "component:external:rust:protoc-bin-vendored-linux-x86_32",
    "component:external:rust:protoc-bin-vendored-linux-x86_64",
    "component:external:rust:protoc-bin-vendored-macos-aarch_64",
    "component:external:rust:protoc-bin-vendored-macos-x86_64",
    "component:external:rust:protoc-bin-vendored-win32",
    "component:external:rust:quote",
    "component:external:rust:r-efi",
    "component:external:rust:rayon",
    "component:external:rust:rayon-core",
    "component:external:rust:rayon.workspace",
    "component:external:rust:regex",
    "component:external:rust:regex-automata",
    "component:external:rust:regex-syntax",
    "component:external:rust:required-features",
    "component:external:rust:rustc_version",
    "component:external:rust:rustix",
    "component:external:rust:rustversion",
    "component:external:rust:ryu",
    "component:external:rust:semver",
    "component:external:rust:semver.workspace",
    "component:external:rust:serde",
    "component:external:rust:serde_core",
    "component:external:rust:serde_derive",
    "component:external:rust:serde_json",
    "component:external:rust:serde_json.workspace",
    "component:external:rust:serde_spanned",
    "component:external:rust:serde.workspace",
    "component:external:rust:sharded-slab",
    "component:external:rust:shlex",
    "component:external:rust:smallvec",
    "component:external:rust:strsim",
    "component:external:rust:syn",
    "component:external:rust:tempfile",
    "component:external:rust:tempfile.workspace",
    "component:external:rust:thiserror",
    "component:external:rust:thiserror-impl",
    "component:external:rust:thiserror.workspace",
    "component:external:rust:thread_local",
    "component:external:rust:toml",
    "component:external:rust:toml_datetime",
    "component:external:rust:toml_edit",
    "component:external:rust:toml_write",
    "component:external:rust:tracing",
    "component:external:rust:tracing-attributes",
    "component:external:rust:tracing-core",
    "component:external:rust:tracing-log",
    "component:external:rust:tracing-subscriber",
    "component:external:rust:tracing-subscriber.workspace",
    "component:external:rust:tracing.workspace",
    "component:external:rust:unicode-ident",
    "component:external:rust:utf8parse",
    "component:external:rust:uuid",
    "component:external:rust:uuid.workspace",
    "component:external:rust:valuable",
    "component:external:rust:wasip2",
    "component:external:rust:wasm-bindgen",
    "component:external:rust:wasm-bindgen-macro",
    "component:external:rust:wasm-bindgen-macro-support",
    "component:external:rust:wasm-bindgen-shared",
    "component:external:rust:windows-link",
    "component:external:rust:windows-sys",
    "component:external:rust:winnow",
    "component:external:rust:wit-bindgen",
    "component:external:rust:zstd",
    "component:external:rust:zstd-framed",
    "component:external:rust:zstd-safe",
    "component:external:rust:zstd-sys",
    "component:bin:omnisstream",
    "component:bin:omnisstream_bench",
    "component:bin:omnisstream_benchdiff",
    "component:bin:omnisstream_ffi_header",
    "component:cargo:crates/omnisstream",
    "component:cargo:crates/omnisstream_backend_api",
    "component:cargo:crates/omnisstream_bench",
    "component:cargo:crates/omnisstream_benchdiff",
    "component:cargo:crates/omnisstream_cli",
    "component:cargo:crates/omnisstream_ffi",
    "component:crates/omnisstream_backend_api/src",
    "component:crates/omnisstream_bench/src",
    "component:crates/omnisstream_benchdiff/src",
    "component:crates/omnisstream_cli/src",
    "component:crates/omnisstream_ffi/src",
    "component:crates/omnisstream/src",
    "component:python-script:spec/omnisstream-spec/tools/validator/pyproject.toml:omnisstream-validate",
    "component:spec/omnisstream-spec/tools/validator/src",
    "component:docs",
    "component:tests"
  ],
  "qualityWarnings": []
}

```
</details>

# Architecture

High-level architecture for OmnisStream-Core.

## Related Pages

- [components](components.md)
- [workflows](workflows.md)
- [dependencies](dependencies.md)

## Architecture Summary

Detected ecosystems:
- python
- rust

Top-level directories:
- `.github/`
- `crates/`
- `docs/`
- `examples/`
- `include/`
- `spec/`
- `target/`

<details>
<summary>Related files:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

## How This Actually Works

Insufficient evidence to narrate one concrete implementation path through this repository.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Key Abstractions

### as_bytes core implementation module
What it is: as_bytes core implementation module acts as an inferred core implementation module built around `as_bytes`, `blake3_256_bytes` in `crates/omnisstream/src/hashing.rs`.
What it controls: Controls a visible slice of crates/omnisstream/src behavior instead of acting as passive inventory.
If you change it: Changing as_bytes core implementation module can shift a central behavior boundary rather than only renaming an internal helper.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/hashing.rs:33`
- `crates/omnisstream/src/hashing.rs:53`
</details>

### complete core implementation module
What it is: complete core implementation module acts as an inferred core implementation module built around `complete`, `create` in `crates/omnisstream/src/upload.rs`.
What it controls: Controls a visible slice of crates/omnisstream/src behavior instead of acting as passive inventory.
If you change it: Changing complete core implementation module can shift a central behavior boundary rather than only renaming an internal helper.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/upload.rs:101`
</details>

### from_pb_bytes core implementation module
What it is: from_pb_bytes core implementation module acts as an inferred core implementation module built around `from_pb_bytes`, `Manifest` in `crates/omnisstream/src/manifest.rs`.
What it controls: Controls a visible slice of crates/omnisstream/src behavior instead of acting as passive inventory.
If you change it: Changing from_pb_bytes core implementation module can shift a central behavior boundary rather than only renaming an internal helper.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream/src/manifest.rs:463`
</details>

### Repository persistence layer
What it is: Repository persistence layer acts as an inferred core implementation module built around `exists`, `new` in `crates/omnisstream/src/part_store.rs`.
What it controls: Controls persistence of repository snapshots, rendered-output metadata, and refresh bookkeeping.
If you change it: Changing it can break persistence compatibility or leave refresh metadata inconsistent across runs.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/part_store.rs:236`
- `crates/omnisstream/src/part_store.rs:144`
</details>

### new core implementation module
What it is: new core implementation module acts as an inferred core implementation module built around `new`, `ReaderError` in `crates/omnisstream/src/reader.rs`.
What it controls: Controls a visible slice of crates/omnisstream/src behavior instead of acting as passive inventory.
If you change it: Changing new core implementation module can shift a central behavior boundary rather than only renaming an internal helper.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/reader.rs:402`
- `crates/omnisstream/src/reader.rs:516`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/hashing.rs`
- `crates/omnisstream/src/upload.rs`
- `crates/omnisstream/src/manifest.rs`
- `crates/omnisstream/src/part_store.rs`
- `crates/omnisstream/src/reader.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/hashing.rs:33`
- `crates/omnisstream/src/hashing.rs:53`
- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/upload.rs:101`
- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream/src/manifest.rs:463`
- `crates/omnisstream/src/part_store.rs:236`
- `crates/omnisstream/src/part_store.rs:144`
- `crates/omnisstream/src/reader.rs:402`
- `crates/omnisstream/src/reader.rs:516`
</details>

## State Transitions and Recovery

Insufficient evidence to explain one bounded state path and its first recovery boundary confidently.

<details>
<summary>Supporting citations:</summary>

- none
</details>


## Subsystem Narratives

Diagram link: [Subsystem Clusters](diagrams.md#subsystem-clusters).

### external
Purpose: external groups 143 components under external/ or related paths.

Responsibilities:
- External rust dependency inferred from lockfile resolution.
- External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream_benchdiff/Cargo.toml, crates/omnisstream_cli/Cargo.toml, crates/omnisstream/Cargo.toml.
- External rust dependency inferred from crates/omnisstream_bench/Cargo.toml, crates/omnisstream/Cargo.toml.
- External rust dependency inferred from crates/omnisstream/Cargo.toml.

Key dependencies:
- memchr
- anstyle-parse
- anstyle-query
- anstyle-wincon
- anstyle

Boundary notes:
- Mostly operates within its own inferred subsystem boundary.
- No strong adjacent subsystem boundary was inferred.
- Dominant paths: `crates/omnisstream_bench/Cargo.toml`, `crates/omnisstream_benchdiff/Cargo.toml`, `crates/omnisstream_cli/Cargo.toml`, `crates/omnisstream/Cargo.toml`, `crates/omnisstream_ffi/Cargo.toml`.

### crates
Purpose: crates groups 16 components under crates/ or related paths.

Responsibilities:
- Rust binary target omnisstream.
- Rust binary target omnisstream_bench.
- Rust binary target omnisstream_benchdiff.
- Rust binary target omnisstream_ffi_header.

Key dependencies:
- omnisstream
- anyhow.workspace
- blake3.workspace
- clap.workspace
- libc.workspace

Boundary notes:
- Crosses 50 external dependency edges into related subsystems.
- Most connected to `external`.
- Dominant paths: `crates/omnisstream_cli/src/main.rs`, `crates/omnisstream_cli/Cargo.toml`, `crates/omnisstream_bench/src/main.rs`, `crates/omnisstream_bench/Cargo.toml`, `crates/omnisstream_benchdiff/src/main.rs`, `crates/omnisstream_benchdiff/Cargo.toml`.

### spec
Purpose: spec groups 3 components under spec/ or related paths.

Responsibilities:
- Python script entrypoint omnisstream-validate.
- omnisstream-validator python component
- Source module rooted at spec/omnisstream-spec/tools/validator/src.
- Grouped around dominant path prefix `spec`.

Key dependencies:

Boundary notes:
- Crosses 7 external dependency edges into related subsystems.
- Most connected to `crates`.
- Dominant paths: `spec/omnisstream-spec/tools/validator/pyproject.toml`, `spec/omnisstream-spec/tools/validator/README.md`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`.

### docs
Purpose: docs groups 1 components under docs/ or related paths.

Responsibilities:
- Repository documentation and wiki source files.
- Grouped around dominant path prefix `docs`.

Key dependencies:
- omnisstream
- omnisstream_bench
- omnisstream_benchdiff
- omnisstream_ffi_header
- omnisstream_backend_api

Boundary notes:
- Mostly operates within its own inferred subsystem boundary.
- No strong adjacent subsystem boundary was inferred.
- Dominant paths: `docs/ffi_cmake.md`, `README.md`, `spec/omnisstream-spec/proto/README.md`.

### root
Purpose: root groups 1 components under root/ or related paths.

Responsibilities:
- OmnisStream-Core rust component
- Grouped around dominant path prefix `root`.

Key dependencies:

Boundary notes:
- Mostly operates within its own inferred subsystem boundary.
- No strong adjacent subsystem boundary was inferred.
- Dominant paths: `Cargo.toml`.

### tests
Purpose: tests groups 1 components under tests/ or related paths.

Responsibilities:
- Repository tests and fixtures.
- Grouped around dominant path prefix `tests`.

Key dependencies:
- omnisstream
- omnisstream_bench
- omnisstream_benchdiff
- omnisstream_ffi_header
- omnisstream_backend_api

Boundary notes:
- Mostly operates within its own inferred subsystem boundary.
- No strong adjacent subsystem boundary was inferred.
- Dominant paths: `crates/omnisstream/tests/api_surface.rs`, `spec/omnisstream-spec/test-vectors/README.md`, `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`.

<details>
<summary>Related files:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/lib.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs:15`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/lib.rs:53`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
</details>

## Execution Narrative

Stages:
1. Entry begins with `omnisstream-validate` (run) from `spec/omnisstream-spec/tools/validator`.
2. Initial control lands in omnisstream and quickly centers on omnisstream as the primary execution owner.
3. Usually triggered from runtime surface `crates/omnisstream_bench/src/main.rs` owned by crates.
4. crates hands off to `anyhow.workspace`, `blake3.workspace`, `clap.workspace` in external through 50 inferred dependency edges.

Owning components:
- omnisstream (application)
- omnisstream_bench (application)
- omnisstream_benchdiff (application)
- omnisstream_cli (package)
- omnisstream_ffi_header (application)

Handoffs:
- crates -> external: crates groups 16 components under crates/ or related paths. hands off into external groups 143 components under external/ or related paths.
- crates hands off to `anyhow.workspace`, `blake3.workspace`, `clap.workspace` in external through 50 inferred dependency edges.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
</details>

## Code Path Slice

Starts at: `exists` (function) in `crates/omnisstream/src/part_store.rs`. Chosen because `exists` is an exported trigger inside hotspot component `crates/omnisstream/src`.

Calls into: `path_for_digest` (function) in `crates/omnisstream/src/part_store.rs`.

Stops at: `to_hex` (function) in `crates/omnisstream/src/hashing.rs`, where no deeper unambiguous call step was inferred within the bounded slice.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:116`
- `crates/omnisstream/src/hashing.rs:37`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/part_store.rs`
- `crates/omnisstream/src/hashing.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:116`
- `crates/omnisstream/src/hashing.rs:37`
</details>

## State and Data Flow

Inputs:
- Input enters from workflow `omnisstream-validate` (run) via `omnisstream-validate`.

Transformations:
- crates/omnisstream/src acts as the primary transformation owner. It hands off into `omnisstream_bench`, `omnisstream_backend_api`, `omnisstream`, `prost` for the next transformation steps.
- Downstream transformation continues through `omnisstream_bench`, `clap`, `serde`, `omnisstream`.

Storage or sinks:
- `omnisstream_bench`, `clap`, `serde`, `omnisstream` behave as the final inferred sinks or terminal state holders in this path.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
</details>

<details>
<summary>Related files:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `omnisstream-validate`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs:15`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
</details>

## Subsystem Interactions

Diagram links: [Subsystem Clusters](diagrams.md#subsystem-clusters) and [Dependency Graph](diagrams.md#dependency-graph).

### crates -> external
Purpose: crates groups 16 components under crates/ or related paths. hands off into external groups 143 components under external/ or related paths.

Trigger: Usually triggered from runtime surface `crates/omnisstream_bench/src/main.rs` owned by crates.

Handoff: crates hands off to `anyhow.workspace`, `blake3.workspace`, `clap.workspace` in external through 50 inferred dependency edges.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
</details>

### spec -> crates
Purpose: spec groups 3 components under spec/ or related paths. hands off into crates groups 16 components under crates/ or related paths.

Trigger: Usually triggered from workflow `omnisstream-validate` (run) touching spec.

Handoff: spec hands off to `omnisstream_benchdiff`, `crates/omnisstream/src` in crates through 7 inferred call edges.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
</details>

## Invariants and Risks

### crates/omnisstream/src is an implicit compatibility boundary
Assumption: Assumption: crates/omnisstream/src can change without breaking `external`, `spec` is risky, because the component bridges those subsystems and carries hotspot score 1797.

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
</details>

### crates -> external is a cross-subsystem coupling hazard
Coupling hazard: Coupling hazard: crates hands off to `anyhow.workspace`, `blake3.workspace`, `clap.workspace` in external through 50 inferred dependency edges. Changes on either side are likely to ripple because crates groups 16 components under crates/ or related paths. hands off into external groups 143 components under external/ or related paths..

<details>
<summary>Supporting citations:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
</details>

### Operational changes tend to fail first at validation boundaries
Failure boundary: Failure boundary: verify high-coordination component `crates/omnisstream/src` against `python -m pytest` and `cargo build` before and after changes, because those surfaces are the first deterministic checks tied to likely breakage.

<details>
<summary>Supporting citations:</summary>

- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
</details>

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_cli/src/main.rs:16`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `Cargo.toml`
</details>

## External Systems

### protoc-bin-vendored-linux-s390_64
Role: Infrastructure or platform integration

Interaction mode: Used by `Documentation`, `Tests` via manifest dependency declarations and pinned in `Cargo.lock`.

<details>
<summary>Supporting citations:</summary>

- `Cargo.lock`
- `docs/ffi_cmake.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
</details>

<details>
<summary>Related files:</summary>

- `Cargo.lock`
- `docs/ffi_cmake.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
</details>

<details>
<summary>Citations:</summary>

- `Cargo.lock`
- `docs/ffi_cmake.md`
- `README.md`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
</details>

## Subsystems and Components

- Tests (tests) depends on 163 known edges.
- omnisstream (package) depends on 21 known edges.
- crates/omnisstream/src (module) depends on 27 known edges.
- omnisstream-validator (application) depends on 0 known edges.
- spec/omnisstream-spec/tools/validator/src (module) depends on 0 known edges.
- Documentation (docs) depends on 164 known edges.
- anyhow.workspace (package) depends on 0 known edges.
- omnisstream_ffi (package) depends on 5 known edges.
- clap.workspace (package) depends on 0 known edges.
- omnisstream_cli (package) depends on 6 known edges.
- serde_json.workspace (package) depends on 0 known edges.
- serde.workspace (package) depends on 0 known edges.

<details>
<summary>Related files:</summary>

- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `spec/omnisstream-spec/test-vectors/vector-compressed/manifest.json`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream/src/fs_util.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/load.py`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
- `crates/omnisstream_cli/build.rs`
- `crates/omnisstream_cli/src/main.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream/src/durability.rs:33`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_cli/src/main.rs:16`
</details>

## Subsystem Clusters

Diagram link: [Subsystem Clusters](diagrams.md#subsystem-clusters).

- external: external groups 143 components under external/ or related paths. Strategy: path. Internal edges: 197. External edges: 0. Dominant paths: `crates/omnisstream_bench/Cargo.toml`, `crates/omnisstream_benchdiff/Cargo.toml`, `crates/omnisstream_cli/Cargo.toml`, `crates/omnisstream/Cargo.toml`, `crates/omnisstream_ffi/Cargo.toml`. Rationale: Grouped around dominant path prefix `external`.
- crates: crates groups 16 components under crates/ or related paths. Strategy: path. Internal edges: 437. External edges: 50. Dominant paths: `crates/omnisstream_cli/src/main.rs`, `crates/omnisstream_cli/Cargo.toml`, `crates/omnisstream_bench/src/main.rs`, `crates/omnisstream_bench/Cargo.toml`, `crates/omnisstream_benchdiff/src/main.rs`, `crates/omnisstream_benchdiff/Cargo.toml`. Rationale: Grouped around dominant path prefix `crates`. Most connected to `external` through inferred graph edges.
- spec: spec groups 3 components under spec/ or related paths. Strategy: path. Internal edges: 24. External edges: 7. Dominant paths: `spec/omnisstream-spec/tools/validator/pyproject.toml`, `spec/omnisstream-spec/tools/validator/README.md`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`, `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`. Rationale: Grouped around dominant path prefix `spec`. Most connected to `crates` through inferred graph edges.
- docs: docs groups 1 components under docs/ or related paths. Strategy: path. Internal edges: 0. External edges: 0. Dominant paths: `docs/ffi_cmake.md`, `README.md`, `spec/omnisstream-spec/proto/README.md`. Rationale: Grouped around dominant path prefix `docs`.
- root: root groups 1 components under root/ or related paths. Strategy: path. Internal edges: 0. External edges: 0. Dominant paths: `Cargo.toml`. Rationale: Grouped around dominant path prefix `root`.
- tests: tests groups 1 components under tests/ or related paths. Strategy: path. Internal edges: 0. External edges: 0. Dominant paths: `crates/omnisstream/tests/api_surface.rs`, `spec/omnisstream-spec/test-vectors/README.md`, `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`. Rationale: Grouped around dominant path prefix `tests`.

<details>
<summary>Related files:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_benchdiff/src/main.rs`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/README.md`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
</details>

## Graph Hotspots

Diagram links: [Dependency Graph](diagrams.md#dependency-graph) and [Component Overview](diagrams.md#component-overview).

- crates/omnisstream/src (module) at `crates/omnisstream/src`: score 1797. Inbound 297, outbound 300, calls 570, dependencies 27. Inbound edges: 297. Outbound edges: 300. Call edges: 570; dependency edges: 27. Bridges 2 subsystem boundaries: `external`, `spec`.
- omnisstream (application) at `crates/omnisstream_cli/src`: score 264. Inbound 38, outbound 49, calls 83, dependencies 4. Inbound edges: 38. Outbound edges: 49. Call edges: 83; dependency edges: 4. Bridges 1 subsystem boundaries: `external`.
- omnisstream_benchdiff (application) at `crates/omnisstream_benchdiff/src`: score 255. Inbound 41, outbound 42, calls 80, dependencies 3. Inbound edges: 41. Outbound edges: 42. Call edges: 80; dependency edges: 3. Bridges 2 subsystem boundaries: `external`, `spec`.
- omnisstream (package) at `crates/omnisstream`: score 174. Inbound 28, outbound 29, calls 8, dependencies 49. Inbound edges: 28. Outbound edges: 29. Call edges: 8; dependency edges: 49. Bridges 1 subsystem boundaries: `external`.
- spec/omnisstream-spec/tools/validator/src (module) at `spec/omnisstream-spec/tools/validator/src`: score 156. Inbound 24, outbound 27, calls 51, dependencies 0. Inbound edges: 24. Outbound edges: 27. Call edges: 51; dependency edges: 0. Bridges 1 subsystem boundaries: `crates`.
- omnisstream_bench (application) at `crates/omnisstream_bench/src`: score 120. Inbound 17, outbound 22, calls 36, dependencies 3. Inbound edges: 17. Outbound edges: 22. Call edges: 36; dependency edges: 3. Bridges 1 subsystem boundaries: `external`.
- crates/omnisstream_ffi/src (module) at `crates/omnisstream_ffi/src`: score 93. Inbound 14, outbound 17, calls 30, dependencies 1. Inbound edges: 14. Outbound edges: 17. Call edges: 30; dependency edges: 1. Mostly operates within a single subsystem boundary.
- omnisstream_cli (package) at `crates/omnisstream_cli`: score 51. Inbound 5, outbound 11, calls 10, dependencies 6. Inbound edges: 5. Outbound edges: 11. Call edges: 10; dependency edges: 6. Bridges 1 subsystem boundaries: `external`.

<details>
<summary>Related files:</summary>

- `crates/omnisstream/src/api.rs`
- `crates/omnisstream/src/compression.rs`
- `crates/omnisstream/src/durability.rs`
- `crates/omnisstream_cli/src/main.rs`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/build.rs`
- `crates/omnisstream/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py`
- `crates/omnisstream_bench/src/main.rs`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs`
- `crates/omnisstream_ffi/src/lib.rs`
- `crates/omnisstream_cli/build.rs`
</details>

<details>
<summary>Citations:</summary>

- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream/Cargo.toml`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream_ffi/src/lib.rs:53`
- `crates/omnisstream_cli/build.rs:110`
</details>

## Where to Read Next

- Start with `components.md` for ownership boundaries.
- Use `workflows.md` for build and test commands.
- Use `dependencies.md` to inspect inferred relationships.

## Citations

<details>
<summary>Citations:</summary>

- `docs/ffi_cmake.md`
- `README.md`
- `spec/omnisstream-spec/proto/README.md`
- `spec/omnisstream-spec/README.md`
- `spec/omnisstream-spec/test-vectors/README.md`
- `spec/omnisstream-spec/tools/validator/README.md`
- `crates/omnisstream/src/hashing.rs:33`
- `crates/omnisstream/src/hashing.rs:53`
- `crates/omnisstream/src/upload.rs:443`
- `crates/omnisstream/src/upload.rs:101`
- `crates/omnisstream/src/manifest.rs:34`
- `crates/omnisstream/src/manifest.rs:463`
- `crates/omnisstream/src/part_store.rs:236`
- `crates/omnisstream/src/part_store.rs:144`
- `crates/omnisstream/src/reader.rs:402`
- `crates/omnisstream/src/reader.rs:516`
- `crates/omnisstream_bench/Cargo.toml`
- `crates/omnisstream_benchdiff/Cargo.toml`
- `crates/omnisstream/Cargo.toml`
- `crates/omnisstream_ffi/Cargo.toml`
- `crates/omnisstream_cli/Cargo.toml`
- `crates/omnisstream_cli/src/main.rs:16`
- `crates/omnisstream_bench/src/main.rs:20`
- `crates/omnisstream_benchdiff/src/main.rs:9`
- `crates/omnisstream_ffi/src/bin/header_gen.rs:3`
- `crates/omnisstream/build.rs:3`
- `crates/omnisstream_backend_api/Cargo.toml`
- `crates/omnisstream_backend_api/src/lib.rs:15`
- `crates/omnisstream_cli/build.rs:110`
- `crates/omnisstream_ffi/cbindgen.toml`
- `crates/omnisstream_ffi/src/lib.rs:53`
- `crates/omnisstream/src/api.rs:100`
- `crates/omnisstream/src/compression.rs:9`
- `spec/omnisstream-spec/tools/validator/pyproject.toml`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/__init__.py`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/cli.py:11`
- `spec/omnisstream-spec/tools/validator/src/omnisstream_validate/hashes.py:11`
- `Cargo.toml`
- `crates/omnisstream/tests/api_surface.rs:5`
- `spec/omnisstream-spec/test-vectors/vector-compressed/EXPECTED.txt`
- `omnisstream-validate`
- `crates/omnisstream/src/part_store.rs:41`
- `crates/omnisstream/src/part_store.rs:116`
- `crates/omnisstream/src/hashing.rs:37`
- `crates/omnisstream/src/durability.rs:33`
- `Cargo.lock`
</details>
